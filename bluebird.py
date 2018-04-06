#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bluebird_cext import *
from collections import defaultdict, namedtuple
from elftools.elf.elffile import *

from mmap import PROT_EXEC, PROT_READ, PROT_WRITE, \
           MAP_PRIVATE, MAP_ANONYMOUS, MAP_SHARED, \
           MAP_DENYWRITE, MAP_EXECUTABLE, PAGESIZE

import os
import platform
import re
from stat import S_IRWXU
import sys

from threading import Thread
from time import sleep


stats_tuple = namedtuple('stats', ['pid', 'comm', 'state', 'ppid', 'pgrp',
                                   'session', 'tty_nr', 'tpgid', 'flags',
                                   'minflt', 'cminflt', 'majflt', 'cmajflt',
                                   'utime', 'stime', 'cutime', 'cstime',
                                   'priority', 'nice', 'num_threads',
                                   'iterealvalue', 'starttime', 'vsize', 'rss',
                                   'rsslim', 'startcode', 'endcode', 
                                   'startstack', 'kstkesp', 'kstkeip', 'signal', 
                                   'blocked', 'sigignore', 'sigcatch', 'wchan',
                                   'nswap', 'cnswap', 'exit_signal', 
                                   'processor', 'rt_priority', 'policy',
                                   'delayacct_blkio_ticks', 'guest_time',
                                   'cguest_time', 'start_data', 'end_data',
                                   'start_brk', 'arg_start', 'arg_end',
                                   'env_start', 'env_end', 'exit_code'])

PATH_MAX = 0x1000

syscall_nr_path = '/usr/include/asm/unistd_{}.h'

if platform.machine() == 'x86_64':
    syscall_machine = '64'
    WORD = 8
else:
    syscall_machine = '32'
    WORD = 4

try:
    with open(syscall_nr_path.format(syscall_machine)) as fh:
        syscalls_raw = fh.read()
except FileNotFoundError:
    raise IncompatibleArchitecture

syscalls = dict()

for call in filter(lambda s: s.startswith('#define __'),
                   syscalls_raw.split('\n')):
    _, call_name, call_number = call.split()
    syscalls[call_name.strip('__NR_')] = int(call_number)

if syscalls.get('ptrace') is None:
    raise PtraceCallNotFoundError


class TraceResults(object):

    def __init__(self, trace_value=None):
        self.trace_value = trace_value

    def __get__(self, obj, objtype):
        return self.trace_value

    def __set__(self, obj, value):
        if obj.tracing:
            raise RunningTraceError
        self.trace_value = value


class Bluebird(object):

    trace_results = TraceResults()

    def __init__(self, pid):
        self.pid = os.getpid()
        self.traced_pid = pid
        self.wdata = defaultdict(list)
        self.rdata = defaultdict(list)
        self.trace_wdata = {}
        self.trace_rdata = {}
        self.attached = False
        self.tracing = False
        self.elf_handle = None
        self.get_heap()
        self.stat_pattern = re.compile('(\d+\s)(\(.+\)\s)(\w+\s)((-?\d+\s?){49})')
        self.stats = self.get_stats() 
        try:
            self.exe_path = os.readlink('/proc/{}/exe'.format(self.traced_pid))
        except FileNotFoundError:
            raise ProcessNotFound

    def start(self):
        if self.attached:
            raise RunningTraceError
        attach(self.traced_pid)
        self.attached = True

    def stop(self):
        if self.attached:
            detach(self.traced_pid)
            self.attached = False

    @property
    def is_attached(self):
        tracer = self._parse_status('TracerPid')
        return str(self.pid) != tracer 
        
    def get_heap(self):
        self.get_maps()
        self.heap_bounds = self.parse_heap_map(self.maps.get('[heap]'))

    def get_maps(self):
        # XXX expand data-structure
        with open('/proc/{}/maps'.format(self.traced_pid)) as fh:
            raw_map_data = fh.readlines()
        self.maps = defaultdict(list)
        for _map in raw_map_data:
            _map = _map.split()
            name, addr = _map[-1].strip('\n'), _map[0].split('-')
            self.maps[name].append(addr)

    def parse_heap_map(self, heap_map):
        if heap_map is None: return None
        start, stop = heap_map[0]
        return int(start, 16), int(stop, 16)
 
    def write(self, addr, data):
        if isinstance(data, int):
            writeint(self.traced_pid, addr, data)
        else:
            writestring(self.traced_pid, addr, data)
        self.trace_wdata[addr] = data

    def read(self, addr, nwords, readtype=str):
        if isinstance(readtype, int):
            peek = readint(self.traced_pid, addr, nwords)
        else:
            peek = readstring(self.traced_pid, addr, nwords)
        self.trace_rdata[addr] = peek
        return peek

    def get_data_strings(self):
        rodata = self.getelf_section('.rodata')
        if rodata is None: raise ElfSectionNotFound
        return ''.join(map(chr, filter(lambda l: l > 31 and l < 126, 
                                                    rodata.data())))

    def getenv(self):
        self.stats = self.get_stats()
        env_length = self.stats.env_end - self.stats.env_start
        env_block = (env_length // WORD) + 1
        env_var = self.read(self.stats.env_start, env_block)
        env_var = filter(lambda s: s and '=' in s, env_var.split('\n'))
        return dict(map(lambda s: s.split('=', 1), env_var))

    def write_trace(self, number_of_calls):
        wr_call = syscalls['write']
        for call in range(number_of_calls):
            for fd, read_data in collect_io_data(self.traced_pid, wr_call).items():
                self.wdata[fd].append(read_data)
        self.cont_trace()

    def read_trace(self, number_of_calls):
        rd_call = syscalls['read']
        for call in range(number_of_calls):
            for fd, read_data in collect_io_data(self.traced_pid, rd_call).items():
                self.rdata[fd].append(read_data)
        self.cont_trace()

    def get_current_call(self):
        return get_syscall(self.traced_pid)

    def cont_trace(self):
        continue_trace(self.traced_pid)

    def get_ranged_syscalls(self, nsyscalls):
        # this allows the tracer get a consecutive count
        # syscalls without allowing any calls to slip by
        return get_syscalls(self.traced_pid, nsyscalls)

    def find_call(self, call, timeout=0):
        find_syscall(self.traced_pid, call, timeout)

    def expand_heap(self, amount):
        if self.heap_bounds is None:
            raise NoHeapAddress    
        start = self.heap_bounds[1]
        new_bounds = start + amount
        bbrk(self.traced_pid, new_bounds, start)
        self.get_heap()

    def create_mmap(self, addr, length, prot, flags, offset, path=None):
        if self.heap_bounds is None:
            raise NoHeapAddress    
        heap = self.heap_bounds[1]
        fd = 0
        if path is not None:
            self.expand_heap(0x1000)
            writestring(self.traced_pid, heap, path)
            fd = openfd(self.traced_pid, os.O_CREAT | os.O_WRONLY |
                                         S_IRWXU, heap)
        bmmap(self.traced_pid, addr, length, prot, flags, offset, heap, fd)
        self.get_heap()

    def get_fds(self):
        base = '/proc/{}/fd/{}'
        fd_dir = base.format(self.traced_pid, '')
        return {fd:os.readlink(base.format(self.traced_pid, fd)) for 
                fd in os.listdir(fd_dir)}

    def redirect_fd(self, fd, path, mode=os.O_WRONLY):
        if not os.path.isfile(path):
            mode |= os.O_CREAT
        string_addr = self.heap_bounds[1]
        self.expand_heap(PATH_MAX)
        self.get_heap()
        writestring(self.traced_pid, string_addr, path)
        redirect_fd(self.traced_pid, fd, string_addr, mode, self.heap_bounds[1])

    def get_trace_dir(self):
        self.get_heap()
        self.path_addr = self.heap_bounds[1]
        self.length = PATH_MAX - 1
        self.expand_heap(self.length)
        self.get_heap()
        path = bgetcwd(self.traced_pid, self.path_addr,
                       self.length, self.heap_bounds[1])
        words = self.length // WORD
        path = readstring(self.traced_pid, self.path_addr, words)
        return path.replace('\n', '')

    def getelf_section(self, section):
        self.elf_handle = open(self.exe_path, 'rb')
        try:
            elfreader = ELFFile(self.elf_handle)
        except FileNotFoundError:
            raise InvalidPath
        sections = {s.name:s for s in elfreader.iter_sections()}
        elf_section = sections.get(section)
        return elf_section

    def getsyms(self):
        syms = self.getelf_section('.symtab')
        if syms is None: raise ElfSectionNotFound
        symtab = defaultdict(list)
        for sym in syms.iter_symbols():
            type_entry = symtab[sym.entry['st_info']['type']]
            idx = len(type_entry)
            type_entry.append((idx, sym.name, hex(sym.entry['st_value'])))
        return symtab

    def restart(self):
        symtab = self.getelf_section('.symtab')
        if symtab is None: raise ElfSectionNotFound
        mainsym = symtab.get_symbol_by_name('main')[0]
        self.get_maps()
        goinit(self.traced_pid, mainsym.entry.st_value + 
                     int(self.maps[self.exe_path][0][0], 16))

    @property
    def name(self):
        return self._parse_status('Name')

    def get_stats(self):
        with open('/proc/{}/stat'.format(self.traced_pid)) as fh:
            stats_raw = fh.read()
        stats = re.findall(self.stat_pattern, stats_raw)[0][:-1]
        pid, name, state = stats[:3]
        stats = [int(pid)] + [name.strip()] + [state.strip()] + \
                [int(i) for j in stats[3:] for i in j.split()]
        return stats_tuple(*stats)

    def _parse_status(self, field):
        with open('/proc/{}/status'.format(self.traced_pid)) as f:
            status_raw = f.read()
        proc_field = re.findall('{}:\t(.+)\n'.format(field), status_raw)
        if not proc_field:
            raise InvalidStatusField
        return proc_field[0] 

    def create_trace_thread(self, func, cb, func_args, cb_args):
        if self.tracing:
            raise RunningTrace
        self.stop()
        sleep(2)
        trace_thread = TracingThread(self, func, cb, func_args, cb_args)
        trace_thread.start()

class TracingThread(Thread):

    def __init__(self, trace_obj, trace_func, trace_cb, 
                 trace_func_args=[], trace_cb_args=[]):
        super(TracingThread, self).__init__()
        self.trace_obj = trace_obj
        self.trace_func = trace_func
        self.trace_func_args = trace_func_args
        self.trace_cb = trace_cb
        self.trace_cb_args = trace_cb_args

    def run(self):
        self.trace_obj.tracing = True
        try:
            trace_results = self.trace_func(self.trace_obj.traced_pid, 
                                            *self.trace_func_args)
        except:
            trace_results = None
            self.trace_obj.trace_error = True
        finally:
            self.trace_obj.tracing = False
            self.trace_obj.trace_results = trace_results
            if self.trace_cb is not None:
                self.trace_cb(*self.trace_cb_args)


class ElfSectionNotFound(BaseException):

    def __str__(self):
        return 'Elf section not found'


class ProcessNotFound(BaseException):

    def __str__(self):
        return 'Process not found'


class RunningTraceError(BaseException):

    def __str__(self):
        return 'Trace in progress'


class NoHeapAddress(BaseException):

    def __str__(self):
        return 'Process has no available heap address'


class InvalidStatusField(BaseException):

    def __str__(self):
        return 'Invalid Process Status field'


class InvalidPath(BaseException):

    def __str__(self):
        return 'Invalid executable path'


class IncompatibleArchitecture(BaseException):

    def __str__(self):
        return 'Incompatible Architecture'


class PtraceCallNotFound(BaseException):

    def __str__(self):
        return 'Ptrace syscall not found'

