#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bluebird_cext import *

import sys

import re
import os
import platform
from math import inf
from time import sleep
from threading import Thread
from elftools.elf.elffile import *
from collections import defaultdict, namedtuple

from mmap import PROT_EXEC, PROT_READ, PROT_WRITE, \
           MAP_PRIVATE, MAP_ANONYMOUS, MAP_SHARED, \
           MAP_DENYWRITE, MAP_EXECUTABLE, PAGESIZE


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

PATH_MAX = 0xfff + 1

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

for syscall_raw in syscalls_raw.split('\n'):
    if syscall_raw.startswith('#define __'):
        _, call_name, call_number = syscall_raw.split()
        syscalls[call_name.strip('__')] = int(call_number)

if syscalls.get('NR_ptrace') is None:
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
        self.tracing_error = False
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
        elf_data = self.getelf_data()
        strings = {s.name:s.data() for s in elf_data.iter_sections()}
        return ''.join(map(chr, filter(lambda l: l > 31 and l < 126, 
                                       strings['.rodata'])))

    def getenv(self):
        self.stats = self.get_stats()
        env_length = self.stats.env_end - self.stats.env_start
        env_block = (env_length // WORD) + 1
        env_var = self.read(self.stats.env_start, env_block)
        env_var = filter(lambda s: s and '=' in s, env_var.split('\n'))
        return dict(map(lambda s: s.split('=', 1), env_var))

    def io_update(self, call, io, ncall, ncalls):
        while self.trace_results is None and not self.tracing_error:
            sleep(1)
        if self.tracing:
            raise RunningTraceError
        for fd in self.trace_results:
            io[fd].append(self.trace_results[fd])
        self.start()
        if ncall < ncalls:
            self.create_trace_thread(iotrace, self.io_update, [call, 1], 
                                           [call, io, ncall + 1, ncalls])

    def rw_trace(self, call, ncalls=inf):
        ncall = 0
        io = self.rdata if call == syscalls['NR_read'] else self.wdata
        while ncall < ncalls:
            io_made = iotrace(self.traced_pid, call, 0)
            for fd in io_made:
                io[fd].append(io_made[fd])
            ncall += 1

    def nb_rw_trace(self, call, ncalls):
        io = self.rdata if call == syscalls['NR_read'] else self.wdata
        self.create_trace_thread(iotrace, self.io_update, [call, 1], 
                                         [call, io, 1, ncalls])

    def get_current_call(self):
        return get_syscall(self.traced_pid)

    def get_ranged_syscalls(self, nsyscalls):
        # this allows the tracer get a consecutive count
        # syscalls without allowing any calls to slip by
        return get_syscalls(self.traced_pid, nsyscalls)

    def find_call(self, call, non_blocking=False, timeout=0):
        if non_blocking:
            self.create_trace_thread(find_syscall, None, 
                                    [call, timeout, 1], None)
        else:    
            find_syscall(self.traced_pid, call, timeout, 0)

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
        bmmap(self.traced_pid, addr, length, prot, flags, offset, heap, path)
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

    def getelf_data(self):
        fh = open(self.exe_path, 'rb')
        try:
            elfreader = ELFFile(fh)
        except:
            raise InvalidPath
        return elfreader

    def restart(self):
        elf = self.getelf_data()
        symtab = elf.get_section_by_name('.symtab')
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

