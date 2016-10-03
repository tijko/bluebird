#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bluebird import *

import re
import os
import platform
from math import inf
from time import sleep
from threading import Thread
from elftools.elf.elffile import *
from collections import defaultdict

from mmap import PROT_EXEC, PROT_READ, PROT_WRITE, \
           MAP_PRIVATE, MAP_ANONYMOUS, MAP_SHARED, \
           MAP_DENYWRITE, MAP_EXECUTABLE, PAGESIZE


PATH_MAX = 0xfff + 1

syscall_nr_path = '/usr/include/asm/unistd_{}.h'

if platform.machine() == 'x86_64':
    syscall_machine = '64'
else:
    syscall_machine = '32'

with open(syscall_nr_path.format(syscall_machine)) as fh:
    syscalls_raw = fh.read()

syscalls = dict()

for syscall_raw in syscalls_raw.split('\n'):
    if syscall_raw.startswith('#define __'):
        syscall = syscall_raw.split()
        syscalls[syscall[1].strip('__')] = int(syscall[2])


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
        self.get_heap()

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
        with open('/proc/{}/maps'.format(self.traced_pid)) as fh:
            raw_map_data = fh.readlines()
        self.maps = {}
        for _map in raw_map_data:
            self.maps[_map.split()[-1].strip('\n')] = _map.split()[0]

    def parse_heap_map(self, heap_map):
        if heap_map is None: return None
        address_range = heap_map.split()[0]
        start, stop = address_range.split('-')
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
            
    def io_update(self, call, io, ncall, ncalls):
        for fd in self.traced_results:
            io[fd].append(self.traced_results[fd])
        if ncall == ncalls:
            return
        self.create_trace_thread(io_trace, self.io_update, [call], 
                                [call, io, ncall + 1, ncalls])

    def rw_trace(self, call, ncalls=inf, non_blocking=False):
        ncall = 0
        io = self.rdata if call == syscalls['NR_read'] else self.wdata
        if non_blocking:
            self.create_trace_thread(iotrace, self.io_update, [call, 1], 
                                    [call, io, ncall + 1, ncalls])
            return
        while ncall < ncalls:
            io_made = iotrace(self.traced_pid, call, 0)
            for fd in io_made:
                io[fd].append(io_made[fd])
            ncall += 1

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

    def get_trace_dir(self):
        self.path_addr = self.heap_bounds[1]
        self.length = PATH_MAX - 1
        self.expand_heap(self.length)
        self.get_heap()
        path = bgetcwd(self.traced_pid, self.path_addr,
                       self.length, self.heap_bounds[1])
        words = self.length // 8
        path = readstring(self.traced_pid, self.path_addr, words)
        return path

    def get_sections(self, path=None, use_current=False):
        if use_current:
            cdir = self.get_trace_dir()
            path = os.path.join(cdir, self.name)
        elif path is None:    
            path = os.path.join('/usr/bin/', self.name)
        fh = open(path, 'rb')
        try:
            elfreader = ELFFile(fh)
        except:
            raise InvalidPath
        return {s.name:s.data() for s in elfreader.iter_sections()}

    @property
    def name(self):
        return self._parse_status('Name')

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
        sleep(1)
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
            trace_results = self.trace_func(self.traced_pid, *self.args)
        except:
            trace_results = None
        finally:
            self.trace_obj.tracing = False
            self.trace_obj.trace_results = trace_results
            if self.trace_cb is not None:
                self.trace_cb(*self.trace_cb_args)

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
