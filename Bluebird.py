#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bluebird import *

import re
from os import getpid
from time import sleep
from threading import Thread

from mmap import PROT_EXEC, PROT_READ, PROT_WRITE, \
           MAP_PRIVATE, MAP_ANONYMOUS, MAP_SHARED, \
           MAP_DENYWRITE, MAP_EXECUTABLE, PAGESIZE


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
        self.pid = getpid()
        self.traced_pid = pid
        self.wstrs = {}
        self.rstrs = {}
        self.attached = False
        self.tracing = False
        self.heap_bounds = self.get_heap(pid)
        # set attached pid COMM

    def start(self):
        # XXX handle already attached trace
        if not self.attached:
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
        
    def get_heap(self, pid):
        with open('/proc/{}/maps'.format(pid)) as fh:
            raw_map_data = fh.read()
        if raw_map_data.find('heap') == -1: return None
        for _map in raw_map_data.split('\n'):
            if 'heap' in _map: break
        return self.parse_heap_map(_map)

    def parse_heap_map(self, heap_map):
        address_range = heap_map.split()[0]
        start, stop = address_range.split('-')
        return int(start, 16), int(stop, 16)
 
    def write(self, addr, data):
        if isinstance(data, int):
            writeint(self.traced_pid, addr, data)
        else:
            writestring(self.traced_pid, addr, data)

    def read(self, addr, nwords, readtype=str):
        if isinstance(readtype, int):
            return readint(self.traced_pid, addr, nwords)
        else:
            return readstring(self.traced_pid, addr, nwords)
            
    def get_current_call(self):
        return get_syscall(self.traced_pid)

    def get_ranged_syscalls(self, nsyscalls):
        # this allows the tracer get a consecutive count
        # syscalls without allowing any calls to slip by
        return get_syscalls(self.traced_pid, nsyscalls)

    def get_call(self, call, non_blocking=False, timeout=0):
        if non_blocking:
            if self.tracing:
                raise RunningTrace
            self.stop()
            sleep(1)
            trace_thread = TracingThread(self, find_syscall, None,
                                         self.traced_pid, call, timeout, 1)
            trace_thread.start()
        else:    
            find_syscall(self.traced_pid, call, timeout, 0)

    def dump_exec(self):
        pass

    def exec_dir(self):
        #make_call(getcwd)
        pass

    def expand_heap(self, amount):
        if self.heap_bounds is None:
            raise NoHeapAddress    
        start = self.heap_bounds[0]
        new_bounds = self.heap_bounds[1] + amount
        bbrk(self.traced_pid, new_bounds, start)
        self.heap_bounds = self.get_heap(self.traced_pid)

    def create_mmap(self, addr, length, prot, flags, offset, path=None):
        if self.heap_bounds is None:
            raise NoHeapAddress    
        heap = self.heap_bounds[1]
        bmmap(self.traced_pid, addr, length, prot, flags, offset, heap, path)
        self.heap_bounds = self.get_heap(self.traced_pid)

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

class TracingThread(Thread):

    def __init__(self, trace_obj, trace_func, trace_cb, *args):
        super(TracingThread, self).__init__()
        self.trace_obj = trace_obj
        self.trace_func = trace_func
        self.trace_cb = trace_cb
        self.args = args

    def run(self):
        self.trace_obj.tracing = True
        try:
            trace_results = self.trace_func(*self.args)
        except:
            trace_results = None
        finally:
            self.trace_obj.tracing = False
            self.trace_obj.trace_results = trace_results


class RunningTraceError(BaseException):

    def __str__(self):
        return 'Trace in progress'


class NoHeapAddress(BaseException):

    def __str__(self):
        return 'Process has no available heap address'


class InvalidStatusField(BaseException):

    def __str__(self):
        return 'Invalid Process Status field'
