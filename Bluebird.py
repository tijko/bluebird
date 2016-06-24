#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bluebird import *
from os import getpid

from threading import Thread


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

    def is_attached(self):
        status_fields = self._parse_status()
        for field in status_fields:
            if 'TracerPid' in field[0]:
                break
        if str(self.pid) != field[1]:
            return False
        return True
 
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

    # halts process at entrance to syscall
    def get_call(self, call, non_blocking=False, timeout=None):
        if non_blocking:
            # check for another running thread
            trace_thread = TracingThread(self, find_syscall, None, 
                                         self.traced_pid, call)
            trace_thread.start()
        else:    
            return find_syscall(self.traced_pid, call)

    def dump_exec(self):
        pass

    def exec_dir(self):
        #make_call(getcwd)
        pass

    def sbrk(self, amount):
        #make_call(sbrk, amount)
        pass

    def name(self):
        status = self._parse_status()
        self.name = status[0][1]

    def _parse_status(self):
        with open('/proc/{}/status'.format(self.traced_pid)) as f:
            status_raw = f.read()
        status = [field.split('\t') for field in status_raw.split('\n')]
        return status
        

class TracingThread(Thread):

    def __init__(self, trace_obj, trace_func, trace_cb, *args):
        super(TracingThread, self).__init__()
        self.trace_obj = trace_obj
        self.trace_func = trace_func
        self.trace_cb = trace_cb
        self.args = args

    def run(self):
        self.trace_obj.tracing = True
        trace_results = self.trace_func(*self.args)
        self.trace_obj.tracing = False
        self.trace_obj.trace_results = trace_results


class RunningTraceError(BaseException):

    def __str__(self):
        return 'Trace in progress'
