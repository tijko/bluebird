#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bluebird import *
from os import getpid

from threading import Thread


class Bluebird(object):

    def __init__(self, pid):
        self.pid = getpid()
        self.traced_pid = pid
        self.wstrs = {}
        self.rstrs = {}
        self.attached = False

    def start(self):
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

    def get_call(self, call):
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
        
