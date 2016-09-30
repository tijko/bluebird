#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from Bluebird import *

import re
import os
from time import sleep
from subprocess import Popen


def parse_proc_status(pid, field):
    proc_pid_path = '/proc/{}/status'.format(pid)
    with open(proc_pid_path) as f:
        status_raw = f.read()
    status_field = re.findall('{}:\t(.+)\n'.format(field), status_raw)
    return int(status_field[0])


class BlueBirdTest(unittest.TestCase):

    def setUp(self):
        self.test_proc_filename = 'alt_print.txt'
        self.stdout = open(self.test_proc_filename, 'x')
        self.test_proc = Popen('./alt_print', stdout=self.stdout)
        self.test_proc_pid = self.test_proc.pid
        self.bluebird = Bluebird(self.test_proc_pid)
        self.bluebird.start()
        sleep(1)

    def tearDown(self):
        if self.test_proc.stdout is not None:
            self.test_proc.stdout.close()
        else:
            self.stdout.close()
        self.test_proc.kill()
        os.unlink(self.test_proc_filename)
        
    def test_attach(self):
        tracer_pid = parse_proc_status(self.test_proc_pid, 'TracerPid')
        self.assertEqual(test_pid, tracer_pid)
            
    def test_writestring(self):
        # XXX using address from objdump -s alt_print
        # find a way to universally calculate address reading the binary
        test_proc_addr = 0x400764
        test_proc_word = 'Potatoe'
        test_proc_output = 'Process <{}> is running!'.format(self.test_proc_pid)
        test_proc_newoutput = '{} <{}> is running!'.format(test_proc_word, 
                                                           self.test_proc_pid)
        self.bluebird.write(test_proc_addr, test_proc_word)
        sleep(2)
        with open(self.test_proc_filename) as test_file:
            proc_output = test_file.read()
        proc_output_lines = list(filter(None, proc_output.split('\n')))
        before_write = proc_output_lines[0]
        after_write = proc_output_lines[-1]
        self.assertEqual(after_write, test_proc_newoutput)
        self.assertNotEqual(after_write, test_proc_output)
     
    def test_readstring(self):
        # XXX using address from objdump -s alt_print
        # find a way to universally calculate address reading the binary
        test_proc_addr = 0x400764
        test_proc_word = 'Process'
        word = self.bluebird.read(test_proc_addr, 1)
        self.assertEqual(test_proc_word, word)
      
    def test_get_syscall(self):
        syscall = self.bluebird.get_current_call()
        self.assertIn(syscall, test_proc_syscalls)

    def test_get_syscalls(self):
        test_syscalls = self.bluebird.get_ranged_syscalls(4)
        calls = test_proc_syscalls * 2 
        self.assertCountEqual(test_syscalls, calls)
     
    def test_find_syscall(self):
        getsid = 124
        test_find = self.bluebird.get_call(getsid, non_blocking=True)
        while self.bluebird.tracing:
            sleep(1)
        self.assertIsNone(test_find)
    
    def test_find_syscall_timeout(self):
        foo_syscall = 404
        test_find = self.bluebird.get_call(foo_syscall, timeout=5)
        self.assertIsNone(test_find)

    def test_bbrk(self):
        self.bluebird.get_heap()
        limit_before = self.bluebird.heap_bounds[1]
        brk_inc_size = 0xffff
        self.bluebird.expand_heap(brk_inc_size)
        sleep(1)
        limit_after = self.bluebird.heap_bounds[1]
        self.assertEqual(limit_before + brk_inc_size + 1, limit_after)

    def test_bmmap_anon(self):
        self.bluebird.get_heap()
        self.bluebird.create_mmap(0, PAGESIZE, PROT_EXEC | PROT_WRITE,
                MAP_ANONYMOUS | MAP_SHARED, 0)
        self.bluebird.get_maps()
        self.assertIsNotNone(self.bluebird.maps.get('(deleted)'))

    def test_bmmap_file(self):
        self.bluebird.get_heap()
        self.bluebird.create_mmap(0, PAGESIZE, PROT_EXEC | PROT_WRITE,
                MAP_ANONYMOUS | MAP_SHARED, 0, path='/tmp/bluebird')
        self.bluebird.get_maps()
        sleep(1)
        self.assertIsNotNone(self.bluebird.maps.get('(deleted)'))

    def test_get_trace_dir(self):
        curr_dir = os.getcwd()
        self.bluebird.get_heap()
        self.assertEqual(curr_dir, self.bluebird.get_trace_dir()) 

    def test_detach(self):
        tracer_pid = parse_proc_status(self.test_proc_pid, 'TracerPid')
        self.assertEqual(test_pid, tracer_pid)
        self.bluebird.stop()
        sleep(1)
        tracer_pid = parse_proc_status(self.test_proc_pid, 'TracerPid')
        self.assertEqual(0, tracer_pid)
    
if __name__ == '__main__':
    # XXX these syscalls are defined in /usr/include/asm/unistd_64.h
    # rewrite to allow compatibility for 32 too.
    test_pid = os.getpid()
    test_proc_syscalls = (1, 35)
    unittest.main(verbosity=3)
