#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from Bluebird import Bluebird

from time import sleep
from os import getpid, unlink
from subprocess import Popen, PIPE


def parse_proc_status(pid):
    tracer_field = 'TracerPid'
    proc_pid_path = '/proc/{}/status'.format(pid)
    with open(proc_pid_path) as f:
        status_raw = f.readlines()
    tracer_field = status_raw[6].split()
    return int(tracer_field[1])


class BlueBirdTest(unittest.TestCase):

    def create_test_proc(self, stdout=PIPE):
        self.test_proc = Popen('./alt_print', stdout=stdout)
        self.test_proc_pid = self.test_proc.pid
        self.bluebird = Bluebird(self.test_proc_pid)
        self.bluebird.start()

    def tearDown(self):
        if self.test_proc.stdout is not None:
            self.test_proc.stdout.close()
        self.test_proc.kill()
        
    def test_attach(self):
        # XXX stop all running processes started
        number_of_attaches = 10
        for _ in range(number_of_attaches):
            self.create_test_proc()
            tracer_pid = parse_proc_status(self.test_proc_pid)
            self.assertEqual(test_pid, tracer_pid)
            # allow for cleanup of resources
            if self.test_proc.stdout is not None:
                self.test_proc.stdout.close()
            self.test_proc.kill()
            sleep(0.4)
            
    def test_writestring(self):
        # XXX using address from objdump -s alt_print
        # find a way to universally calculate address reading the binary
        test_proc_addr = 0x400754
        test_proc_word = 'Potatoe'
        test_proc_filename = 'alt_print.txt'
        test_proc_file = open(test_proc_filename, 'x')
        self.create_test_proc(stdout=test_proc_file)
        sleep(1)
        test_proc_output = 'Process <{}> is running!'.format(self.test_proc_pid)
        test_proc_newoutput = '{} <{}> is running!'.format(test_proc_word, 
                                                           self.test_proc_pid)
        self.bluebird.write(test_proc_addr, test_proc_word)
        sleep(2)
        test_proc_file.close()
        with open(test_proc_filename) as test_file:
            proc_output = test_file.read()
        unlink(test_proc_filename)
        proc_output_lines = list(filter(None, proc_output.split('\n')))
        before_write = proc_output_lines[0]
        after_write = proc_output_lines[-1]
        self.assertEqual(after_write, test_proc_newoutput)
        self.assertNotEqual(after_write, test_proc_output)
     
    def test_readstring(self):
        # XXX using address from objdump -s alt_print
        # find a way to universally calculate address reading the binary
        self.create_test_proc()
        sleep(1)
        test_proc_addr = 0x400754
        test_proc_word = 'Process'
        word = self.bluebird.read(test_proc_addr, 1)
        self.assertEqual(test_proc_word, word)
      
    def test_get_syscall(self):
        self.create_test_proc()
        sleep(1)
        syscall = self.bluebird.get_current_call()
        self.assertIn(syscall, test_proc_syscalls)

    def test_get_syscalls(self):
        self.create_test_proc()
        sleep(1)
        test_syscalls = self.bluebird.get_ranged_syscalls(4)
        calls = test_proc_syscalls * 2 
        self.assertCountEqual(test_syscalls, calls)
     
    def test_find_syscall(self):
        self.create_test_proc()
        sleep(1)
        getsid = 124
        test_find = self.bluebird.get_call(getsid, non_blocking=True)
        while self.bluebird.tracing:
            sleep(1)
        self.assertIsNone(test_find)
    
    def test_find_syscall_timeout(self):
        self.create_test_proc()
        sleep(1)
        foo_syscall = 404
        test_find = self.bluebird.get_call(foo_syscall, timeout=5)
        self.assertIsNone(test_find)
   
    def test_detach(self):
        self.create_test_proc()
        sleep(1)
        tracer_pid = parse_proc_status(self.test_proc_pid)
        self.assertEqual(test_pid, tracer_pid)
        self.bluebird.stop()
        sleep(1)
        tracer_pid = parse_proc_status(self.test_proc_pid)
        self.assertEqual(0, tracer_pid)
    
if __name__ == '__main__':
    # XXX these syscalls are defined in /usr/include/asm/unistd_64.h
    # rewrite to allow compatibility for 32 too.
    test_pid = getpid()
    test_proc_syscalls = (1, 35)
    unittest.main(verbosity=3)
