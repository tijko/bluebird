#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from bluebird import *

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
        attach(self.test_proc_pid)

    def setUp(self):
        self.create_test_proc()

    def tearDown(self):
        if self.test_proc.stdout is not None:
            self.test_proc.stdout.close()
        self.test_proc.kill()
        
    def test_attach(self):
        number_of_attaches = 10
        for _ in range(number_of_attaches):
            self.create_test_proc()
            tracer_pid = parse_proc_status(self.test_proc_pid)
            self.assertEqual(test_pid, tracer_pid)
                        
    def test_writestring(self):
        test_proc_addr = 0x4006e4
        test_proc_word = 'Potatoe'
        test_proc_filename = 'alt_print.txt'
        test_proc_file = open(test_proc_filename, 'x')
        self.create_test_proc(stdout=test_proc_file)
        test_proc_output = 'Process <{}> is running!'.format(self.test_proc_pid)
        test_proc_newoutput = '{} <{}> is running!'.format(test_proc_word, 
                                                           self.test_proc_pid)
        writestring(self.test_proc_pid, test_proc_addr, test_proc_word)
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
        test_proc_addr = 0x4006e4
        test_proc_word = 'Process'
        word = readstring(self.test_proc_pid, test_proc_addr, 1)
        self.assertEqual(test_proc_word, word)
      
    def test_get_syscall(self):
        sleep(1)
        syscall = get_syscall(self.test_proc_pid)
        self.assertIn(syscall, test_proc_syscalls)

    def test_get_syscalls(self):
        sleep(1)
        test_syscalls = get_syscalls(self.test_proc_pid, 4)
        calls = test_proc_syscalls * 2 
        self.assertCountEqual(test_syscalls, calls)

    def test_detach(self):
        test_proc = Popen('./alt_print', stdout=PIPE)
        sleep(1)
        tracer_pid = parse_proc_status(self.test_proc_pid)
        self.assertEqual(test_pid, tracer_pid)
        detach(self.test_proc_pid)
        tracer_pid = parse_proc_status(self.test_proc_pid)
        self.assertEqual(0, tracer_pid)


if __name__ == "__main__":
    test_pid = getpid()
    test_proc_syscalls = (1, 35)
    unittest.main()
