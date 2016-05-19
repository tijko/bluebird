#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from bluebird import *

from os import getpid
from subprocess import Popen, PIPE


def parse_proc_status(pid):
    tracer_field = 'TracerPid'
    proc_pid_path = '/proc/{}/status'.format(pid)
    with open(proc_pid_path) as f:
        status_raw = f.read()
    tracerpid_pos = status_raw.find(tracer_field)
    if tracerpid_pos == -1:
        return 0
    status_fields = [field.split('\t') for field in status_raw.split('\n')]
    for field in status_fields:
        if tracer_field in field[0]:
            return int(field[1]) 
    return 0


class BlueBirdTest(unittest.TestCase):

    def test_attach(self):
        test_pid = getpid()
        number_of_attaches = 10
        test_program = './alt_print'
        for _ in range(number_of_attaches):
            test_proc = Popen(test_program, stdout=PIPE)
            test_proc_pid = test_proc.pid
            attach(test_proc_pid)
            tracer_pid = parse_proc_status(test_proc_pid)
            self.assertEqual(test_pid, tracer_pid)
                        
    def test_writestring(self):
        test_proc_string = 'Process <{}> is running!'
        test_proc_addr = 0x400644
        test_proc_word = 'Potatoe'
        test_proc = Popen('./alt_print', stdout=PIPE)
        test_proc_pid = test_proc.pid
        attach(test_proc_pid)
        writestring(test_proc_pid, test_proc_addr, test_proc_word)

if __name__ == "__main__":
    unittest.main()
