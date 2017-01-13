#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from bluebird import *

import re
import os
import sys
from time import sleep
from subprocess import Popen, PIPE
from elftools.elf import elffile as elf


def parse_proc_status(pid, field):
    proc_pid_path = '/proc/{}/status'.format(pid)
    with open(proc_pid_path) as f:
        status_raw = f.read()
    status_field = re.findall('{}:\t(.+)\n'.format(field), status_raw)
    return int(status_field[0])

def find_string_address(string):
    alt_print_fh = open('alt_print', 'rb')
    elf_handle = elf.ELFFile(alt_print_fh)
    data_section = elf_handle.get_section_by_name('.rodata')
    data = data_section.data()
    start_address = data_section.header['sh_addr']
    section_data = ''.join(map(chr, data))
    return start_address + section_data.find(string)

def compile_test_bin():
    if os.path.isfile('alt_print'):
        os.unlink('alt_print')
    gcc_args = ['gcc', 'alt_print.c', '-o', 'alt_print', '-g', '-Wall']
    print('Compiling test binary <alt_print>...')
    cc = Popen(gcc_args, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    errors = cc.stderr.read()
    if not errors:
        return
    print('Bad compilation!')
    print(errors.strip('\n'))
    sys.exit(0)


class BlueBirdTest(unittest.TestCase):

    def setUp(self):
        self.test_proc_filename = 'alt_print.txt'
        if os.path.exists(self.test_proc_filename):
            os.unlink(self.test_proc_filename)
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
        self.test_proc.wait()
        os.unlink(self.test_proc_filename)
        
    def test_attach(self):
        tracer_pid = parse_proc_status(self.test_proc_pid, 'TracerPid')
        self.assertEqual(test_pid, tracer_pid)
            
    def test_writestring(self):
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
        test_proc_word = 'Process'
        word = self.bluebird.read(test_proc_addr, 1).strip('\n')
        self.assertEqual(test_proc_word, word)
      
    def test_get_syscall(self):
        syscall = self.bluebird.get_current_call()
        self.assertIn(syscall, test_proc_syscalls)

    def test_get_syscalls(self):
        test_syscalls = self.bluebird.get_ranged_syscalls(4)
        calls = test_proc_syscalls * 2 
        self.assertCountEqual(test_syscalls, calls)
     
    def test_find_syscall(self):
        getsid = syscalls['NR_getsid']
        test_find = self.bluebird.find_call(getsid, non_blocking=True)
        while self.bluebird.tracing:
            sleep(1)
        self.assertIsNone(test_find)
    
    def test_find_syscall_timeout(self):
        foo_syscall = 404
        test_find = self.bluebird.find_call(foo_syscall, timeout=5)
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

    def test_getenv(self):
        with open('/proc/{}/environ'.format(self.test_proc_pid)) as fh:
            environ = fh.read()
        environ = environ.split('\x00')
        environ = [var for var in environ if var]
        env_dict = dict(map(lambda s: s.split('=', 1), environ))
        bluebird_env = self.bluebird.getenv()
        self.assertEqual(env_dict, bluebird_env)

    def test_iotrace_write(self):
        process_str = 'Process <{}> is running!\n'.format(self.test_proc_pid)
        self.bluebird.rw_trace(write, ncalls=4)
        for fd in self.bluebird.wdata:
            for wstr in self.bluebird.wdata[fd]:
                self.assertEqual(process_str, wstr)

    def test_detach(self):
        tracer_pid = parse_proc_status(self.test_proc_pid, 'TracerPid')
        self.assertEqual(test_pid, tracer_pid)
        self.bluebird.stop()
        sleep(1)
        tracer_pid = parse_proc_status(self.test_proc_pid, 'TracerPid')
        self.assertEqual(0, tracer_pid)
    
if __name__ == '__main__':
    compile_test_bin()
    test_pid = os.getpid()
    write, nanosleep = syscalls['NR_write'], syscalls['NR_nanosleep']
    test_proc_addr = find_string_address('Process')
    test_proc_syscalls = (write, nanosleep)
    unittest.main(verbosity=3, exit=False)
    os.unlink('alt_print')
