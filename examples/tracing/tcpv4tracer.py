#!/usr/bin/python
#
# tcpv4tracer	Trace TCP IPv4 connections.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4tracer [-h] [-p PID]
#
from __future__ import print_function
from bcc import BPF

import os
import argparse
import ctypes

parser = argparse.ArgumentParser(
    description="Trace TCP IPv4 connections",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()

TASK_COMM_LEN = 16   # linux/sched.h
class TCPEvt(ctypes.Structure):
	_fields_ = [
		("type", ctypes.c_char * 12),
		("pid", ctypes.c_uint),
		("comm", ctypes.c_char * TASK_COMM_LEN),
		("saddr", ctypes.c_uint),
		("daddr", ctypes.c_uint),
		("sport", ctypes.c_ushort),
		("dport", ctypes.c_ushort),
		("netns", ctypes.c_uint),
	]

def print_event(cpu, data, size):
	event = ctypes.cast(data, ctypes.POINTER(TCPEvt)).contents
	print("%-12s %-6s %-16s %-16s %-16s %-6s %-6s %-8s" % (event.type.decode('utf-8'), event.pid, event.comm.decode('utf-8'),
	    inet_ntoa(event.saddr),
	    inet_ntoa(event.daddr),
	    event.sport,
	    event.dport,
	    event.netns))

bpf_program_file_name = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tcpv4tracer.c")
with open(bpf_program_file_name) as bpf_program_file:
	bpf_text = bpf_program_file.read()

if args.pid:
	bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (pid != %s) { return 0; }' % args.pid)
else:
	bpf_text = bpf_text.replace('##FILTER_PID##', '')

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-12s %-6s %-16s %-16s %-16s %-6s %-6s %-8s" % ("TYPE", "PID", "COMM", "SADDR", "DADDR",
    "SPORT", "DPORT", "NETNS"))

def inet_ntoa(addr):
	dq = ''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff)
		if (i != 3):
			dq = dq + '.'
		addr = addr >> 8
	return dq

b["tcp_event"].open_perf_buffer(print_event)
while True:
	b.kprobe_poll()
