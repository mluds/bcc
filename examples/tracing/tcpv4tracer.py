#!/usr/bin/python
#
# tcpv4tracer	Trace TCP IPv4 connections.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4tracer [-h] [-p PID]
#
from __future__ import print_function
from bcc import BPF

import argparse
import ctypes

parser = argparse.ArgumentParser(
    description="Trace TCP IPv4 connections",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

struct tcp_event_t {
	char type[8];
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
};

BPF_PERF_OUTPUT(tcp_event);
BPF_HASH(connectsock, u32, struct sock *);
BPF_HASH(closesock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	connectsock.update(&pid, &sk);

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = connectsock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		connectsock.delete(&pid);
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = 0, daddr = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

	// output
	struct tcp_event_t evt = {
		.type = "connect",
		.pid = pid,
		.saddr = saddr,
		.daddr = daddr,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
	};
	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
	tcp_event.perf_submit(ctx, &evt, sizeof(evt));

	connectsock.delete(&pid);

	return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	FILTER

	// stash the sock ptr for lookup on return
	closesock.update(&pid, &sk);

	return 0;
};

int kretprobe__tcp_close(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = closesock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = 0, daddr = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

	// output
	struct tcp_event_t evt = {
		.type = "close",
		.pid = pid,
		.saddr = saddr,
		.daddr = daddr,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
	};

	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
	tcp_event.perf_submit(ctx, &evt, sizeof(evt));

	closesock.delete(&pid);

	return 0;
}
"""

TASK_COMM_LEN = 16   # linux/sched.h
class TCPEvt(ctypes.Structure):
	_fields_ = [
		("type", ctypes.c_char * 8),
		("pid", ctypes.c_uint),
		("comm", ctypes.c_char * TASK_COMM_LEN),
		("saddr", ctypes.c_uint),
		("daddr", ctypes.c_uint),
		("sport", ctypes.c_ushort),
		("dport", ctypes.c_ushort),
	]

def print_event(cpu, data, size):
	event = ctypes.cast(data, ctypes.POINTER(TCPEvt)).contents
	print("%-8s %-6d %-12s %-16s %-16s %-4s %-4s" % (event.type.decode('utf-8'), event.pid, event.comm.decode('utf-8'),
	    inet_ntoa(event.saddr),
	    inet_ntoa(event.daddr),
	    event.sport,
	    event.dport))

if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-8s %-6s %-12s %-16s %-16s %-4s %-4s" % ("TYPE", "PID", "COMM", "SADDR", "DADDR",
    "SPORT", "DPORT"))

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
