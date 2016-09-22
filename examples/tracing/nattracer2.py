#!/usr/bin/python
#
# nattracer	Trace NAT
#		For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: nattracer [-h] [-p PID]
#
from __future__ import print_function
from bcc import BPF

import argparse
import ctypes
import struct

parser = argparse.ArgumentParser(
    description="Trace NA",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <bcc/proto.h>

BPF_PERF_OUTPUT(nat_event);
BPF_HASH(tcpsockbuff, u64, struct sock *);

int kprobe____nf_conntrack_confirm(	struct pt_regs *ctx,
					struct sk_buff *skb)
{
	u64 pid = bpf_get_current_pid_tgid();

	##FILTER_PID##

	struct sock *sk;
	sk = skb->sk;
	// stash the nf_conntrack_tuple ptr for lookup on return
	tcpsockbuff.update(&pid, &sk);

	return 0;
}

int kretprobe____nf_conntrack_confirm(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = tcpsockbuff.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	struct sock *skp = *skpp;

	u32 saddr = 0, daddr = 0;
	u16 sport = 0, dport = 0;

	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

	bpf_trace_printk("trace_nat_tcp %d %d %d\\n", saddr, daddr, sport);

	return 0;
}
"""

def swap16(i):
    return struct.unpack("<H", struct.pack(">H", i))[0]

def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

if args.pid:
    bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('##FILTER_PID##', '')

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-6s %-16s %-16s %-6s" % ("PID", "SADDR", "DADDR", "SPORT"))

def inet_ntoa(addr):
	dq = ''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff)
		if (i != 3):
			dq = dq + '.'
		addr = addr >> 8
	return dq

while 1:
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields()
		(_tag, saddr, daddr, sport) = msg.split(" ")
	except ValueError:
		# Ignore messages from other tracers
		continue

	# Ignore messages from other tracers
	if _tag != "trace_nat_tcp":
		continue

	print("%-6s %-16s %-16s %-6s" % (pid, inet_ntoa(int(saddr)), inet_ntoa(int(daddr)), swap16(int(sport))))
