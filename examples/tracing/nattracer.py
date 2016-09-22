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
BPF_HASH(tcpsockbuff, u64, const struct nf_conntrack_tuple *);
BPF_HASH(ipsockbuff, u64, const struct nf_conntrack_tuple *);

int kprobe__nf_nat_ipv4_manip_pkt(	struct pt_regs *ctx,
					struct sk_buff *skb,
					unsigned int iphdroff,
					const struct nf_nat_l4proto *l4proto,
					const struct nf_conntrack_tuple *target,
					enum nf_nat_manip_type maniptype)
{
	u64 pid = bpf_get_current_pid_tgid();

	##FILTER_PID##

	// stash the nf_conntrack_tuple ptr for lookup on return
	ipsockbuff.update(&pid, &target);

	return 0;
}

int kretprobe__nf_nat_ipv4_manip_pkt(	struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	const struct nf_conntrack_tuple **nfctpp;
	nfctpp = ipsockbuff.lookup(&pid);
	if (nfctpp == 0) {
		return 0;	// missed entry
	}

	struct nf_conntrack_tuple n;
	bpf_probe_read(&n, sizeof(struct nf_conntrack_tuple), (struct nf_conntrack_tuple *)(*nfctpp));

	u32 saddr = 0;
	u32 daddr = 0;
	saddr = n.src.u3.ip;
	daddr = n.dst.u3.ip;
	// output
	bpf_trace_printk("trace_nat_ip %d %d\\n", saddr, daddr);

	return 0;
}

int kprobe__tcp_manip_pkt(	struct pt_regs *ctx,
				struct sk_buff *skb,
				const struct nf_nat_l3proto *l3proto,
				unsigned int iphdroff, unsigned int hdroff,
				const struct nf_conntrack_tuple *tuple,
				enum nf_nat_manip_type maniptype)
{
	u64 pid = bpf_get_current_pid_tgid();

	##FILTER_PID##

	// stash the nf_conntrack_tuple ptr for lookup on return
	tcpsockbuff.update(&pid, &tuple);

	return 0;
}

int kretprobe__tcp_manip_pkt(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	const struct nf_conntrack_tuple **nfctpp;
	nfctpp = tcpsockbuff.lookup(&pid);
	if (nfctpp == 0) {
		return 0;	// missed entry
	}


	struct nf_conntrack_tuple n;
	bpf_probe_read(&n, sizeof(struct nf_conntrack_tuple), (struct nf_conntrack_tuple *)(*nfctpp));

	u16 sport = 0;
	u16 dport = 0;
	sport = n.src.u.tcp.port;
	dport = n.dst.u.tcp.port;
	// output
	bpf_trace_printk("trace_nat_tcp %d %d\\n", sport, dport);

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
print("%-6s %-6s %-6s %-6s" % ("PROTO", "PID", "SPORT", "DPORT"))

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
		(_tag, sport, dport) = msg.split(" ")
	except ValueError:
		# Ignore messages from other tracers
		continue
	
	# Ignore messages from other tracers
	if _tag == "trace_nat_tcp":
	    print("%-6s %-6s %-6s %-6s" % ("tcp", pid, swap16(int(sport)), swap16(int(dport))))
	elif _tag == "trace_nat_ip":
	    print("%-6s %-6s %-16s %-16s" % ("ip", pid, inet_ntoa(int(sport)), inet_ntoa(int(dport))))
	else:
	    continue
