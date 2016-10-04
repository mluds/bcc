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
#include <net/net_namespace.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <bcc/proto.h>

struct tcp_event_t {
	char type[12];
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 saddr_nat;
	u32 daddr_nat;
	u16 sport_nat;
	u16 dport_nat;
	u32 netns;
};

struct nat_t {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	char needs_ip;
	char padding[3];
};

BPF_PERF_OUTPUT(tcp_event);
BPF_HASH(connectsock, u64, struct sock *);
BPF_HASH(closesock, u64, struct sock *);
BPF_HASH(tcpsockbuff, u64, const struct nf_conntrack_tuple *);
BPF_HASH(ipsockbuff, u64, const struct nf_conntrack_tuple *);
BPF_HASH(natmap, u64, struct nat_t);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u64 pid = bpf_get_current_pid_tgid();

	##FILTER_PID##

	// stash the sock ptr for lookup on return
	connectsock.update(&pid, &sk);

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	struct nat_t *nat;
	nat = natmap.lookup(&pid);

	struct sock **skpp;
	skpp = connectsock.lookup(&pid);
	if (skpp == 0) {
		if (nat != 0) {
			natmap.delete(&pid);
		}
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
	struct ns_common *ns;
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#else
	net_ns_inum = 0;
#endif

	u32 saddr_nat = 0, daddr_nat = 0;
	u16 sport_nat = 0, dport_nat = 0;
	if (nat != 0) {
	    bpf_probe_read(&saddr_nat, sizeof(saddr_nat), &nat->saddr);
	    bpf_probe_read(&daddr_nat, sizeof(daddr_nat), &nat->daddr);
	    bpf_probe_read(&sport_nat, sizeof(sport_nat), &nat->sport);
	    bpf_probe_read(&dport_nat, sizeof(dport_nat), &nat->dport);
	}

	// output
	struct tcp_event_t evt = {
		.type = "connect",
		.pid = pid >> 32,
		.saddr = saddr,
		.daddr = daddr,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
		.saddr_nat = saddr_nat,
		.daddr_nat = daddr_nat,
		.sport_nat = ntohs(sport_nat),
		.dport_nat = ntohs(dport_nat),
		.netns = net_ns_inum,
	};

	u16 family = 0;
	bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);

	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
	tcp_event.perf_submit(ctx, &evt, sizeof(evt));

	connectsock.delete(&pid);

	return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
	u64 pid = bpf_get_current_pid_tgid();

	##FILTER_PID##

	// stash the sock ptr for lookup on return
	closesock.update(&pid, &sk);

	return 0;
};

int kretprobe__tcp_close(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = closesock.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	// pull in details
	struct sock *skp = *skpp;
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#else
	net_ns_inum = 0;
#endif

	// output
	struct tcp_event_t evt = {
		.type = "close",
		.pid = pid >> 32,
		.saddr = saddr,
		.daddr = daddr,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
		.saddr_nat = 0,
		.daddr_nat = 0,
		.sport_nat = 0,
		.dport_nat = 0,
		.netns = net_ns_inum,
	};

	u16 family = 0;
	bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);

	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
	tcp_event.perf_submit(ctx, &evt, sizeof(evt));

	closesock.delete(&pid);

	struct nat_t *nat;
	nat = natmap.lookup(&pid);
	if (nat != 0) {
		natmap.delete(&pid);
	}

	return 0;
}

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	##FILTER_PID##

	if (newsk == NULL)
		return 0;

	// check this is TCP
	u8 protocol = 0;
	// workaround for reading the sk_protocol bitfield:
	bpf_probe_read(&protocol, 1, (void *)((long)&newsk->sk_wmem_queued) - 3);
	if (protocol != IPPROTO_TCP)
		return 0;

	// pull in details
	u16 family = 0, lport = 0;
	u32 net_ns_inum = 0;
	bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);
	bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);

// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &newsk->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#else
	net_ns_inum = 0;
#endif

	if (family == AF_INET) {
		struct tcp_event_t evt = {.type = "accept", .netns = net_ns_inum};
		evt.pid = pid >> 32;
		bpf_probe_read(&evt.saddr, sizeof(u32),
			&newsk->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&evt.daddr, sizeof(u32),
			&newsk->__sk_common.skc_daddr);
			evt.sport = lport;
		evt.dport = 0;
		evt.saddr_nat = 0;
		evt.daddr_nat = 0;
		evt.sport_nat = 0;
		evt.dport_nat = 0;
		bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
		tcp_event.perf_submit(ctx, &evt, sizeof(evt));
	}
	// else drop

	return 0;
}

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

	struct nat_t *nat;
	nat = natmap.lookup(&pid);
	if (nat == 0) {
		return 0;	// no nat
	}

	char needs_ip = 0;
	bpf_probe_read(&needs_ip, sizeof(needs_ip), &nat->needs_ip);
	if (!needs_ip) {
		return 0;	// already got the info
	}

	struct nf_conntrack_tuple n;
	bpf_probe_read(&n, sizeof(struct nf_conntrack_tuple), (struct nf_conntrack_tuple *)(*nfctpp));

	// pull in details
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&saddr, sizeof(saddr), &n.src.u3.ip);
	bpf_probe_read(&daddr, sizeof(daddr), &n.dst.u3.ip);

	u16 natted_sport = 0;
	u16 natted_dport = 0;
	bpf_probe_read(&natted_sport, sizeof(natted_sport), &nat->sport);
	bpf_probe_read(&natted_dport, sizeof(natted_dport), &nat->dport);

	struct nat_t newnat = {
		.sport = natted_sport,
		.dport = natted_dport,
		.saddr = saddr,
		.daddr = daddr,
		.needs_ip = 0};
	natmap.update(&pid, &newnat);

	ipsockbuff.delete(&pid);

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

	struct nat_t *nat;
	nat = natmap.lookup(&pid);
	if (nat != 0) {
		return 0;	// alredy got the info
	}

	struct nf_conntrack_tuple n;
	bpf_probe_read(&n, sizeof(struct nf_conntrack_tuple), (struct nf_conntrack_tuple *)(*nfctpp));

	// pull in details
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &n.src.u.tcp.port);
	bpf_probe_read(&dport, sizeof(dport), &n.dst.u.tcp.port);

	struct nat_t newnat = {
		.sport = sport,
		.dport = dport,
		.saddr = 0,
		.daddr = 0,
		.needs_ip = 1};
	natmap.update(&pid, &newnat);

	tcpsockbuff.delete(&pid);

	return 0;
}
"""

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
		("saddr_nat", ctypes.c_uint),
		("daddr_nat", ctypes.c_uint),
		("sport_nat", ctypes.c_ushort),
		("dport_nat", ctypes.c_ushort),
		("netns", ctypes.c_uint),
	]

def print_event(cpu, data, size):
	event = ctypes.cast(data, ctypes.POINTER(TCPEvt)).contents
	print("%-12s %-6s %-16s %-16s %-16s %-6s %-6s %-16s %-16s %-6s %-6s %-8s" % (event.type.decode('utf-8'), event.pid, event.comm.decode('utf-8'),
	    inet_ntoa(event.saddr),
	    inet_ntoa(event.daddr),
	    event.sport,
	    event.dport,
	    inet_ntoa(event.saddr_nat),
	    inet_ntoa(event.daddr_nat),
	    event.sport_nat,
	    event.dport_nat,
	    event.netns))

if args.pid:
    bpf_text = bpf_text.replace('##FILTER_PID##',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('##FILTER_PID##', '')

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-12s %-6s %-16s %-16s %-16s %-6s %-6s %-16s %-16s %-6s %-6s %-8s" % ("TYPE", "PID", "COMM", "SADDR", "DADDR",
    "SPORT", "DPORT", "SADDR_NAT", "DADDR_NAT", "SPORT_NAT", "DPORT_NAT", "NETNS"))

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
