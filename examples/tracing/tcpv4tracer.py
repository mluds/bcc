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
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
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

struct nat_key_t {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
};

struct nat_t {
	u32 nat_saddr;
	u32 nat_daddr;
	u16 nat_sport;
	u16 nat_dport;
};

struct nat_interm_t {
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u16 nat_sport;
	u16 nat_dport;
};

BPF_PERF_OUTPUT(tcp_event);
BPF_HASH(connectsock, u64, struct sock *);
BPF_HASH(closesock, u64, struct sock *);
BPF_HASH(tcpsockbuff, u64, const struct nf_conntrack_tuple *);
BPF_HASH(ipsockbuff, u64, const struct nf_conntrack_tuple *);
BPF_HASH(intermmap, u64, struct nat_interm_t);
BPF_HASH(natmap, struct nat_key_t, struct nat_t);
BPF_HASH(natrevmap, struct nat_t, struct nat_key_t);

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
	struct ns_common *ns;
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

	struct nat_key_t key = {
		.saddr = saddr,
		.daddr = daddr,
		.sport = sport,
		.dport = dport
	};
	struct nat_t *nat = natmap.lookup(&key);

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
		bpf_probe_read(&saddr_nat, sizeof(saddr_nat), &nat->nat_saddr);
		bpf_probe_read(&daddr_nat, sizeof(daddr_nat), &nat->nat_daddr);
		bpf_probe_read(&sport_nat, sizeof(sport_nat), &nat->nat_sport);
		bpf_probe_read(&dport_nat, sizeof(dport_nat), &nat->nat_dport);
		natmap.delete(&key);
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

	struct nat_interm_t *tpl;
	tpl = intermmap.lookup(&pid);
	if (tpl == 0) {
		intermmap.delete(&pid);
		return 0;	// missed entry
	}

	// get tcp information
	u16 sport = 0, nat_sport = 0, dport = 0, nat_dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &tpl->sport);
	bpf_probe_read(&dport, sizeof(dport), &tpl->dport);
	bpf_probe_read(&nat_sport, sizeof(nat_sport), &tpl->nat_sport);
	bpf_probe_read(&nat_dport, sizeof(nat_dport), &tpl->nat_dport);

	struct iphdr *iph;
	unsigned int hdroff = 0;
	// hdr = (struct tcphdr *)(skb->data + hdroff);
	iph = (struct iphdr *)(skb->data + iphdroff);
	hdroff = iphdroff + iph->ihl * 4;

	u32 saddr = 0, daddr = 0;
	bpf_probe_read(&saddr, sizeof(saddr), &iph->saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &iph->daddr);

	struct nat_interm_t newtpl = {
		.sport = sport,
		.dport = dport,
		.saddr = saddr,
		.daddr = daddr,
		.nat_sport = nat_sport,
		.nat_dport = nat_dport};

	intermmap.update(&pid, &newtpl);

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

	struct nat_interm_t *tpl;
	tpl = intermmap.lookup(&pid);
	if (tpl == 0) {
		intermmap.delete(&pid);
		return 0;	// missed entry
	}

	struct nf_conntrack_tuple n;
	bpf_probe_read(&n, sizeof(struct nf_conntrack_tuple), (struct nf_conntrack_tuple *)(*nfctpp));

	// pull in details
	u32 saddr = 0, nat_saddr = 0, daddr = 0, nat_daddr = 0;
	u16 sport = 0, nat_sport = 0, dport = 0, nat_dport = 0;

	bpf_probe_read(&sport, sizeof(sport), &tpl->sport);
	bpf_probe_read(&dport, sizeof(dport), &tpl->dport);
	bpf_probe_read(&nat_sport, sizeof(nat_sport), &tpl->nat_sport);
	bpf_probe_read(&nat_dport, sizeof(nat_dport), &tpl->nat_dport);
	bpf_probe_read(&saddr, sizeof(saddr), &tpl->saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &tpl->daddr);
	bpf_probe_read(&nat_saddr, sizeof(nat_saddr), &n.src.u3.ip);
	bpf_probe_read(&nat_daddr, sizeof(nat_daddr), &n.dst.u3.ip);

	struct nat_key_t key;
	key.saddr = saddr;
	key.daddr = daddr;
	key.sport = sport;
	key.dport = dport;

	struct nat_t val;
	val.nat_sport = nat_sport;
	val.nat_dport = nat_dport;
	val.nat_saddr = nat_saddr;
	val.nat_daddr = nat_daddr;

	// we don't need the intermediate map anymore
	intermmap.delete(&pid);

	// map[{sport, dport, saddr, daddr}] -> [{nat_sport, nat_dport, nat_saddr, nat_daddr}]
	natmap.update(&key, &val);
	// map[{nat_sport, nat_dport, nat_saddr, nat_daddr}] -> [{sport, dport, saddr, daddr}]
	natrevmap.update(&val, &key);

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

	struct tcphdr *hdr;

	int hdrsize = 8;
	if (skb->len >= hdroff + sizeof(struct tcphdr))
		hdrsize = sizeof(struct tcphdr);

	hdr = (struct tcphdr *)(skb->data + hdroff);

	u16 sport = 0, dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &hdr->source);
-       bpf_probe_read(&dport, sizeof(dport), &hdr->dest);

	struct nat_interm_t tpl;
	tpl.sport = sport;
	tpl.dport = dport;
	tpl.saddr = 0;
	tpl.daddr = 0;
	tpl.nat_sport = 0;
	tpl.nat_dport = 0;

	intermmap.update(&pid, &tpl);
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
		intermmap.delete(&pid);
		return 0;	// missed entry
	}

	struct nat_interm_t *tpl;
	tpl = intermmap.lookup(&pid);
	if (tpl == 0) {
		intermmap.delete(&pid);
		return 0;	// missed entry
	}

	struct nf_conntrack_tuple n;
	bpf_probe_read(&n, sizeof(struct nf_conntrack_tuple), (struct nf_conntrack_tuple *)(*nfctpp));

	// pull in details
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, nat_sport = 0, dport = 0, nat_dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &tpl->sport);
	bpf_probe_read(&dport, sizeof(dport), &tpl->dport);
	bpf_probe_read(&nat_sport, sizeof(nat_sport), &n.src.u.tcp.port);
	bpf_probe_read(&nat_dport, sizeof(nat_dport), &n.dst.u.tcp.port);

	struct nat_interm_t newtpl = {
		.sport = sport,
		.dport = dport,
		.saddr = 0,
		.daddr = 0,
		.nat_sport = nat_sport,
		.nat_dport = nat_dport};

	intermmap.update(&pid, &newtpl);
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
