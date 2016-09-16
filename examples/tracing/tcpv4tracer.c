//
// tcpv4tracer bpf program
// For Linux, uses BCC, eBPF. Embedded C.
//

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>

struct tcp_event_t {
	char type[12];
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
};

BPF_PERF_OUTPUT(tcp_event);
BPF_HASH(connectsock, u32, struct sock *);
BPF_HASH(closesock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();

	##FILTER_PID##

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

	// output
	struct tcp_event_t evt = {
		.type = "connect",
		.pid = pid,
		.saddr = saddr,
		.daddr = daddr,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
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
	u32 pid = bpf_get_current_pid_tgid();

	##FILTER_PID##

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
		.pid = pid,
		.saddr = saddr,
		.daddr = daddr,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
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
	u32 pid = bpf_get_current_pid_tgid();

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
		struct tcp_event_t evt = {.type = "accept", .pid = pid, .netns = net_ns_inum};
		bpf_probe_read(&evt.saddr, sizeof(u32),
			&newsk->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&evt.daddr, sizeof(u32),
			&newsk->__sk_common.skc_daddr);
			evt.sport = lport;
		evt.dport = 0;
		bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
		tcp_event.perf_submit(ctx, &evt, sizeof(evt));
	}
	// else drop

	return 0;
}
