#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define AF_INET 2

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1<<24);
    __type(key, __u64);
    __type(value, __u64);
} start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<24);// 256MB
} events SEC(".maps");

struct event {
    u32 saddr;
    u32 daddr;
    u64 timestamp;
    u16 sport;
    u16 dport;
};

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk)
{
    u64 ts = bpf_ktime_get_ns();
    u64 key = (__u64)sk;
    bpf_map_update_elem(&start_time, &key, &ts, BPF_ANY);
    return 0;
}

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk)
{
    __u64 key = (__u64)sk;
    __u64 *start = bpf_map_lookup_elem(&start_time, &key);
    if (!start) {
        return 0;
    }
    __u64 latency = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&start_time, &key);

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->sport = sk->__sk_common.skc_num;
    e->dport = sk->__sk_common.skc_dport;
    e->saddr = sk->__sk_common.skc_rcv_saddr;
    e->daddr = sk->__sk_common.skc_daddr;
    e->timestamp = latency;

    bpf_ringbuf_submit(e, 0);

    return 0;
}



char LICENSE[] SEC("license") = "Dual MIT/GPL";