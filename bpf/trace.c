#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);// 256MB
} events SEC(".maps");

// sock カーネルがTCP接続などのソケット情報を管理するための構造体
// bpf_probe_read_kernelヘルパー関数を使い、カーネルメモリからIPアドレスを読み出します
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_connect, struct sock *sk)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    bpf_probe_read_kernel(&e->src_ip, sizeof(e->src_ip), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&e->dst_ip, sizeof(e->dst_ip), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&e->dst_port, sizeof(e->dst_port), &sk->__sk_common.skc_dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
