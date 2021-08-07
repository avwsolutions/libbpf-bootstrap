// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hkill.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

int bad_sig = 9;

SEC("tp/syscalls/sys_enter_kill")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
	//struct task_struct *task;
	struct event *e;
	int pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	int tpid = ctx->args[0];
	int sig = ctx->args[1];
        //char comm[16];
        /* only catch hard kills */	
	if (sig != bad_sig)
	  return 0;
        
        /* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	//task = (struct task_struct *)bpf_get_current_task();

	e->pid = pid;
	e->signal = sig;
	e->tpid = tpid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
	
	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;

}
