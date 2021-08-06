// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
// #include <linux/bpf.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_kill")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int sig = ctx->args[1];
        // signal = BPF_CORE_READ(ctx, id);
	bpf_printk("BPF triggered from PID %d with signal %d.\n", pid, sig);

	return 0;
}
