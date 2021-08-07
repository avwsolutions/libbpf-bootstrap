// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
// #include <linux/bpf.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_kill")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	int tpid = ctx->args[0];
	int sig = ctx->args[1];
	bpf_printk("Hello reader, we have TPID: %d killed with Signal: %d by PID:%d\n", tpid, sig, pid);

	return 0;
}
