// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
// #include <linux/bpf.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_mkdir")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	u32 uid = bpf_get_current_uid_gid();
	//char comm[16] = {};
	//bpf_get_current_comm(&comm, sizeof(comm));
        char dir[80] = {}; 
	bpf_probe_read_user_str(&dir, sizeof(dir), (void *)ctx->args[0]) ;
        
	// signal = BPF_CORE_READ(ctx, id);
	
	bpf_printk("BPF triggered from PID %d, UID: %d has created a directory %s.\n", pid, uid, &dir);

	return 0;
}
