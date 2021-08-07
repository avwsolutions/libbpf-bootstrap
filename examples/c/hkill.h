/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __HKILL_H
#define __HKILL_H

#define COMM_LEN 16

struct event {
	int pid;
	char comm[COMM_LEN];
	int tpid;
	int signal;
};

#endif /* __HKILL_H */
