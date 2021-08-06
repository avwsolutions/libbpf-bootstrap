/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __KILL9_H
#define __KILL9_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	int signal;
};

#endif /* __BOOTSTRAP_H */
