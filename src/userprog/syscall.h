#include "lib/kernel/list.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

typedef int file_descriptor;

void syscall_init (void);

struct open_file {
	file_descriptor fd;
	struct list_elem elem;
	struct file* file;
};

#endif /* userprog/syscall.h */
