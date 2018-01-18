#include "lib/kernel/list.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

typedef int file_descriptor;

struct open_file {
	file_descriptor fd;
	struct list_elem syscall_list_elem;
	struct list_elem thread_list_elem;
	struct file* file;
	char* file_name;
};

void syscall_init (void);
#endif /* userprog/syscall.h */
