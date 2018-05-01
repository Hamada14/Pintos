#include "lib/kernel/list.h"
#include "threads/synch.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

typedef int file_descriptor;

struct open_file {
	file_descriptor fd;
	struct list_elem elem;
	struct file* file;
	char* file_name;
};

struct lock lock_filesystem;

void syscall_init (void);
void close_all_files(void);
#endif /* userprog/syscall.h */
