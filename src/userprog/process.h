#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

void init_argv(char** argv, char* file_name);
void free_argv(char** argv);

void push_ptr_to_stack(size_t **esp, size_t ptr);

void init_file_data(char* unparsed_file_name);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void add_args_to_stack(void **esp, char** argv);
#endif /* userprog/process.h */
