#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

/* project 2-1) Argument Passing */
void args_to_stack(char **argv, int count, struct intr_frame*_if, char **address_list);
int args_parsing (char *file_name, char **argv);

/* project 2-6) Extra */
bool dup_fde_with_distinct_openfile(struct list *parent_fd_table, struct list *child_fd_table);

#endif /* userprog/process.h */
