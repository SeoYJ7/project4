#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* project 2-3 */
#include <list.h>
#include "filesys/file.h"

/* project 2-3 */
typedef int pid_t;

/* project 2-5 */
struct lock file_lock; 

/* project 2-3 */
struct fd_table_entry
{
    struct list_elem file_elem;
    struct file *file_addr;
	// struct file_holder *file_holder;
    int file_descriptor;
};

/* for 2-EX */
// struct file_holder {
//     struct file *file_addr;
//     int count;
//     enum std_info std_info;
// };

void syscall_init (void);

#endif /* userprog/syscall.h */
