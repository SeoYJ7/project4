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
	struct open_file *open_file;
    int file_descriptor;
};

/* project 2-EX */

enum open_file_type
{
    STD_IN,
    STD_OUT,
    STD_ERR,
    FILE
};

struct open_file {
    struct file *file_pos;
    int refcnt;
    enum open_file_type type;
};

void syscall_init (void);

#endif /* userprog/syscall.h */
