#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
/* project 2-3 */
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	//printf ("system call!\n");
	//thread_exit ();
	/* project 2-3 */
	switch (f->R.rax)
    {
		case SYS_HALT:
			halt ();
			break;
		case SYS_EXIT:
			exit((int) f->R.rdi);
			break;
	}
}

/* project 2-2 */
/* invalid user virtual addr인지 check하는 함수 */
/* mapped되지 않은 virtual address인지 확인하는 방법으로 pml4e_walk (current thread의 pml4에서 addr에 mapping되는 Pte가 없으면 NULL return) 사용
pml4_get_page는 PTE가 있더라도 validity가 0이면 NULL을 return하는데 validity가 0인 것은 page_fault가 일어나야 하는 상황이지 exit이 되어야 하는 상황은 아니기에
pml4e_walk 함수 사용
 */
void check_addr(void *addr)
{
	if (addr == NULL || is_kernel_vaddr (addr) || pml4e_walk(thread_current() -> pml4, addr, 0) == NULL) exit (-1);
}

/* project 2-3 */
/* power_off 함수를 사용하여 pintos를 종료 */
void halt (void){
	power_off();
}
/* current user program을 종료한다. exit status를 thread가 기억해서 Parent가 wait시에 return 할 수 있도록 한다. */
void exit (int status){
	thread_current() -> exit_status = status;
	thread_exit();
}

void get_args(void *esp, int *arg , int count)
{
  for (int i = 0; i < count; i++)
    {
      int *ptr = (int *) esp + i + 1;
      check_addr((void *) ptr);
      arg[i] = *ptr;
    }
}

int
exec (const char *cmd_line)
{
	check_addr (cmd_line);
	char *cmd_line_copy = palloc_get_page (PAL_ZERO);
    strlcpy (cmd_line_copy, cmd_line, strlen (cmd_line) + 1);

	int exec_result = process_exec (cmd_line_copy);
	palloc_free_page (cmd_line_copy);

    if (exec_result == -1) return -1;
}

int 
wait (pid_t pid)
{
	return process_wait ((tid_t) pid);
}

bool
create (const char *file , unsigned initial_size)
{
    check_addr (file);
	return filesys_create (file, initial_size);
}

bool
remove (const char *file)
{
    check_addr (file);
	return filesys_remove (file);
}

// helper function for open()
bool
file_descriptor_less_func (struct list_elem *e1, struct list_elem *e2, void *aux UNUSED)
{
    struct fd_table_entry *f1 = list_entry (e1, struct fd_table_entry, file_elem);
    struct fd_table_entry *f2 = list_entry (e2, struct fd_table_entry, file_elem);
    return f1->file_descriptor < f2->file_descriptor;
}

int
open (const char *file)
{
	check_addr (file);
	lock_acquire (&file_lock);

	struct file *f = filesys_open(file);

	if(f == NULL)
	{
		lock_release(&file_lock);
		return -1;
	}

	struct thread *curr_thread = thread_current ();
	struct list *curr_fds = &curr_thread->fd_table;
	
	struct fd_table_entry *new_file = (struct fd_table_entry *) malloc (sizeof (struct fd_table_entry));
	
	new_file->file_addr = f;

	int n = 3; // 0, 1, 2 는 정해져있기 때문에 3부터 시작
	list_sort(curr_fds, file_descriptor_less_func, NULL);
	for (struct list_elem *temp = list_begin (curr_fds); temp != list_end (curr_fds); temp = list_next (temp)){
		struct fd_table_entry *fp = list_entry (temp, struct fd_table_entry, file_elem);
		if (fp->file_descriptor < n) continue;
		else if (fp->file_descriptor == n) n++;
		else if (fp->file_descriptor > n) break;
	}
	new_file->file_descriptor = n;

	list_push_back (curr_fds, &new_file->file_elem);

	int fd = new_file->file_descriptor;
	lock_release (&file_lock);
	return fd;
}

// helper function
struct fd_table_entry *get_file_descriptor (int fd, struct list *fd_list)
{
    struct file_descriptor *fd_ptr;
    struct list_elem *elem_ptr;

    elem_ptr = list_begin (fd_list);
    while (elem_ptr != list_tail (fd_list))
    {
        if (list_next (elem_ptr) == NULL)
            break;
        fd_ptr = list_entry (elem_ptr, struct file_descriptor, fd_elem);
        if (fd == fd_ptr->fd_number)
            return fd_ptr;
        elem_ptr = list_next (elem_ptr);
    }
    return NULL;
}

int
filesize (int fd){

}