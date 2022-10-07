#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

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
	check_addr((void *) f->esp);
	int args[3];
	switch (f->R.rax)
    {
		case SYS_HALT:
			halt ();
			break;
		case SYS_EXIT:
			get_args(f, &args[0], 1);
			exit(args[0]);
			break;
	}
}

/* project 2-2 */
void check_addr(void *addr)
{
	if (addr == NULL || is_kernel_vaddr (addr) || addr < (void *) 0x08048000) exit (-1);
}

/* project 2-3 */
void get_args(void *esp, int *arg , int count)
{
  for (int i = 0; i < count; i++)
    {
      int *ptr = (int *) esp + i + 1;
      check_addr((void *) ptr);
      arg[i] = *ptr;
    }
}

void
halt (void)
{
    power_off ();
}

void
exit (int status)
{
    thread_current () -> exit_status = status;
    printf ("%s: exit(%d)\n", thread_name (), status);
    thread_exit ();
}

pid_t
fork (const char *thread_name)
{
	check_addr (thread_name);

}

int
exec (const char *cmd_line)
{
	check_addr (cmd_line);
	char *cmd_line_copy = palloc_get_page (PAL_ZERO);
    strlcpy (cmd_line_copy, cmd_line, strlen (file_name) + 1);

	int child_tid = process_exec (cmd_line_copy)
	palloc_free_page (cmd_line_copy);

    if (child_tid == -1) return -1;
}

int 
wait (pid_t pid)
{

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