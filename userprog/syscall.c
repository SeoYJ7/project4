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

	/* projcet 2-5 */
	lock_init (&file_lock);
}

/* project 2-2 */
/* invalid user virtual addr인지 check하는 함수 */
/* mapped되지 않은 virtual address인지 확인하는 방법으로 pml4e_walk (current thread의 pml4에서 addr에 mapping되는 Pte가 없으면 NULL return) 사용
pml4_get_page는 PTE가 있더라도 validity가 0이면 NULL을 return하는데 validity가 0인 것은 page_fault가 일어나야 하는 상황이지 exit이 되어야 하는 상황은 아니기에
pml4e_walk 함수 사용
 */
void check_addr(const uint64_t *addr)
{
	if (addr == NULL || is_kernel_vaddr (addr) || pml4e_walk(thread_current() -> pml4, addr, false) == NULL) exit (-1);
}

/* project 2-3 */
/* power_off 함수를 사용하여 pintos를 종료 */
void halt (void){
	power_off();
}
/* current user program을 종료한다. exit status를 thread가 기억해서 Parent가 wait시에 return 할 수 있도록 한다. */
void exit (int status){
	thread_current() -> exit_status = status;
	printf ("%s: exit(%d)\n", thread_name (), status);
	thread_exit();
}

pid_t fork (const char *thread_name, struct intr_frame *if_){
	check_addr(thread_name);
	return (pid_t) process_fork(thread_name, if_);
}

int
exec (const char *cmd_line)
{
	check_addr (cmd_line);

	char *cmd_line_copy = palloc_get_page (PAL_ZERO);

	if (cmd_line_copy == NULL) exit (-1);

    strlcpy (cmd_line_copy, cmd_line, strlen (cmd_line) + 1);

	int exec_result = process_exec (cmd_line_copy);
	palloc_free_page (cmd_line_copy);

    if (exec_result == -1) return(-1);
	return(0);
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
<<<<<<< HEAD
	if (new_file == NULL)
		return NULL;

=======
	new_file->new_fd = (struct file_holder *) malloc (sizeof (struct file_holder));
	
	new_file->count = 1;
>>>>>>> 8f0503c945bf2988221bf02fa31fc8fbf5319cf1
	new_file->file_addr = f;

	/* project 2-5 */
	if (strcmp (thread_current ()->name, (char *) file) == 0) file_deny_write (f);

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
struct fd_table_entry *get_fd_table_entry (int fd, struct list *fd_list)
{	
	struct fd_table_entry *fde;
	for (struct list_elem *temp = list_begin (fd_list); temp != list_tail (fd_list); temp = list_next (temp)){
		fde = list_entry (temp, struct fd_table_entry, file_elem);
        if (fd == fde->file_descriptor) return fde;
	}
    return NULL;
}

int
filesize (int fd)
{
	lock_acquire(&file_lock);

	struct fd_table_entry *fdte = get_fd_table_entry(fd, &thread_current ()->fd_table);

	if (fdte == NULL){
		lock_release (&file_lock);
        return -1;
	}

	int length = file_length (fdte->file_addr);
	lock_release (&file_lock);
	return length;
}

int 
read (int fd, void *buffer, unsigned size)
{
	check_addr (buffer);
	lock_acquire (&file_lock);
	// 
	struct fd_table_entry *fdte = get_fd_table_entry(fd, &thread_current ()->fd_table);
	
	if (fdte == NULL){
		lock_release (&file_lock);
        // return -1;
		exit (-1);
	}

	if (fd == 0)
	{
		int ret;
		for (int i = 0; i < size; i++){
			if (((char *) buffer)[i] == '\0')
            	ret = i;
				break;
		}
		lock_release (&file_lock);
		return ret;
	}

	if (fd == 1 || fd == 2) {
		lock_release (&file_lock);
		return -1;
	}
	int bytes = file_read (fdte->file_addr, buffer, size);
	lock_release (&file_lock);
	return bytes;
}

int 
write (int fd, const void *buffer, unsigned size)
{
	// PANIC("%s", buffer);
	check_addr (buffer);
	lock_acquire (&file_lock);
	
	if (fd == 0)
	{
		lock_release(&file_lock);
		return -1;
	}

	if (fd == 1)
	{
		putbuf (buffer, size);
    	lock_release(&file_lock);
    	return size;
	}

	if (fd == 2) {
		lock_release(&file_lock);
		return -1;
	}
	
	struct fd_table_entry *fdte = get_fd_table_entry(fd, &thread_current ()->fd_table);
	if (fdte == NULL){
		lock_release (&file_lock);
		exit(-1);
	}
	
	/* project 2-5 */
	if (strcmp (fdte, thread_current ()->name) == 0) file_deny_write (fdte);
	struct file *f = fdte->file_addr;
	if (get_deny_write(f)) file_deny_write (f);

	int bytes = file_write (fdte->file_addr, buffer, size);
	
	

	lock_release (&file_lock);
	return bytes;
}

void 
seek (int fd, unsigned position)
{
	lock_acquire (&file_lock);
	struct fd_table_entry *fdte = get_fd_table_entry(fd, &thread_current ()->fd_table);
	if (fdte == NULL)
    {
        lock_release (&file_lock);
        return -1;
    }
	file_seek (fdte->file_addr, position);
	lock_release (&file_lock);
    return;
}

unsigned
tell (int fd)
{
	lock_acquire (&file_lock);
	struct fd_table_entry *fdte = get_fd_table_entry(fd, &thread_current ()->fd_table);
	if (fdte == NULL)
    {
        lock_release (&file_lock);
        return -1;
    }
	unsigned pos = file_tell (fdte->file_addr);
	lock_release (&file_lock);
	return pos;
}

void
close (int fd)
{
	lock_acquire (&file_lock);
	struct fd_table_entry *fdte = get_fd_table_entry(fd, &thread_current ()->fd_table);
	if (fdte == NULL)
    {
        lock_release (&file_lock);
        return -1;
    }
	// if (fdte->file_addr != NULL) file_close (fdte->file_addr);
	if (fdte->count > 1) {
		fdte->count--;
	} else {
		if (fdte->file_addr != NULL) file_close(fdte->file_addr);
		free(fdte->file_addr);
	}
    list_remove (&fdte->file_elem);
    free (fdte);
    lock_release (&file_lock);
}

void
holder_down (struct file_holder *fh)
{
    if (fh->count > 1) {
        fh->count--;
    } else if (fh->count == 1) {
        if (fh->file_addr != NULL) file_close (fh->file_addr);
        free (fh);
    }
}

int
dup2(int oldfd, int newfd)
{
	lock_acquire (&file_lock);
	struct fd_table_entry *fdte = get_fd_table_entry(oldfd, &thread_current ()->fd_table);
	if (fdte == NULL) {
        lock_release (&file_lock);
        return -1;
    }
	if (fdte->file_holder == NULL) {
        lock_release (&file_lock);
        return -1;
    }
	if (oldfd == newfd) {
        lock_release (&file_lock);
        return newfd;
    }
	struct fd_table_entry *new_fdte = get_fd_table_entry(newfd, &thread_current ()->fd_table);

	if (new_fdte != NULL) {
		holder_down (new_fdte->file_holder)
	} else {
		new_fdte = (struct fd_table_entry *) malloc (sizeof (struct fd_table_entry));
        if (new_fdte == NULL)
        {
            lock_release (&file_lock);
            return -1;
        }
		new_fdte->file_descriptor = newfd;
		list_push_back (&thread_current ()->fd_table, &new_fdte->file_elem);
	}
	
	new_fdte->file_addr = fdte->file_addr;
	new_fdte->count = fdte->count + 1;
	lock_release (&file_lock);
    return newfd; 
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
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork ((const char *) f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = exec ((const char *) f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait ((pid_t) f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create ((const char *) f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove ((const char *) f->R.rdi);
			break;
		case SYS_OPEN:
			// PANIC("open")
			f->R.rax = open ((const char *) f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize (f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read (f->R.rdi, (void *) f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write (f->R.rdi, (void *) f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek (f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell (f->R.rdi);
			break;
		case SYS_CLOSE:
			close (f->R.rdi);
			break;
		case SYS_DUP2:
			f->R.rax = dup2 (f->R.rdi, f->R.rsi);
			break;
	}
}
