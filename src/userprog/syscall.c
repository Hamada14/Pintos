#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);
static void syscall_mapper (int syscall_number);
static struct list files_list;
static file_descriptor fd;

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&files_list);
  fd = 2;
}

static void halt (void) {
	shutdown_power_off();
}

static void exit (int status) {

}

static pid_t exec (const char *cmd_line) {

}

static int wait (pid_t pid) {

}

static bool create (struct intr_frame *f) {
	int stack_ptr;
	stack_ptr = f -> esp;
	stack_ptr = stack_ptr + 4;
	const char* file_name = *stack_ptr;
	stack_ptr = stack_ptr + 4;
	unsigned initial_size = *stack_ptr;
	return filesys_create(file_name, initial_size);
}

static bool remove (struct intr_frame *f) {
	int stack_ptr;
	stack_ptr = *(f -> esp);
	stack_ptr = stack_ptr + 4;
	const char* file_name = *stack_ptr;
	return filesys_remove(file_name);
}

static int open (struct intr_frame *f) {
	int stack_ptr;
	stack_ptr = f -> esp;
	stack_ptr = stack_ptr + 4;
	const char* file_name = *stack_ptr;
	struct file* file_to_open = filesys_open(file_name);
	if (file_to_open == NULL) {
		return -1;
	}
	struct open_file *file = malloc(sizeof(*(struct *open_file)));
	open_file->file = file_to_open;
	open_file->fd = fd++;
	list_push_back(&files_list, &open_file->elem);
	return open_file->fd;
}

static int filesize (struct intr_frame* f) {
	int stack_ptr;
	stack_ptr = f -> esp;
	stack_ptr = stack_ptr + 4;
	int fd = *stack_ptr;
	struct open_file *file_to_get;
	for (e = list_begin (&files_list); e != list_end (&files_list); e = list_next (e)) {
      struct open_file *file = list_entry (e, struct open_file, elem);
      if (file->fd == fd) {
      	file_to_get = file;
      	break;
      }
    }
    if (file_to_get == NULL) {
    	//I DON'T KNOW WHAT TO RETURN
    }
    return file_length(file_to_get->file);
}

static int read (struct  intr_frame* f) {
	int stack_ptr;
	stack_ptr = f -> esp;
	stack_ptr = stack_ptr + 4;
	int fd = *stack_ptr;
	stack_ptr = stack_ptr + 4;
	void* buffer = *stack_ptr;
	stack_ptr = stack_ptr + 4;
	unsigned length = *stack_ptr;
	int size_read = 0;
	if (fd == 0) {
		while (length--) {
			buffer++ = input_getc();
		}
	} else {
		for (e = list_begin (&files_list); e != list_end (&files_list); e = list_next (e)) {
      		struct open_file *file = list_entry (e, struct open_file, elem);
      		if (file->fd == fd) {
      			return file_read(file->file, buffer, length);
      		}
    	}
    	return -1;
	}
}

static int write (int fd, const void *buffer, unsigned length) {

}

static void seek (struct intr_frame* f) {
	int stack_ptr;
	stack_ptr = f -> esp;
	stack_ptr = stack_ptr + 4;
	int fd = *stack_ptr;
	stack_ptr = stack_ptr + 4;
	unsigned position = *stack_ptr;
	for (e = list_begin (&files_list); e != list_end (&files_list); e = list_next (e)) {
      	struct open_file *file = list_entry (e, struct open_file, elem);
      	if (file->fd == fd) {
      		file_seek(file->file, position);
      	}
	}
}

static unsigned tell (struct intr_frame* f) {
	int stack_ptr;
	stack_ptr = f -> esp;
	stack_ptr = stack_ptr + 4;
	int fd = *stack_ptr;
	for (e = list_begin (&files_list); e != list_end (&files_list); e = list_next (e)) {
      	struct open_file *file = list_entry (e, struct open_file, elem);
      	if (file->fd == fd) {
      		return file_tell(file->file);
      	}
	}
	//RETURN THAT NO FILE WITH THE GIVEN FD NOT FOUND
}

static void close (struct intr_frame *f) {
	int stack_ptr;
	stack_ptr = f -> esp;
	stack_ptr = stack_ptr + 4;
	int fd = *stack_ptr;
	for (e = list_begin (&files_list); e != list_end (&files_list); e = list_next (e)) {
      	struct open_file *file = list_entry (e, struct open_file, elem);
      	if (file->fd == fd) {
      		file_close(file->file);
      	}
	}
}

static void syscall_handler (struct intr_frame *f UNUSED) {
	int syscall_number = f -> esp;
	switch (syscall_number) {
		case SYS_HALT:
			halt();
			break;
	    case SYS_EXIT:
	    	break;
	    case SYS_EXEC:
	    	break;
	    case SYS_WAIT:
	    	break;
	    case SYS_CREATE:
	    	create(f);
	    	break;
	    case SYS_REMOVE:
	    	break;
	    case SYS_OPEN:
	    	break;
	    case SYS_FILESIZE:
	    	break;
	    case SYS_READ:
	    	break;
	   	case SYS_WRITE:
	   		break;
	    case SYS_SEEK:
	    	break;
	    case SYS_TELL:
	    	break;
	    case SYS_CLOSE:
	    	break;
	    default:
	    	break;
	}
}