#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"


static struct lock lock_filesystem;

static void syscall_handler (struct intr_frame *);
static void halt (void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file_name);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static  unsigned tell (int fd);
static void close (int fd);
static struct open_file* get_file(file_descriptor fd);

static struct list files_list;
static file_descriptor fd;

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&files_list);
  fd = 2;
}

static void syscall_handler (struct intr_frame *f) {
  size_t* esp_ptr = (size_t*)f->esp;
  int syscall_number = *esp_ptr;
  size_t arg1 = *(esp_ptr + 1);
  size_t arg2 = *(esp_ptr + 2);
  size_t arg3 = *(esp_ptr + 3);
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
	   	create(arg1, arg2);
	   	break;
    case SYS_REMOVE:
    	remove(arg1);
    	break;
    case SYS_OPEN:
    	break;
    case SYS_FILESIZE:
    	break;
    case SYS_READ:
    	break;
   	case SYS_WRITE:
      	// write(arg1, arg2, arg3);
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

static void halt (void) {
	shutdown_power_off();
}

static void exit (int status) {

}

static pid_t exec (const char *cmd_line) {

}

static int wait (pid_t pid) {

}

static bool create (const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

static bool remove (const char *file) {
	return filesys_remove(file);
}

static int open (const char *file_name) {
	struct file* file = filesys_open(file_name);
	if (file == NULL) {
		return -1;
	}
	struct open_file *open_file = malloc(sizeof(struct open_file*));
	open_file->file = file;
	open_file->fd = fd++;
	list_push_back(&files_list, &open_file->syscall_list_elem);
	list_push_back(&thread_current()->owned_files, &open_file->thread_list_elem);
	return open_file->fd;
}

static int filesize (int fd) {
	struct open_file *file = get_file(fd);
    return file_length(file->file);
}

static int read (int fd, void *buffer, unsigned size) {
	if (fd == 0) {
		while (size--) {
			buffer = input_getc();
			buffer += sizeof(buffer);
		}
	} else {
		struct open_file* file = get_file(fd);
		if (file != NULL) {
			return file_read(file->file, buffer, size);
		} else {
       		return -1;
       	}
	}
}

static void seek (int fd, unsigned position) {
   	struct open_file *file = get_file(fd);
   	if (file != NULL) {
		file_seek(file->file, position);
	}
}

static unsigned tell (int fd) {
	struct open_file *file = get_file(fd);
    if (file != NULL) {
    	return file_tell(file->file);
    }
	//RETURN THAT NO FILE WITH THE GIVEN FD NOT FOUND
}

static void close (int fd) {
	struct open_file *file = get_file(fd);
    if (file != NULL) {
    	file_close(file->file);
	}
	list_remove(&file->syscall_list_elem);
	list_remove(&file->thread_list_elem);
}

static struct open_file* get_file(file_descriptor fd) {
	for (struct list_elem* e = list_begin (&files_list); e != list_end (&files_list); e = list_next (e)) {
      		struct open_file *file = list_entry (e, struct open_file, syscall_list_elem);
      		if (file->fd == fd) {
      			return file;
      		}
	}
	return NULL;
}