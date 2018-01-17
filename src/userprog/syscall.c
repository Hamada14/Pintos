#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>

static struct lock lock_filesystem;

static void syscall_handler(struct intr_frame *);
static void halt(void);
static void exit(int status);
static pid_t exec(const char *cmd_line);
static int wait(pid_t pid);
static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file_name);
static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);
static struct open_file *get_file(file_descriptor fd);
struct file *get_file_by_fd(int fd);
static void close_all_files();

static struct list files_list;
static file_descriptor fd_counter;

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&files_list);
  lock_init(&lock_filesystem);
  fd_counter = 2;
}

static void
validate_addr(size_t* adr) {
  if(adr < 0 || adr == NULL || (!is_user_vaddr(adr)) || (pagedir_get_page (thread_current()->pagedir, adr) == NULL)) {
      exit(-1);
  }
}

static void syscall_handler(struct intr_frame *f) {
  if(f->esp == NULL) {
    exit(-1);
  }
  size_t *esp_ptr = f->esp;
  validate_addr(esp_ptr);
  int syscall_number = *esp_ptr;
  switch (syscall_number) {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    validate_addr(esp_ptr + 1);
    exit(*(esp_ptr + 1));
    break;
  case SYS_EXEC:
    validate_addr(esp_ptr + 1);
    validate_addr(*(esp_ptr + 1));
    f->eax = exec(*(esp_ptr + 1));
    break;
  case SYS_WAIT:
    validate_addr(esp_ptr + 1);
    f->eax = wait(*(esp_ptr + 1));
    break;
  case SYS_CREATE:
    validate_addr(esp_ptr + 1);
    validate_addr(esp_ptr + 2);
    f->eax = create(*(esp_ptr + 1), *(esp_ptr + 2));
    break;
  case SYS_REMOVE:
    validate_addr(esp_ptr + 1);
    f->eax = remove(*(esp_ptr + 1));
    break;
  case SYS_OPEN:
    validate_addr(*(esp_ptr + 1));
    f->eax = open(*(esp_ptr + 1));
    break;
  case SYS_FILESIZE:
    validate_addr(esp_ptr + 1);
    f->eax = filesize(*(esp_ptr + 1));
    break;
  case SYS_READ:
    validate_addr(esp_ptr + 1);
    validate_addr(esp_ptr + 2);
    validate_addr(esp_ptr + 3);
	validate_addr(*(esp_ptr + 2));
    f->eax = read(*(esp_ptr + 1), *(esp_ptr + 2), *(esp_ptr + 3));
    break;
  case SYS_WRITE:
    validate_addr(esp_ptr + 1);
    validate_addr(esp_ptr + 2);
    validate_addr(esp_ptr + 3);
    validate_addr(*(esp_ptr + 2));
	f->eax = write(*(esp_ptr + 1), *(esp_ptr + 2), *(esp_ptr + 3));
    break;
  case SYS_SEEK:
    validate_addr(esp_ptr + 1);
    validate_addr(esp_ptr + 2);
    seek(*(esp_ptr + 1), *(esp_ptr + 2));
    break;
  case SYS_TELL:
    validate_addr(esp_ptr + 1);
    f->eax = tell(*(esp_ptr + 1));
    break;
  case SYS_CLOSE:
    validate_addr(esp_ptr + 1);
    close(*(esp_ptr + 1));
    break;
  default:
    exit(-1);
    break;
  }
}

static void halt(void) { shutdown_power_off(); }

static void exit(int status) {
  close_all_files();
  thread_current()->thread_data->exit_status = status;
  printf ("%s: exit(%d)\n", thread_name(), status);
  sema_up(thread_current()->thread_data->wait_sema);
  thread_exit();
}

static pid_t exec(const char *cmd_line) {
  return (pid_t)process_execute(cmd_line);
}

static int wait(pid_t pid) { return process_wait(pid); }

static bool create(const char *file, unsigned initial_size) {
  validate_addr(file);
  if (file == NULL || *file == '\0' || initial_size < 0) {
  	exit(-1);
  }
  if (strlen(file) > 14) {
  	return false;
  }
  return filesys_create(file, initial_size);
}

static bool remove(const char *file) { return filesys_remove(file); }

static int open(const char *file_name) {
  if (file_name == NULL) {
  	exit(-1);
  }
  struct file *file = filesys_open(file_name);
  if (file == NULL) {
  	return -1;
  }
  struct open_file *open_file = malloc(sizeof(*open_file));
  open_file->file = file;
  open_file->fd = fd_counter++;
  list_push_back(&files_list, &open_file->syscall_list_elem);
  list_push_back(&thread_current()->owned_files, &open_file->thread_list_elem);
  return open_file->fd;
}

static int filesize(int fd) {
  struct open_file *file = get_file(fd);
  if (file != NULL) {
    return file_length(file->file);
  }
  return -1;
}

static int read(int fd, void *buffer, unsigned size) {
  if (fd == 0) {
    while (size--) {
      buffer = input_getc();
      buffer += sizeof(buffer);
    }
  } else {
    struct open_file *file = get_file(fd);
    if (file != NULL) {
      return file_read(file->file, buffer, size);
    } else {
      return -1;
    }
  }
}

static void seek(int fd, unsigned position) {
  struct open_file *file = get_file(fd);
  if (file != NULL) {
    file_seek(file->file, position);
  }
  exit(-1);
}

static unsigned tell(int fd) {
  struct open_file *file = get_file(fd);
  if (file != NULL) {
    return file_tell(file->file);
  }
  exit(-1);
}

static void close(int fd) {
  struct open_file *file = get_file(fd);
  if (file != NULL) {
    file_close(file->file);
    list_remove(&file->syscall_list_elem);
  	list_remove(&file->thread_list_elem);
  }
}

static struct open_file *get_file(file_descriptor fd) {
  for (struct list_elem *e = list_begin(&files_list);
       e != list_end(&files_list); e = list_next(e)) {
    struct open_file *file = list_entry(e, struct open_file, syscall_list_elem);
    if (file->fd == fd) {
      return file;
    }
  }
  return NULL;
}

static int write(int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  lock_acquire(&lock_filesystem);
  struct open_file *file = get_file(fd);
  if (file == NULL) {
    lock_release(&lock_filesystem);
    return -1;
  }
  int sz = file_write(file->file, buffer, size);
  lock_release(&lock_filesystem);
  return sz;
}

static void close_all_files() {
	for (struct list_elem *e = list_begin(&files_list);
       e != list_end(&files_list); e = list_next(e)) {
    struct open_file *file = list_entry(e, struct open_file, syscall_list_elem);
    file_close(file->file);
    list_remove(&file->syscall_list_elem);
  	list_remove(&file->thread_list_elem);
  }
}
