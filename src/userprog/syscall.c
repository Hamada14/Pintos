#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include <string.h>
#include <stdio.h>
#include "devices/input.h"
#include <syscall-nr.h>
#include "userprog/process.h"
#include "devices/shutdown.h"


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


void syscall_init (){
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&lock_filesystem);
}

static void validate_addr(size_t *adr) {
  if (adr < (size_t *)0 || adr == NULL || (!is_user_vaddr(adr)) ||
      (pagedir_get_page(thread_current()->pagedir, adr) == NULL)) {
    exit(-1);
  }
}

static void syscall_handler(struct intr_frame *f) {
  if (f->esp == NULL) {
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
    exit((int)*(esp_ptr + 1));
    break;
  case SYS_EXEC:
    validate_addr(esp_ptr + 1);
    validate_addr((size_t *)*(esp_ptr + 1));
    f->eax = exec((const char *)*(esp_ptr + 1));
    break;
  case SYS_WAIT:
    validate_addr(esp_ptr + 1);
    f->eax = wait(*(esp_ptr + 1));
    break;
  case SYS_CREATE:
    validate_addr(esp_ptr + 1);
    validate_addr((size_t *)*(esp_ptr + 1));
    validate_addr(esp_ptr + 2);
    f->eax = create((const char *)*(esp_ptr + 1), *(esp_ptr + 2));
    break;
  case SYS_REMOVE:
    validate_addr(esp_ptr + 1);
    f->eax = remove((const char *)*(esp_ptr + 1));
    break;
  case SYS_OPEN:
    validate_addr((size_t*)*(esp_ptr + 1));
    f->eax = open((const char *)*(esp_ptr + 1));
    break;
  case SYS_FILESIZE:
    validate_addr(esp_ptr + 1);
    f->eax = filesize(*(esp_ptr + 1));
    break;
  case SYS_READ:
    validate_addr(esp_ptr + 1);
    validate_addr(esp_ptr + 2);
    validate_addr(esp_ptr + 3);
    validate_addr((size_t*)*(esp_ptr + 2));
    f->eax = read(*(esp_ptr + 1), (size_t*)*(esp_ptr + 2), *(esp_ptr + 3));
    break;
  case SYS_WRITE:
    validate_addr(esp_ptr + 1);
    validate_addr(esp_ptr + 2);
    validate_addr(esp_ptr + 3);
    validate_addr((size_t*)*(esp_ptr + 2));
    f->eax = write(*(esp_ptr + 1), (size_t *)*(esp_ptr + 2), *(esp_ptr + 3));
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
  lock_acquire(&executable_files_lock);
  remove_executable_file(thread_name());
  lock_release(&executable_files_lock);
  close_all_files();
  clear_memory();
  thread_current()->thread_data->exit_status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  if(!thread_current()->parent_died)
    sema_up(thread_current()->thread_data->wait_sema);
  thread_exit();
}

static pid_t exec(const char *cmd_line) {
  return (pid_t)process_execute(cmd_line);
}

static int wait(pid_t pid) { return process_wait(pid); }

static bool create(const char *file, unsigned initial_size) {
  if (file == NULL || *file == '\0') {
    exit(-1);
  }
  if (strlen(file) > 14) {
    return false;
  }
  lock_acquire(&lock_filesystem);
  bool res = filesys_create(file, initial_size);
  lock_release(&lock_filesystem);
  return res;
}

static bool remove(const char *file) {
  lock_acquire(&lock_filesystem);
  bool ret = filesys_remove(file);
  lock_release(&lock_filesystem);
  return ret;
}

static int open(const char *file_name) {
  if (file_name == NULL) {
  	exit(-1);
  } else if (*file_name == '\0') {
  	return -1;
  }
  lock_acquire(&lock_filesystem);
  struct file *file = filesys_open(file_name);
  if (file == NULL) {
  	lock_release(&lock_filesystem);
    return -1;
  }
  struct open_file *open_file = malloc(sizeof(struct open_file));
  open_file->file = file;
  open_file->fd = thread_current()->fd_counter++;
  open_file->file_name = malloc((1 + strlen(file_name)) * sizeof(char));
  strlcpy(open_file->file_name, file_name, strlen(file_name) + 1);
  list_push_back(&thread_current()->files, &open_file->elem);
  lock_release(&lock_filesystem);
  return open_file->fd;
}

static int filesize(int fd) {
  lock_acquire(&lock_filesystem);
  struct open_file *file = get_file(fd);
  int sz = -1;
  if (file != NULL) {
    sz = file_length(file->file);
  }
  lock_release(&lock_filesystem);
  return sz;
}

static int read(int fd, void *buffer, unsigned size) {
  lock_acquire(&lock_filesystem);
  if (fd == 0) {
  	int sz = 0;
    while (size != 0) {
      size--;
      buffer = input_getc();
      buffer += sizeof(buffer);
      sz++;
    }
    lock_release(&lock_filesystem);
    return sz;
  } else {
    struct open_file *file = get_file(fd);
    int sz = -1;
    if (file != NULL) {
      sz = file_read(file->file, buffer, size);
    }
    lock_release(&lock_filesystem);
    return sz;
  }
}

static void seek(int fd, unsigned position) {
  lock_acquire(&lock_filesystem);
  struct open_file *file = get_file(fd);
  if (file != NULL) {
    file_seek(file->file, position);
    lock_release(&lock_filesystem);
  } else {
    lock_release(&lock_filesystem);
    exit(-1);
  }
}

static unsigned tell(int fd) {
  lock_acquire(&lock_filesystem);
  struct open_file *file = get_file(fd);
  if(file == NULL) {
    lock_release(&lock_filesystem);
    exit(-1);
  }
  int ret = file_tell(file->file);
  lock_release(&lock_filesystem);
  return ret;
}

static void close(int fd) {
  lock_acquire(&lock_filesystem);
  struct open_file *file = get_file(fd);
  if (file != NULL) {
    file_close(file->file);
    list_remove(&file->elem);
    free(file->file_name);
    free(file);
  }
  lock_release(&lock_filesystem);
}

static int write(int fd, const void *buffer, unsigned size) {
  lock_acquire(&lock_filesystem);
  if (fd == 1) {
    putbuf(buffer, size);
    lock_release(&lock_filesystem);
    return size;
  }
  struct open_file *file = get_file(fd);
  int sz = -1;
  if (file != NULL) {
    lock_acquire(&executable_files_lock);
    if (is_executable_file(file->file_name)) {
      lock_release(&executable_files_lock);
      lock_release(&lock_filesystem);
      return 0;
    }
    sz = file_write(file->file, buffer, size);
    lock_release(&executable_files_lock);
  }
  lock_release(&lock_filesystem);
  return sz;
}

static struct open_file *get_file(file_descriptor fd) {
  for (struct list_elem *e = list_begin(&thread_current()->files);
       e != list_end(&thread_current()->files); e = list_next(e)) {
    struct open_file *file = list_entry(e, struct open_file, elem);
    if (file->fd == fd) {
      return file;
    }
  }
  return NULL;
}

void close_all_files() {
  lock_acquire(&lock_filesystem);
	while (!list_empty(&thread_current()->files)) {
    struct open_file *file = list_entry(list_begin(&thread_current()->files), struct open_file, elem);
    file_close(file->file);
  	list_remove(&file->elem);
    free(file->file_name);
    free(file);
  }
  lock_release(&lock_filesystem);
}
