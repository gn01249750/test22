#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include <list.h>
#include "threads/malloc.h"
#include "devices/input.h"
#include <user/syscall.h>
#include "threads/palloc.h"
#include "vm/page.h"


struct lock file_lock;
struct file* process_get_file (int fd);
static void syscall_handler (struct intr_frame *);
void halt (void);
void get_arg (struct intr_frame *f, int *arg, int number);
void exit (int status);
tid_t exec (const char *cmd_line);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
struct file *get_file_by_fd (int fd);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
static void check_arg_content(const void *ptr);
void buffer_address_valid(void* buffer, unsigned size);
mapid_t mmap (int fd, void *addr);
void updateSPT(struct file* file, int fileSize, void* addr);
bool isAddrMapped(void* addr);
void munmap (mapid_t map);

#define MAP_FAILED ((mapid_t) -1)

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static bool pointer_is_valid(const void *ptr)
{
  if(!is_user_vaddr(ptr))
    return false;

  if( (void *) 0x08048000 > ptr)
    return false;

  //printf("@@@@@@ before pagedir \n");
   void *ptr2 = pagedir_get_page(thread_current()->pagedir,ptr);
   // printf("page pointer is: %p @@@@@@ \n", ptr2);
   if (ptr2 == NULL)
     return false;
   

  return true; 
}

static void check_arg_content(const void *ptr)
{
  if(!pointer_is_valid(ptr))
    exit(-1);
}

static void check_args(int* start, int number)
{
  int i;
  for(i = 1; i<=number;i++){
    if(!pointer_is_valid((const void *)(start+i))){
      exit(-1);
    }
  }
}

void buffer_address_valid(void* buffer, unsigned size)
{
  unsigned i;
  char* temp = (char *) buffer;
  for( i = 0; i< size ; i++){
      check_arg_content( (const void *) temp);
      temp++;
  }
}

static void
syscall_handler (struct intr_frame *f) 
{
  int * ptr = f->esp;
  
  if(!pointer_is_valid(f->esp))
    process_exit();
  
  switch(* (int *) f->esp){
  case SYS_HALT:
    {
      check_args(f->esp,0);
      halt();
    }
  case SYS_EXIT:
    {
      check_args(f->esp,1);
      exit(*(ptr+1));
      break;
    }
  case SYS_EXEC:
    {
      check_args(f->esp,1);
      if(!pointer_is_valid(ptr+1)){
	exit(-1);
      }
      f->eax = exec(*(ptr+1));
      break;
    }
  case SYS_WAIT:
    {
      check_args(f->esp,1);
      f->eax = wait(*(ptr+1));
      break;
    }
  case SYS_CREATE:
    {
      check_args(f->esp,1);
      f->eax = create(*(ptr+1),*(ptr+2));
      break;
    }
  case SYS_REMOVE:
    {
      check_args(f->esp,1);
      f->eax = remove(*(ptr+1));
      break;
    }
  case SYS_FILESIZE:
    {
      check_args(f->esp,1);
      f->eax = filesize(*(ptr+1));
      break;
    }
  case SYS_READ:
    {
      check_args(f->esp,3);
      
      f->eax = read(*(ptr+1),*(ptr+2),*(ptr+3));
      break;
    }
  case SYS_OPEN:
    {
      check_args(f->esp,1);
      f->eax = open(*(ptr+1));
      break;
    }
  case SYS_WRITE:
    {
      check_args(f->esp,3);
      f->eax = write(*(ptr+1), *(ptr+2), *(ptr+3));
      break;
    }
  case SYS_SEEK:
    {
      check_args(f->esp,2);
      seek(*(ptr+1),*(ptr+2));
      break;
    }
  case SYS_TELL:
    {
      check_args(f->esp,1);
      f->eax = tell(*(ptr+1));
      break;
    }
  case SYS_CLOSE:
    {
      check_args(f->esp,1);
      close(*(ptr+1));
      break;
    }
  case SYS_MMAP:
    {
      check_args(f->esp,2);
      f->eax = mmap(*(ptr+1),*(ptr+2));      
      break;
    }
  case SYS_MUNMAP:
    {
      check_args(f->esp,1);
      munmap(*(ptr+1));
      break;
    }
  }
}

void close (int fd)
{
  struct thread *cur = thread_current();
  struct list *file_list = &cur->file_list;
  struct list_elem *fe;
  struct file_descriptor *sfd;
  bool last = false;
  for(fe = list_begin (file_list); fe != list_end (file_list); fe = list_next (fe)){
    sfd = list_entry (fe, struct file_descriptor, file_list_elem);
    if(sfd->fd == fd){
      lock_acquire (&file_lock);
      file_close(sfd->file);
      lock_release (&file_lock);
      if(list_end(list_next(fe))){
	last = true;
      }
      list_remove(fe);
      free(sfd);
      if (last)
	break;
    }
  }
}

unsigned tell (int fd)
{
  struct file *file = get_file_by_fd(fd);

  if(file == NULL)
    exit(-1);
  
  lock_acquire (&file_lock);
  unsigned bytes =  file_tell(file);
  lock_release (&file_lock);
  return bytes;
}

void seek (int fd, unsigned position)
{
  struct file *file = get_file_by_fd(fd);

  if(file == NULL){
    exit(-1);
  }

  lock_acquire (&file_lock);
  file_seek(file,position);
  lock_release (&file_lock);
  
}

int read(int fd, void *buffer, unsigned size)
{
  check_arg_content((const void *)buffer);
  buffer_address_valid(buffer,size);
  if(fd == 0){    /*read from keyboard */
    int cur_read;
    for(cur_read = 0; cur_read < (int) size; cur_read++){
      *(uint8_t *)(buffer + cur_read) = input_getc();
    }
    return size;
  }else{         /*read from opened file */
    struct file *file = get_file_by_fd(fd);

    if(file == NULL)
      return -1;

    lock_acquire (&file_lock);
    int bytes_read = file_read(file,buffer,size);
    lock_release (&file_lock);
    return bytes_read;    
  }
}


int filesize(int fd)
{
  struct file *file = get_file_by_fd(fd);
  if(file == NULL){
    exit(-1);
  }
  lock_acquire (&file_lock);
  int size = file_length(file);
  lock_release (&file_lock);
  return size;
}

struct file *get_file_by_fd(int fd)
{
  struct thread* cur = thread_current();
  struct list_elem *elem;
  for(elem = list_begin (&cur->file_list); elem != list_end(&cur->file_list);
      elem = list_next (elem)){
    struct file_descriptor *file_descriptor =
      list_entry(elem,struct file_descriptor, file_list_elem);
    if(file_descriptor->fd == fd){
      return file_descriptor->file;
    }
  }
  return NULL;
}

bool remove(const char *file)
{
  check_arg_content((const void *) file);
  if(file == NULL){
    exit(-1);
  }
  lock_acquire (&file_lock);
  bool status = filesys_remove(file);
  lock_release (&file_lock);
  return status;
}

int open(const char *file)
{
  check_arg_content((const void *) file);
  if(file == NULL)
    return -1;

  lock_acquire (&file_lock);
  struct file *open_file = filesys_open(file);
  lock_release(&file_lock);
  
  if(open_file == NULL){
    return -1;
  }
 
  struct list *file_list = &thread_current()->file_list;
  struct list_elem *file_element;  

  int max_fd_number;

  if(list_empty(file_list)){
    max_fd_number = 1;
  }else{
    file_element = list_begin(file_list);
    struct file_descriptor *head_fd =
      list_entry(file_element,struct file_descriptor,file_list_elem);

    max_fd_number = head_fd->fd;

  }
  struct file_descriptor *file_d = malloc(sizeof(struct file_descriptor));
  file_d->fd = max_fd_number +1;
  file_d->file = open_file;
  list_push_front(file_list, &file_d->file_list_elem);
  return max_fd_number + 1;
}

bool create(const char *file, unsigned initial_size)
{
  check_arg_content((const void *) file);
  if(file == NULL)
    exit(-1);
  
  lock_acquire (&file_lock);
  bool status =  filesys_create(file,initial_size);
  lock_release (&file_lock);
  return status;
}

int wait(tid_t pid)
{
  return process_wait(pid);
}

tid_t exec(const char *cmd_line)
{
  check_arg_content((const void *) cmd_line);
  lock_acquire (&file_lock);
  int tid =  process_execute(cmd_line);
  lock_release (&file_lock);
  return tid;
}

void exit(int status)
{
  thread_current()->return_status = status;
  thread_exit();
}

int write(int fd, const void *buffer , unsigned size)
{
  //printf("!!!!!!!!!!enter write \n");
  //printf("@@@@@@ buffer: %p \n", buffer);
  check_arg_content((const void *) buffer);
  // printf("#### fd == %d\n", fd);
  
  buffer_address_valid(buffer,size);
  // printf("@@@@#####$$$$$ \n");
  
  if(fd == 1){   /* write to console.  */
    //printf("fd == 1@@@@@@@@@ \n");
    putbuf(buffer,size);
    return size;
  }else{         /* write to file.  */
    struct file *file = get_file_by_fd(fd);
    //printf("$$$$$$$$**** file got \n");
    if(file == NULL)
      return -1;
    lock_acquire (&file_lock);

    //    printf("$$$$$^^^^^ in lock %p %d %d\n", buffer, fd, file_length(&file));
    
    int written_bytes = file_write(file,buffer,size);
    //    printf("after write ****** @@@@@@ \n");
    lock_release (&file_lock);
    // printf(" release lock @@@@@ %d\n",written_bytes);
    return written_bytes;
  }
}

void halt(void)
{
  shutdown_power_off();
}

mapid_t
mmap (int fd, void *addr)
{
  if(fd == 0 || fd == 1)
    return MAP_FAILED;

  if((uint8_t) addr % PGSIZE != 0 || addr == (void *) 0x0000)
    return MAP_FAILED;

  // TODO: Implement overlapping files condition

  struct file* file = get_file_by_fd(fd);
  unsigned fileSize = (unsigned) filesize(fd);
  if(file == NULL || fileSize == 0) {
      return MAP_FAILED;
  }
  
  bool isDefined = isAddrMapped(addr);
  
  if(isDefined)
    return MAP_FAILED;
  else
    updateSPT(file, fileSize, addr);
  
  // Update the mmap_table in thread
  struct thread *t = thread_current();
  struct mmap_node* mapNode = malloc(sizeof(struct mmap_node));
  mapNode->fd = fd;
  mapNode->pageAddr = addr;
  mapNode->threadID = t->tid;

  if(list_size(&t->mmap_table) == 0)
    t->mmap_size = 1;
  else
    t->mmap_size++;
  
  mapNode->mapid = t->mmap_size;
  list_push_back(&t->mmap_table, &mapNode->elem);

  return t->mmap_size;
}

void
updateSPT(struct file* file, int fileSize, void* addr)
{
  // Create SPTs with File mapping
  struct thread* t = thread_current();
  int sizeItr = (int) fileSize;
  int offset = 0;
  while(sizeItr > 0)
  {
    int page_read_bytes = 0;
    int page_zero_bytes = 0;
    if(sizeItr > PGSIZE)
    {
      page_read_bytes = PGSIZE;
      page_zero_bytes = 0;
    }
    else
    {
      page_read_bytes = sizeItr;
      page_zero_bytes = PGSIZE - sizeItr;
    }
    
    struct spt* supTable = malloc(sizeof(struct spt));
    supTable->upage = addr;
    supTable->file = file;
    supTable->ofs = offset;
    supTable->read_bytes = page_read_bytes;
    supTable->zero_bytes = page_zero_bytes;
    list_push_back(&t->s_page_table, &supTable->elem);
    sizeItr -= PGSIZE;
    offset += PGSIZE;
    addr += PGSIZE;
  }
}

bool
isAddrMapped(void* addr)
{
  struct thread* t = thread_current();
  struct list_elem *e;

  for(e = list_begin (&t->s_page_table); e != list_end(&t->s_page_table);
      e = list_next(e))
  {
    struct spt *supTable = list_entry(e, struct spt, elem);
    if(supTable->upage == addr) {
      printf("@@@@@@@ addr is mapped \n");
      return true;
    }
  }
  return false;
}

void
munmap (mapid_t mapid)
{
  struct thread* t = thread_current();
  struct list_elem *e;
  int fd;
  for(e = list_begin (&t->mmap_table); e != list_end(&t->mmap_table);
      e = list_next(e))
  {
    struct mmap_node *mapNode = list_entry(e, struct mmap_node, elem);
    if(mapNode->mapid == mapid) {
      fd = mapNode->fd;
      list_remove(e);
      free(mapNode);
      break;
    }
  }
  
  struct file* file = get_file_by_fd(fd);
  for(e = list_begin (&t->s_page_table); e != list_end(&t->s_page_table);
      e = list_next(e))
  {
    struct spt *supTable = list_entry(e, struct spt, elem);
    if(supTable->file == file) {
      if(pagedir_is_dirty(t->pagedir, supTable->upage))
	file_write_at(file, supTable->upage, supTable->read_bytes,
		      supTable->ofs);

      list_remove(e);
      free(supTable);
      break;
    }
  }
 
}
