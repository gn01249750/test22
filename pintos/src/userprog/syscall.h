#include <list.h>
#include "threads/thread.h"

typedef int mapid_t;

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct mmap_node {
  int fd;
  void *pageAddr;
  tid_t threadID;
  mapid_t mapid;
  struct list_elem elem;
};

void syscall_init (void);


#endif /* userprog/syscall.h */
