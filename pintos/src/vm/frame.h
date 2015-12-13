
#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <debug.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include <list.h>



void ft_init(void);
uint32_t* get_unused_frame(enum palloc_flags);
void update_frame_table(uint32_t *, uint32_t *);

#endif

