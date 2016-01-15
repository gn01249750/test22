#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <list.h>
//#include "vm/swap.h"
//#include "vm/frame.h"
#include "filesys/file.h"
#include <stdbool.h>
#include "threads/thread.h"
#include "threads/vaddr.h"

struct spt
{
	uint8_t *upage;
	struct file* file;
	off_t ofs;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	bool writable;
  
	struct list_elem elem;
};

bool update_spt(struct spt*);
struct spt* get_page(uint8_t*);
bool isStackGrowth(const void *vaddr, const void *esp);



#endif /* vm/page.h */
