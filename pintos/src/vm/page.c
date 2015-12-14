#include "vm/page.h"
#include <stdio.h>
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"


bool update_spt(struct spt* entry)
{
  list_push_back(&thread_current()->s_page_table, &entry->elem);
}


struct spt *get_page(uint8_t *upage)
{
   struct thread* t = thread_current();
   struct list_elem *e;
   // printf("in pget page @@@@@@@@@@@ \n");
   for(e = list_begin(&t->s_page_table); e != list_end(&t->s_page_table); e = list_next(e)){
     struct spt *entry= list_entry(e, struct spt, elem);
     //   printf("etry upage %p @@@@@@@@@@@@@ \n", entry->upage);
     if(entry->upage == upage){
       return entry;
     }else{
       //    printf("not found @@@@@@@@@@@@@ \n");
     }
   }
   return NULL;
}



bool isStackGrowth(const void *vaddr, const void *esp)
{
  if(!is_user_vaddr(vaddr))
    return false;

    if(PHYS_BASE - 0x00800000 < vaddr &&
       ((esp - 32) == vaddr || (esp - 4) == vaddr)){
      return true;
    }
   
    return false;
}


