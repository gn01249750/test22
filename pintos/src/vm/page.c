#include "vm/page.h"




bool update_spt(struct spt* entry)
{
  list_push_back(&thread_current()->s_page_table, &entry->elem);
}



struct spt* get_page(uint8_t *upage)
{
	struct list_elem *e;
  	for(e = list_begin(&thread_current()->s_page_table); e != list_end(&thread_current()->s_page_table); e = list_next(e))
  	{
	  //  printf("@@@@@@@@@@@@ \n");
	struct spt *entry= list_entry(e, struct spt, elem);
    	if(entry->upage == upage){
      		return entry;
    	}
	// printf("@@@@@@@@@@@@@@@@ 2\n");
 	 }
  	return NULL;
}

bool isStackGrowth(const void *vaddr, const void *esp)
{
  if(!is_user_vaddr(vaddr))
    return false;

  if(PHYS_BASE - 0x00800000 > vaddr || (esp -32 != vaddr && esp -8 != vaddr))
    return false;

  return true;
  
}
