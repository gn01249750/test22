#include "vm/frame.h"




struct list all_frames;

struct FrameTableNode {
  tid_t threadID;
  struct thread* thread;
  uint32_t* pageAddr;
  uint32_t* frameAddr;
  struct list_elem elem;
};

void ft_init(void){
  list_init(&all_frames);
}


uint32_t* get_unused_frame(enum palloc_flags flag)
{
  uint32_t* frame = palloc_get_page(flag);
  // check if all frames are taken and implement Page swapping
  if(frame == NULL){
    return page_eviction(flag);
  }
  return frame;
}

bool free_frame_node(struct FrameTableNode *);
bool free_frame_node(struct FrameTableNode *ftn)
{
  list_remove(&ftn->elem);
  pagedir_clear_page(ftn->thread->pagedir, ftn->pageAddr);
  palloc_free_page(ftn->frameAddr);
  free(ftn);
  return true;
}

uint32_t* page_eviction(enum palloc_flags flag)
{
  bool loop = true;
  while(loop){
    struct list_elem *e;
    for(e = list_begin(&all_frames); e != list_end(&all_frames);
	e = list_next(e)){
     struct FrameTableNode *ftn= list_entry(e, struct FrameTableNode, elem);
     // if ftn is allowed to free
     if(free_frame_node(ftn))
       return get_unused_frame(flag);     
    }
  }
  return NULL;
}



void update_frame_table(uint32_t *upage, uint32_t *kpage)
{
  struct FrameTableNode* fn = malloc(sizeof(struct FrameTableNode));
  struct thread* t = thread_current();

  fn->threadID = t->tid;
  fn->pageAddr = upage;
  fn->frameAddr = kpage;

  list_push_back(&all_frames, &fn->elem);
}



