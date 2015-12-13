#include "vm/frame.h"




struct list all_frames;

struct FrameTableNode {
  tid_t threadID;
  uint32_t* pageAddr;
  uint32_t* frameAddr;
  struct list_elem elem;
};

void ft_init(void){
  list_init(&all_frames);
}


uint32_t* get_unused_frame(enum palloc_flags flag) {
  uint32_t* frame = palloc_get_page(flag);
  // check if all frames are taken and implement Page swapping
  if(flag == PAL_USER){

  }
  return frame;
}


void update_frame_table(uint32_t *upage, uint32_t *kpage) {
  struct FrameTableNode* fn = malloc(sizeof(struct FrameTableNode));
  struct thread* t = thread_current();

  fn->threadID = t->tid;
  fn->pageAddr = upage;
  fn->frameAddr = kpage;

  list_push_back(&all_frames, &fn->elem);
}



