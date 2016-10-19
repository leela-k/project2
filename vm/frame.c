#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

void init_f_table(void)
{
	list_init(&frame_table);
	lock_init(&frame_table_lock);
}

void add_frame_entry(void* frame)
{
	struct fte *entry = malloc(sizeof(struct fte));
	entry->frame = frame;
	entry->frame_thread = thread_current();
	lock_acquire(&frame_table_lock);
	list_push_back(&frame_table, &entry->elem);
	lock_release(&frame_table_lock);
}

void* add_frame(enum palloc_flags page_flags)
{
	if(page_flags != PAL_USER){
		return NULL;
	}
	void *frame = palloc_get_page(page_flags);
	if(frame){
		add_frame_entry(frame);
	}
	return frame;
}

void remove_frame(void *frame){
	lock_acquire(&frame_table_lock);
	struct list_elem *e;
	for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)){
		struct fte *entry = list_entry(e, struct fte, elem);
		if(entry->frame == frame){
			list_remove(e);
			free(entry);
			palloc_free_page(frame);
			lock_release(&frame_table_lock);
			return;
		}
	}
	lock_release(&frame_table_lock);
	return;
}