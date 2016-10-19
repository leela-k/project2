#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdbool.h>
#include <stdint.h>
#include <list.h>

struct lock frame_table_lock;

struct list frame_table;

struct fte {
	void  *frame;	//Pointer to physical frame
	struct thread *frame_thread;
	struct list_elem elem;
};

void init_f_table(void);
void add_frame_entry(void *frame);
void* add_frame(enum palloc_flags page_flags);
void remove_frame(void *frame);