#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdbool.h>
#include <string.h>

typedef int pid_t;
typedef int fid_t;
#define userSpaceBottom ((void*) 0x08084000)

void syscall_handler (struct intr_frame *);
void halt(void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
struct file* getFileByFd(int fd);
void checkPtr(void* pt);



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
syscall_handler (struct intr_frame *f UNUSED){
	int * callArg = f->esp;

  	if (!(is_user_vaddr(callArg) && is_user_vaddr (callArg + 3)))
    	exit(-1);
    if(callArg < userSpaceBottom)
        exit(-1);

    int params[4];
    int i = 0;
    while(i < 4){
    	params[i] = *(callArg + i);
    	i++;
    }

    //printf("About to switch on the SYSTEM CALL\n");
    switch (params[0]){
    	case SYS_HALT:
    		//printf("HALT CALLED\n");
    		halt();
    		break;
    	case SYS_EXIT:
    		//printf("EXIT CALLED\n");
    		exit(params[1]);
    		break;
    	case SYS_EXEC:
    		//printf("EXEC CALLED\n");
    		f->eax = exec((const char*)params[1]);
    		break;
    	case SYS_WAIT:
    		//printf("WAIT CALLED\n");
    		f->eax = wait((pid_t)params[1]);
    		break;
    	case SYS_CREATE:
    		//printf("CREATE CALLED\n");
    		f->eax = create((const char*)params[1], (unsigned)params[2]);
    		break;
    	case SYS_REMOVE:
    		//printf("REMOVE CALLED\n");
    		f->eax = remove((const char*)params[1]);
    		break;
    	case SYS_OPEN:
    		//printf("OPEN CALLED\n");
    		f->eax = open((const char*)params[1]);
    		break;
    	case SYS_FILESIZE:
    		//printf("FILESIZE CALLED\n");
    		f->eax = filesize(params[1]);
    		break;
    	case SYS_READ:
    		//printf("READ CALLED\n");
    		f->eax = read(params[1], (void*)params[2], (unsigned)params[3]);
    		break;
    	case SYS_WRITE:
    		//printf("WRITE CALLED\n");
    		//char * buff = (char *)params[2];
    		//printf("\n\n%s\n\n", buff);
    		f->eax = write(params[1], (void*)params[2], (unsigned)params[3]);
    		break;
    	case SYS_SEEK:
    		//printf("SEEK CALLED\n");
    		seek(params[1], (unsigned)params[2]);
    		break;
    	case SYS_TELL:
    		//printf("TELL CALLED\n");
    		f->eax = tell(params[1]);
    		break;
    	case SYS_CLOSE:
    		//printf("CLOSE CALLED\n");
    		close(params[1]);
    		break;
    	default:
    		//printf("WHAT THE FUCK\n");
			break;
    }

  //printf ("system call!\n");
  return;
  //thread_exit ();
}

/* Terminates Pintos by calling shutdown_power_off() (declared in threads/init.h). 
This should be seldom used, because you lose some information about possible deadlock situations, etc.*/
void halt(void){
	//printf("ENTERED HALT HANDLER\n");
	shutdown_power_off();
}
/* Terminates the current user program, returning status to the kernel. If the process's parent waits for it (see below), 
this is the status that will be returned. Conventionally, a status of 0 indicates success and 
nonzero values indicate errors.*/
void exit (int status){
	//printf("ENTERED EXIT HANDLER\n");
    struct thread *cur = thread_current();
    printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}
/*Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program 
id (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. 
Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its 
executable. You must use appropriate synchronization to ensure this.*/
pid_t exec (const char *cmd_line){
	printf("ENTERED EXEC HANDLER\n");
}
/*Waits for a child process pid and retrieves the child's exit status.
If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. If pid did not call 
exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. It is perfectly legal 
for a parent process to wait for child processes that have already terminated by the time the parent calls wait, but the 
kernel must still allow the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel.

wait must fail and return -1 immediately if any of the following conditions is true:

pid does not refer to a direct child of the calling process. pid is a direct child of the calling process if and only if the 
calling process received pid as a return value from a successful call to exec.
Note that children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C, even if 
B is dead. A call to wait(C) by process A must fail. Similarly, orphaned processes are not assigned to a new parent if their 
parent process exits before they do.

The process that calls wait has already called wait on pid. That is, a process may wait for any given child at most once.
Processes may spawn any number of children, wait for them in any order, and may even exit without having waited for some or 
all of their children. Your design should consider all the ways in which waits can occur. All of a process's resources, 
including its struct thread, must be freed whether its parent ever waits for it or not, and regardless of whether the child 
exits before or after its parent.

You must ensure that Pintos does not terminate until the initial process exits. The supplied Pintos code tries to do this 
by calling process_wait() (in userprog/process.c) from main() (in threads/init.c). We suggest that you implement 
process_wait() according to the comment at the top of the function and then implement the wait system call in terms of 
process_wait().

Implementing this system call requires considerably more work than any of the rest.*/
int wait (pid_t pid){
	//printf("ENTERED WAIT HANDLER\n");
	return -1;
}
/*Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. 
Creating a new file does not open it: opening the new file is a separate operation which would require a open system call.*/
bool create (const char *file, unsigned initial_size){

    //printf("File name is: %s\n", file);

    //Fail if file is NULL
    //checkPtr((void * ) file);
    struct thread* cur = thread_current();
    if(file == NULL){
        exit(-1);
    }
    if(!(is_user_vaddr(file)))
        exit(-1);
    if(!pagedir_get_page(cur->pagedir, file)){
        exit(-1);
    }

    //checkPtr(file);
    // //Fail if file name empty
    // if(file[0] == '\0'){
    //     printf("File name empty\n");
    //     //exit(-1);
    //     return false;
    // }

    //Fail if file name too long
    if(strlen(file) > 14){
        return false;
        
    }

    return  filesys_create(file, initial_size);
}
/*Deletes the file called file. Returns true if successful, false otherwise. A file may be removed regardless of whether 
it is open or closed, and removing an open file does not close it. See Removing an Open File, for details.*/
bool remove (const char *file){
	//printf("ENTERED REMOVE HANDLER\n");
	return false;
}
/*Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could 
not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) 
is standard output. The open system call will never return either of these file descriptors, which are valid as system call 
arguments only as explicitly described below.

Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.

When a single file is opened more than once, whether by a single process or different processes, each open returns a new 
file descriptor. Different file descriptors for a single file are closed independently in separate calls to close and 
they do not share a file position.*/
int open (const char *file){
	//printf("ENTERED OPEN HANDLER\n");
    struct thread* cur = thread_current();
    if(file == NULL)
        return -1;
    if(!(is_user_vaddr(file)))
        exit(-1);
    if(!pagedir_get_page(cur->pagedir, file)){
        exit(-1);
    }

    struct file* newFile = filesys_open(file);
    if(!newFile){
        return -1;
    }
    struct filewd* fed = malloc(sizeof(struct filewd));
    fed->fileS = newFile;
    fed->fd = cur->fdIndex;
    cur->fdIndex++;
    list_push_back(&cur->files, &fed->elem);
	return fed->fd;
}
/*Returns the size, in bytes, of the file open as fd.*/
int filesize (int fd){
	//printf("ENTERED FILESIZE HANDLER\n");
    struct file* fileToSizeUp = getFileByFd(fd);
    return file_length(fileToSizeUp);
}
/*Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), 
or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using 
input_getc().*/
int read (int fd, void *buffer, unsigned size){
	//printf("ENTERED READ HANDLER\n");
    struct thread* cur = thread_current();
    //Read from standard input
    if (!(is_user_vaddr(buffer)))
        exit(-1);
    if(!pagedir_get_page(cur->pagedir, buffer)){
        exit(-1);
    }

    if(fd == 1){
        return -1;
    }
    if(fd == 0){
        uint32_t i;
        char* buf = (char*) buffer;
        for(i = 0; i < size; i++){
            buf[i] = input_getc();
        }
        return size;
    }
    else{
        struct file* fileToRead = getFileByFd(fd);
        //NULL file
        if(fileToRead == NULL){
            return -1;
        }
        
        int bytes = file_read(fileToRead, buffer, size);
        return bytes;
    }
    return -1;
}
/*Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than 
size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. The 
expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if 
no bytes could be written at all.

Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), 
at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) 
Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human 
readers and our grading scripts.*/
int write (int fd, const void *buffer, unsigned size){
	//printf("ENTERED WRITE HANDLER\n");
    struct thread* cur = thread_current();

    if(!pagedir_get_page(cur->pagedir, buffer)){
        exit(-1);
    }

    struct file* fileS;
    if(fd == 0){
        return -1;
    }
    if(fd == 1){
        putbuf(buffer, size);
        return size;
    }
    else{
        fileS = getFileByFd(fd);
        if(fileS == NULL){
            return -1;
        }
        return file_write(fileS,buffer, size);
        printf("SOMETHING WENT WRONG DURING WRITE HANDLE\n");
        
    }
}
/*Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the 
file. (Thus, a position of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. A later 
write extends the file, filling any unwritten gap with zeros. (However, in Pintos files have a fixed length until 
project 4 is complete, so writes past end of file will return an error.) These semantics are implemented in the file 
system and do not require any special effort in system call implementation.*/
void seek (int fd, unsigned position){
	//printf("ENTERED SEEK HANDLER\n");
    struct file* fileS = getFileByFd(fd);
    if(!fileS){
        return -1;
    }
    return file_seek(fileS, position);
}
/*Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the 
beginning of the file.*/
unsigned tell (int fd){
	//printf("ENTERED TELL HANDLER\n");
    struct file* fileS = getFileByFd(fd);
    if(!fileS){
        return -1;
    }
    return file_tell(fileS);
	return 0;
}
/*Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by 
calling this function for each one.*/
void close (int fd){
	//printf("ENTERED CLOSE HANDLER\n");
    if(fd == 0 || fd == 1){
        return;
    }
    
    struct thread* cur =  thread_current();
    struct list_elem *e;

      for (e = list_begin (&cur->files); e != list_end (&cur->files);
           e = list_next (e))
        {
          struct filewd *f = list_entry (e, struct filewd, elem);
          if(fd == f->fd)
            {
                list_remove(&(f->elem));
                free(f);
                return;
            }
        }

    

}

struct file* getFileByFd(int fd){
    struct thread* cur =  thread_current();
    struct list_elem *e;

      for (e = list_begin (&cur->files); e != list_end (&cur->files);
           e = list_next (e))
        {
          struct filewd *f = list_entry (e, struct filewd, elem);
          if(fd == f->fd)
            {
                return f->fileS;
            }
        }
    return NULL;
}

void checkPtr(void* pt){
    struct thread* cur = thread_current();
    if (!(is_user_vaddr(pt)) || pt < userSpaceBottom || !pagedir_get_page(cur->pagedir, pt))
        exit(-1);

}

