#include "proc.h"
#include "defs.h"
#include "loader.h"
#include "trap.h"
#include "vm.h"

struct proc pool[NPROC];
__attribute__((aligned(16))) char kstack[NPROC][PAGE_SIZE];
__attribute__((aligned(4096))) char trapframe[NPROC][TRAP_PAGE_SIZE];

extern char boot_stack_top[];
struct proc *current_proc;
struct proc idle;

int threadid()
{
	return curr_proc()->pid;
}

int cpuid()
{
	return 0;
}

struct proc *curr_proc()
{
	return current_proc;
}

// initialize the proc table at boot time.
void proc_init()
{
	struct proc *p;
	for (p = pool; p < &pool[NPROC]; p++) {
		p->state = UNUSED;

		// each process gets its own kernel stack
		p->kstack = (uint64)kstack[p - pool];

		// each process gets its own trapframe (user<->kernel register storage)
		p->trapframe = (struct trapframe *)trapframe[p - pool];

		// ---------------- PROJECT 3 ----------------
		memset(p->syscall_times, 0, sizeof(p->syscall_times));
		p->time = 0;
		p->start_msec = 0;
		p->started = 0;

		p->priority = 16;
		p->stride = 0;
		p->pass = BIG_STRIDE / p->priority;
		// ------------------------------------------
	}

	// idle process setup
	idle.kstack = (uint64)boot_stack_top;
	idle.pid = IDLE_PID;
	current_proc = &idle;
}

int allocpid()
{
	static int PID = 1;
	return PID++;
}

// Allocate a new process structure
struct proc *allocproc()
{
	struct proc *p;

	// find UNUSED slot
	for (p = pool; p < &pool[NPROC]; p++) {
		if (p->state == UNUSED) {
			goto found;
		}
	}
	return 0;

found:
	p->pid = allocpid();
	p->state = USED;
	p->ustack = 0;
	p->max_page = 0;
	p->parent = NULL;
	p->exit_code = 0;

	// create new page table for process
	p->pagetable = uvmcreate((uint64)p->trapframe);
	if (p->pagetable == 0) {
		p->state = UNUSED;
		return 0;
	}

	// reset context + memory
	memset(&p->context, 0, sizeof(p->context));
	memset((void *)p->kstack, 0, KSTACK_SIZE);
	memset((void *)p->trapframe, 0, TRAP_PAGE_SIZE);

	// ---------------- PROJECT 4 ----------------
	// initialize file descriptor table:
	// each process starts with no open files
	// (stdin/stdout/stderr will be added later)
	memset((void *)p->files, 0, sizeof(struct file *) * FD_BUFFER_SIZE);
	// ------------------------------------------

	// ---------------- PROJECT 3 ----------------
	memset(p->syscall_times, 0, sizeof(p->syscall_times));
	p->time = 0;
	p->start_msec = 0;
	p->started = 0;

	p->priority = 16;
	p->stride = 0;
	p->pass = BIG_STRIDE / p->priority;
	// ------------------------------------------

	// when scheduled, process starts at usertrapret
	p->context.ra = (uint64)usertrapret;
	p->context.sp = p->kstack + KSTACK_SIZE;

	return p;
}

// ---------------- PROJECT 4 ----------------
// initialize standard file descriptors:
// fd 0 -> stdin
// fd 1 -> stdout
// fd 2 -> stderr
int init_stdio(struct proc *p)
{
	for (int i = 0; i < 3; i++) {

		// safety: should not already be initialized
		if (p->files[i] != NULL) {
			return -1;
		}

		// create stdio file objects (handled in file.c)
		p->files[i] = stdio_init(i);
	}
	return 0;
}
// ------------------------------------------

// stride scheduler (Project 3)
void scheduler()
{
	struct proc *p;
	struct proc *best;

	for (;;) {
		best = 0;

		// pick process with smallest stride value
		for (p = pool; p < &pool[NPROC]; p++) {
			if (p->state != RUNNABLE)
				continue;

			if (best == 0 || p->stride < best->stride)
				best = p;
		}

		if (best == 0) {
			panic("all app are over!\n");
		}

		best->state = RUNNING;
		current_proc = best;

		// context switch
		swtch(&idle.context, &best->context);

		// update stride after running
		if (best->state == RUNNABLE) {
			best->stride += best->pass;
		}
	}
}

void sched()
{
	struct proc *p = curr_proc();
	if (p->state == RUNNING)
		panic("sched running");
	swtch(&p->context, &idle.context);
}

void yield()
{
	current_proc->state = RUNNABLE;
	sched();
}

// free process memory
void freepagetable(pagetable_t pagetable, uint64 max_page)
{
	uvmunmap(pagetable, TRAMPOLINE, 1, 0);
	uvmunmap(pagetable, TRAPFRAME, 1, 0);
	uvmfree(pagetable, max_page);
}

void freeproc(struct proc *p)
{
	if (p->pagetable)
		freepagetable(p->pagetable, p->max_page);

	p->pagetable = 0;

	// ---------------- PROJECT 4 ----------------
	// IMPORTANT:
	// close ALL open file descriptors when process exits
	// this prevents file leaks and ensures ref counts decrease
	for (int i = 0; i < FD_BUFFER_SIZE; i++) {
		if (p->files[i] != NULL) {
			fileclose(p->files[i]); // decrement ref count
			p->files[i] = NULL;
		}
	}
	// ------------------------------------------

	p->state = UNUSED;
}

int fork()
{
	struct proc *np;
	struct proc *p = curr_proc();
	int i;

	np = allocproc();
	if (np == 0) {
		panic("allocproc\n");
	}

	// copy memory
	if (uvmcopy(p->pagetable, np->pagetable, p->max_page) < 0) {
		panic("uvmcopy\n");
	}

	np->max_page = p->max_page;

	// ---------------- PROJECT 4 ----------------
	// duplicate file descriptor table:
	// parent and child SHARE same open file objects
	// increment ref count so file isn't freed early
	for (i = 0; i < FD_BUFFER_SIZE; i++) {
		if (p->files[i] != NULL) {
			p->files[i]->ref++;      // increase ref count
			np->files[i] = p->files[i]; // share pointer
		}
	}
	// ------------------------------------------

	// copy registers
	*(np->trapframe) = *(p->trapframe);

	// child returns 0 from fork
	np->trapframe->a0 = 0;

	np->parent = p;

	// scheduling fields
	np->priority = 16;
	np->stride = 0;
	np->pass = BIG_STRIDE / np->priority;

	np->state = RUNNABLE;
	return np->pid;
}

// ---------------- PROJECT 4 ----------------
// push argv onto user stack for exec
// builds:
// [argv strings][argv pointers array]
int push_argv(struct proc *p, char **argv)
{
	uint64 argc, ustack[MAX_ARG_NUM + 1];

	uint64 sp = p->ustack + USTACK_SIZE;
	uint64 spb = p->ustack;

	for (argc = 0; argv[argc]; argc++) {

		if (argc >= MAX_ARG_NUM)
			panic("too many args");

		// copy string onto stack
		sp -= strlen(argv[argc]) + 1;

		// align stack to 16 bytes
		sp -= sp % 16;

		if (sp < spb)
			panic("push_argv overflow");

		// copy string into user memory
		if (copyout(p->pagetable, sp, argv[argc],
			    strlen(argv[argc]) + 1) < 0)
			panic("push_argv copyout failed");

		ustack[argc] = sp;
	}

	ustack[argc] = 0;

	// push argv pointer array
	sp -= (argc + 1) * sizeof(uint64);
	sp -= sp % 16;

	if (copyout(p->pagetable, sp, (char *)ustack,
		    (argc + 1) * sizeof(uint64)) < 0)
		panic("push_argv argv copyout failed");

	// set registers
	p->trapframe->a1 = sp; // argv
	p->trapframe->sp = sp; // stack pointer

	return argc;
}
// ------------------------------------------

// ---------------- PROJECT 4 ----------------
// exec loads program from filesystem instead of memory array
int exec(char *path, char **argv)
{
	struct inode *ip;
	struct proc *p = curr_proc();

	// lookup file in filesystem
	if ((ip = namei(path)) == 0) {
		return -1;
	}

	// clear old memory
	uvmunmap(p->pagetable, 0, p->max_page, 1);
	p->max_page = 0;

	// load program from inode
	bin_loader(ip, p);

	// release inode
	iput(ip);

	// push argv onto new stack
	return push_argv(p, argv);
}
// ------------------------------------------

int wait(int pid, int *code)
{
	struct proc *np;
	int havekids;
	struct proc *p = curr_proc();

	for (;;) {
		havekids = 0;

		for (np = pool; np < &pool[NPROC]; np++) {
			if (np->state != UNUSED && np->parent == p &&
			    (pid <= 0 || np->pid == pid)) {

				havekids = 1;

				if (np->state == ZOMBIE) {
					pid = np->pid;
					*code = np->exit_code;
					np->state = UNUSED;
					return pid;
				}
			}
		}

		if (!havekids)
			return -1;

		p->state = RUNNABLE;
		sched();
	}
}

void exit(int code)
{
	struct proc *p = curr_proc();
	p->exit_code = code;

	freeproc(p);

	if (p->parent != NULL) {
		p->state = ZOMBIE;
	}

	struct proc *np;
	for (np = pool; np < &pool[NPROC]; np++) {
		if (np->parent == p) {
			np->parent = NULL;
		}
	}

	sched();
}

// ---------------- PROJECT 4 ----------------
// allocate a free file descriptor slot in process table
int fdalloc(struct file *f)
{
	struct proc *p = curr_proc();

	for (int i = 0; i < FD_BUFFER_SIZE; ++i) {
		if (p->files[i] == NULL) {
			p->files[i] = f;
			return i; // return fd index
		}
	}
	return -1; // no free slot
}
// ------------------------------------------