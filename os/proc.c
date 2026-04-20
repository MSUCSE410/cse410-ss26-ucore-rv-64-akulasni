#include "proc.h"
#include "defs.h"
#include "loader.h"
#include "trap.h"
#include "vm.h"
#include "timer.h"

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

struct proc *curr_proc()
{
	return current_proc;
}

// initialize the proc table at boot time.
void proc_init(void)
{
	struct proc *p;
	for (p = pool; p < &pool[NPROC]; p++) {
		p->state = UNUSED;
		p->kstack = (uint64)kstack[p - pool];
		p->trapframe = (struct trapframe *)trapframe[p - pool];

		// Chapter 4 merge:
		// reset syscall/time tracking fields for every process slot
		memset(p->syscall_times, 0, sizeof(p->syscall_times));
		p->time = 0;
		p->start_msec = 0;
		p->started = 0;

		// Chapter 5:
		// initialize stride-scheduling fields
		// priority starts at 16 per project spec
		// stride starts at 0 per project spec
		// pass = BIG_STRIDE / priority, which is how much the
		// process's stride increases after it gets CPU time
		p->priority = 16;
		p->stride = 0;
		p->pass = BIG_STRIDE / p->priority;
	}

	idle.kstack = (uint64)boot_stack_top;
	idle.pid = 0;
	current_proc = &idle;
}

int allocpid()
{
	static int PID = 1;
	return PID++;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel.
// If there are no free procs, or a memory allocation fails, return 0.
struct proc *allocproc(void)
{
	struct proc *p;
	for (p = pool; p < &pool[NPROC]; p++) {
		if (p->state == UNUSED) {
			goto found;
		}
	}
	return 0;

found:
	p->pid = allocpid();
	p->state = USED;

	// Create a new user page table for this process.
	p->pagetable = uvmcreate((uint64)p->trapframe);
	if (p->pagetable == 0) {
		p->state = UNUSED;
		return 0;
	}

	p->ustack = 0;
	p->max_page = 0;
	p->parent = NULL;
	p->exit_code = 0;

	memset(&p->context, 0, sizeof(p->context));
	memset((void *)p->kstack, 0, KSTACK_SIZE);
	memset((void *)p->trapframe, 0, TRAP_PAGE_SIZE);

	// Chapter 4 merge:
	// initialize tracking fields for a newly allocated process
	memset(p->syscall_times, 0, sizeof(p->syscall_times));
	p->time = 0;
	p->start_msec = 0;
	p->started = 0;

	// Chapter 5:
	// every new process starts with the default priority and stride values
	p->priority = 16;
	p->stride = 0;
	p->pass = BIG_STRIDE / p->priority;

	// Start execution by returning through usertrapret.
	p->context.ra = (uint64)usertrapret;
	p->context.sp = p->kstack + KSTACK_SIZE;
	return p;
}

// Scheduler never returns.
// Chapter 5 change:
// We replaced the old queue-based scheduler with stride scheduling.
//
// Old approach:
//   - push RUNNABLE processes into a queue
//   - pop the next process from the queue
//
// New approach:
//   - scan the whole process table
//   - choose the RUNNABLE process with the smallest stride
//   - run that process
//   - after it gives up the CPU, add pass to its stride
//
// This makes CPU time proportional to priority because:
//   pass = BIG_STRIDE / priority
// so a larger priority means a smaller pass increment,
// which lets that process run more often over time.
void scheduler(void)
{
	struct proc *p;
	struct proc *best;

	for (;;) {
		best = 0;

		// Find the RUNNABLE process with the smallest stride.
		for (p = pool; p < &pool[NPROC]; p++) {
			if (p->state != RUNNABLE)
				continue;

			if (best == 0 || p->stride < best->stride)
				best = p;
		}

		// If nothing can run, all apps are over.
		if (best == 0) {
			panic("all app are over!\n");
		}

		tracef("switch to proc %d", best - pool);

		// Run the selected process.
		best->state = RUNNING;
		current_proc = best;
		swtch(&idle.context, &best->context);

		// Chapter 5:
		// when the process returns to the scheduler and is still runnable,
		// increase its stride by its pass value
		// this is the key step of stride scheduling
		if (best->state == RUNNABLE) {
			best->stride += best->pass;
		}
	}
}

// Switch to scheduler.
void sched(void)
{
	struct proc *p = curr_proc();
	if (p->state == RUNNING)
		panic("sched running");
	swtch(&p->context, &idle.context);
}

// Give up the CPU for one scheduling round.
void yield(void)
{
	// Chapter 5 change:
	// under stride scheduling we no longer push the process into a queue.
	// We only mark it RUNNABLE, and the scheduler will pick the next
	// process by comparing strides.
	current_proc->state = RUNNABLE;
	sched();
}

// Free a process's page table, and free the
// physical memory it refers to.
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
	p->state = UNUSED;
}

int fork()
{
	struct proc *np;
	struct proc *p = curr_proc();

	if ((np = allocproc()) == 0) {
		panic("allocproc\n");
	}

	// Copy user memory from parent to child.
	if (uvmcopy(p->pagetable, np->pagetable, p->max_page) < 0) {
		panic("uvmcopy\n");
	}

	np->max_page = p->max_page;

	// Copy saved user registers.
	*(np->trapframe) = *(p->trapframe);

	// Child sees return value 0 from fork.
	np->trapframe->a0 = 0;
	np->parent = p;

	// Chapter 5:
	// child starts with default stride-scheduler values
	np->priority = 16;
	np->stride = 0;
	np->pass = BIG_STRIDE / np->priority;

	// Mark child runnable.
	// Old queue-based code used add_task(np), but that was removed.
	np->state = RUNNABLE;
	return np->pid;
}

int exec(char *name)
{
	int id = get_id_by_name(name);
	if (id < 0)
		return -1;

	struct proc *p = curr_proc();

	// Remove the old user memory and load the new program.
	uvmunmap(p->pagetable, 0, p->max_page, 1);
	p->max_page = 0;
	loader(id, p);
	return 0;
}

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
					np->state = UNUSED;
					pid = np->pid;
					*code = np->exit_code;
					return pid;
				}
			}
		}

		if (!havekids) {
			return -1;
		}

		// Parent yields while waiting for a child to exit.
		// Under stride scheduling we do not enqueue it manually.
		p->state = RUNNABLE;
		sched();
	}
}

// Exit the current process.
void exit(int code)
{
	struct proc *p = curr_proc();
	p->exit_code = code;
	debugf("proc %d exit with %d\n", p->pid, code);

	freeproc(p);

	if (p->parent != NULL) {
		// Parent can collect this child through wait().
		p->state = ZOMBIE;
	}

	// Reparent children to NULL if their parent exits.
	struct proc *np;
	for (np = pool; np < &pool[NPROC]; np++) {
		if (np->parent == p) {
			np->parent = NULL;
		}
	}

	sched();
}