#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "proc.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

// Chapter 4 merge:
// updated gettimeofday so it safely writes to user memory using useraddr()
// and also initializes timing info for the process the first time it runs.
uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	struct proc *p = curr_proc();

	uint64 pa = useraddr(p->pagetable, (uint64)val);
	if (pa == 0)
		return -1;

	uint64 cycle = get_cycle();
	uint64 now_msec = cycle * 1000 / CPU_FREQ;

	if (!p->started) {
		p->start_msec = now_msec;
		p->started = 1;
	}

	TimeVal *tv = (TimeVal *)pa;
	tv->sec = cycle / CPU_FREQ;
	tv->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!\n");
	return fork();
}

uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

// Chapter 4 merge:
// returns process status, runtime, and syscall counters back to user space.
uint64 sys_task_info(TaskInfo *info)
{
	struct proc *p = curr_proc();

	uint64 pa = useraddr(p->pagetable, (uint64)info);
	if (pa == 0)
		return -1;

	TaskInfo *dst = (TaskInfo *)pa;

	switch (p->state) {
	case UNUSED:
		dst->status = UnInit;
		break;
	case RUNNABLE:
		dst->status = Ready;
		break;
	case RUNNING:
		dst->status = Running;
		break;
	case ZOMBIE:
		dst->status = Exited;
		break;
	default:
		dst->status = Ready;
		break;
	}

	uint64 now_msec = (get_cycle() * 1000) / CPU_FREQ;
	if (p->started) {
		p->time = (int)(now_msec - p->start_msec);
	} else {
		p->time = 0;
	}
	dst->time = p->time;

	for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
		dst->syscall_times[i] = p->syscall_times[i];
	}

	return 0;
}

// Chapter 4 merge:
// maps a new user memory range with requested permissions.
uint64 sys_mmap(uint64 start, uint64 len, uint64 port, uint64 flag, uint64 fd)
{
	(void)flag;
	(void)fd;

	struct proc *p = curr_proc();

	if (len == 0)
		return 0;
	if (len > (1UL << 30))
		return -1;
	if ((port & ~0x7UL) != 0)
		return -1;
	if ((port & 0x7UL) == 0)
		return -1;
	if (start % PGSIZE != 0)
		return -1;
	if (start >= MAXVA)
		return -1;
	if (start + len < start)
		return -1;
	if (start + len > MAXVA)
		return -1;

	uint64 begin = start;
	uint64 end = PGROUNDUP(start + len);

	for (uint64 va = begin; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0)
			return -1;
	}

	int perm = PTE_U;
	if (port & 0x1)
		perm |= PTE_R;
	if (port & 0x2)
		perm |= PTE_W;
	if (port & 0x4)
		perm |= PTE_X;

	uint64 mapped = 0;
	for (uint64 va = begin; va < end; va += PGSIZE) {
		void *mem = kalloc();
		if (mem == 0) {
			uvmunmap(p->pagetable, begin, mapped / PGSIZE, 1);
			return -1;
		}

		memset(mem, 0, PGSIZE);

		if (mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) != 0) {
			kfree(mem);
			uvmunmap(p->pagetable, begin, mapped / PGSIZE, 1);
			return -1;
		}

		mapped += PGSIZE;
	}

	return 0;
}

// Chapter 4 merge:
// unmaps a previously mapped user memory range.
uint64 sys_munmap(uint64 start, uint64 len)
{
	struct proc *p = curr_proc();

	if (len == 0)
		return 0;
	if (start % PGSIZE != 0)
		return -1;
	if (start >= MAXVA)
		return -1;
	if (start + len < start)
		return -1;
	if (start + len > MAXVA)
		return -1;

	uint64 begin = start;
	uint64 end = PGROUNDUP(start + len);

	for (uint64 va = begin; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0)
			return -1;
	}

	uvmunmap(p->pagetable, begin, (end - begin) / PGSIZE, 1);
	return 0;
}

// Chapter 5:
// spawn is basically fork + exec in one syscall.
// It creates a new child process, loads the requested program into it,
// marks the child RUNNABLE, and returns the child's pid.
// Return -1 on invalid filename or allocation failure.
uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
	struct proc *np;
	char name[200];

	// Copy program name from user space into kernel buffer.
	if (copyinstr(p->pagetable, name, va, sizeof(name)) < 0)
		return -1;

	// Make sure the target program exists.
	int id = get_id_by_name(name);
	if (id < 0)
		return -1;

	// Allocate a new child process.
	np = allocproc();
	if (np == 0)
		return -1;

	np->parent = p;
	np->exit_code = 0;

	// Chapter 5:
	// spawned child starts with default stride scheduling values.
	np->priority = 16;
	np->stride = 0;
	np->pass = BIG_STRIDE / np->priority;

	// Load the selected user program into the child.
	loader(id, np);

	// Make the child eligible to run.
	np->state = RUNNABLE;

	return np->pid;
}

// Chapter 5:
// set_priority changes the calling process's priority.
// Valid priorities are >= 2.
// On success return the new priority; otherwise return -1.
//
// Also recompute pass because stride scheduling uses:
//   pass = BIG_STRIDE / priority
uint64 sys_set_priority(long long prio)
{
	struct proc *p = curr_proc();

	if (prio < 2)
		return -1;

	p->priority = prio;
	p->pass = BIG_STRIDE / p->priority;
	return prio;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);

	// Chapter 4 merge:
	// count how many times each syscall is used by this process.
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone:
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;

	// Chapter 5:
	// handle set_priority syscall
	case SYS_setpriority:
		ret = sys_set_priority((long long)args[0]);
		break;

	case SYS_taskinfo:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;

	// Chapter 5:
	// handle spawn syscall
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;

	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}