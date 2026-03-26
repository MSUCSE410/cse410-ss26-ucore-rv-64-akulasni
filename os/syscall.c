#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "proc.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
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

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

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

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);

	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
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
	case SYS_taskinfo:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}