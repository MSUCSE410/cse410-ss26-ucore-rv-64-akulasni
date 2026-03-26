#ifndef PROC_H
#define PROC_H

#include "riscv.h"
#include "types.h"

#define NPROC (16)
#define MAX_SYSCALL_NUM 500

struct context {
	uint64 ra;
	uint64 sp;
	uint64 s0;
	uint64 s1;
	uint64 s2;
	uint64 s3;
	uint64 s4;
	uint64 s5;
	uint64 s6;
	uint64 s7;
	uint64 s8;
	uint64 s9;
	uint64 s10;
	uint64 s11;
};

enum procstate { UNUSED, USED, SLEEPING, RUNNABLE, RUNNING, ZOMBIE };
enum taskstatus { UnInit, Ready, Running, Exited };

typedef struct {
	enum taskstatus status;
	int syscall_times[MAX_SYSCALL_NUM];
	int time;
} TaskInfo;

struct proc {
	enum procstate state;
	int pid;
	pagetable_t pagetable;
	uint64 ustack;
	uint64 kstack;
	struct trapframe *trapframe;
	struct context context;
	uint64 max_page;

	unsigned int syscall_times[MAX_SYSCALL_NUM];
	int time;
	uint64 start_msec;
	int started;
};

struct proc *curr_proc();
void exit(int);
void proc_init();
void scheduler() __attribute__((noreturn));
void sched();
void yield();
struct proc *allocproc();
void swtch(struct context *, struct context *);

#endif // PROC_H