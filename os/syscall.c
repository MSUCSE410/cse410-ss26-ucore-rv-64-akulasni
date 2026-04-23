#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "proc.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"

uint64 console_write(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	tracef("write size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return len;
}

uint64 console_read(uint64 va, uint64 len)
{
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	tracef("read size = %d", len);
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
}

uint64 sys_write(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;

	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}

	switch (f->type) {
	case FD_STDIO:
		return console_write(va, len);
	case FD_INODE:
		return inodewrite(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
}

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;

	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d\n", fd);
		return -1;
	}

	switch (f->type) {
	case FD_STDIO:
		return console_read(va, len);
	case FD_INODE:
		return inoderead(f, va, len);
	default:
		panic("unknown file type %d\n", f->type);
	}
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

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();

	uint64 pa = useraddr(p->pagetable, val);
	if (pa == 0)
		return -1;

	uint64 cycle = get_cycle();
	uint64 now_msec = cycle * 1000 / CPU_FREQ;

	if (!p->started) {
		p->start_msec = now_msec;
		p->started = 1;
	}

	TimeVal *t = (TimeVal *)pa;
	t->sec = cycle / CPU_FREQ;
	t->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
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
	debugf("fork!");
	return fork();
}

static inline uint64 fetchaddr(pagetable_t pagetable, uint64 va)
{
	uint64 *addr = (uint64 *)useraddr(pagetable, va);
	if ((uint64)addr == 0)
		return 0;
	return *addr;
}

uint64 sys_exec(uint64 path, uint64 uargv)
{
	struct proc *p = curr_proc();
	char name[MAX_STR_LEN];
	if (copyinstr(p->pagetable, name, path, MAX_STR_LEN) < 0)
		return -1;

	uint64 arg;
	static char strpool[MAX_ARG_NUM][MAX_STR_LEN];
	char *argv[MAX_ARG_NUM];
	int i;

	for (i = 0; uargv && (arg = fetchaddr(p->pagetable, uargv));
	     uargv += sizeof(char *), i++) {
		if (i >= MAX_ARG_NUM - 1)
			return -1;
		if (copyinstr(p->pagetable, strpool[i], arg, MAX_STR_LEN) < 0)
			return -1;
		argv[i] = strpool[i];
	}
	argv[i] = NULL;

	return exec(name, argv);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	if ((uint64)code == 0)
		return -1;
	return wait(pid, code);
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

uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
	struct proc *np;
	struct inode *ip;
	char name[200];

	if (copyinstr(p->pagetable, name, va, sizeof(name)) < 0)
		return -1;

	if ((ip = namei(name)) == 0)
		return -1;

	np = allocproc();
	if (np == 0) {
		iput(ip);
		return -1;
	}

	if (init_stdio(np) < 0) {
		iput(ip);
		return -1;
	}

	np->parent = p;
	np->exit_code = 0;
	np->priority = 16;
	np->stride = 0;
	np->pass = BIG_STRIDE / np->priority;

	bin_loader(ip, np);
	iput(ip);

	np->state = RUNNABLE;
	return np->pid;
}

uint64 sys_set_priority(long long prio)
{
	struct proc *p = curr_proc();

	if (prio < 2)
		return -1;

	p->priority = prio;
	p->pass = BIG_STRIDE / p->priority;
	return prio;
}

uint64 sys_openat(uint64 va, uint64 omode, uint64 _flags)
{
	struct proc *p = curr_proc();
	char path[200];
	if (copyinstr(p->pagetable, path, va, 200) < 0)
		return -1;
	return fileopen(path, omode);
}

uint64 sys_close(int fd)
{
	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;

	struct proc *p = curr_proc();
	struct file *f = p->files[fd];
	if (f == NULL) {
		errorf("invalid fd %d", fd);
		return -1;
	}

	fileclose(f);
	p->files[fd] = 0;
	return 0;
}

/*
sys_fstat:
Returns metadata about a file given its file descriptor.

Inputs:
- fd: file descriptor
- st_addr: user virtual address where struct stat should be written

Steps:
1. Validate fd
2. Get file from process file table
3. Extract inode info using stati()
4. Copy result back to user memory
*/
int sys_fstat(int fd, uint64 st_addr)
{
	struct proc *p = curr_proc(); 
	// get current process (needed for fd table + pagetable)

	if (fd < 0 || fd >= FD_BUFFER_SIZE)
		return -1;
	// ensure fd is within valid range

	struct file *f = p->files[fd];
	// get file object from process file descriptor table

	if (f == NULL || f->type != FD_INODE)
		return -1;
	// ensure file exists and is a regular file (not stdio)

	struct stat st;
	// kernel-space struct to hold file metadata

	stati(f->ip, &st);
	// PROJECT 4:
	// fill stat struct using inode fields (size, nlink, type)

	if (copyout(p->pagetable, st_addr, (char *)&st, sizeof(st)) < 0)
		return -1;
	// copy stat struct from kernel → user memory

	return 0;
}

/*
sys_linkat:
Creates a HARD LINK (new file name pointing to the same inode).

Inputs:
- oldpath: existing file
- newpath: new name to point to same inode

Steps:
1. Copy both paths from user space
2. Lookup original file inode
3. Ensure new name does not exist
4. Add directory entry pointing to same inode
5. Increment inode link count
*/
int sys_linkat(int olddirfd, uint64 oldpath_va, int newdirfd,
	       uint64 newpath_va, uint64 flags)
{
	(void)olddirfd;
	(void)newdirfd;
	(void)flags;
	// unused arguments in this simplified implementation

	struct proc *p = curr_proc();
	// current process (needed for memory access)

	char oldpath[100], newpath[100];
	// buffers for file paths

	if (copyinstr(p->pagetable, oldpath, oldpath_va, 100) < 0)
		return -1;
	// copy source path from user → kernel

	if (copyinstr(p->pagetable, newpath, newpath_va, 100) < 0)
		return -1;
	// copy destination path from user → kernel

	struct inode *ip = namei(oldpath);
	// find inode of existing file

	if (ip == NULL)
		return -1;
	// fail if source file does not exist

	ivalid(ip);
	// ensure inode data is loaded

	if (ip->type == T_DIR) {
		iput(ip);
		return -1;
	}
	// do not allow linking directories

	struct inode *dp = root_dir();
	// get root directory inode

	ivalid(dp);
	// ensure directory inode is loaded

	struct inode *exist = dirlookup(dp, newpath, 0);
	// check if new path already exists

	if (exist != NULL) {
		iput(exist);
		iput(dp);
		iput(ip);
		return -1;
	}
	// fail if destination already exists

	if (dirlink(dp, newpath, ip->inum) < 0) {
		iput(dp);
		iput(ip);
		return -1;
	}
	// PROJECT 4:
	// create new directory entry → newpath points to same inode

	iupdate(dp);
	// write updated directory to disk

	ip->nlink++;
	// PROJECT 4:
	// increment link count (one more reference to inode)

	iupdate(ip);
	// persist updated link count

	iput(dp);
	iput(ip);
	// release references

	return 0;
}

/*
sys_unlinkat:
Removes a file (deletes a directory entry).

Inputs:
- name: file to remove

Steps:
1. Copy file name from user space
2. Find inode using directory lookup
3. Remove directory entry
4. Decrement link count
5. File is deleted when nlink reaches 0
*/
int sys_unlinkat(int dirfd, uint64 name_va, uint64 flags)
{
	(void)dirfd;
	(void)flags;
	// unused parameters in simplified version

	struct proc *p = curr_proc();
	// current process

	char name[100];
	// buffer for file name

	if (copyinstr(p->pagetable, name, name_va, 100) < 0)
		return -1;
	// copy file name from user → kernel

	struct inode *dp = root_dir();
	// get root directory

	ivalid(dp);
	// ensure directory is valid

	struct inode *ip = dirlookup(dp, name, 0);
	// find inode of file

	if (ip == NULL) {
		iput(dp);
		return -1;
	}
	// fail if file does not exist

	ivalid(ip);
	// load inode data

	if (ip->type == T_DIR) {
		iput(dp);
		iput(ip);
		return -1;
	}
	// do not allow removing directories

	if (dirunlink(dp, name) < 0) {
		iput(dp);
		iput(ip);
		return -1;
	}
	// PROJECT 4:
	// remove directory entry (name → inode mapping)

	iupdate(dp);
	// write updated directory to disk

	ip->nlink--;
	// PROJECT 4:
	// decrement link count (one less reference)

	iupdate(ip);
	// persist updated inode

	iput(dp);
	iput(ip);
	// release references

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
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_openat:
		ret = sys_openat(args[0], args[1], args[2]);
		break;
	case SYS_close:
		ret = sys_close(args[0]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
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
		ret = sys_exec(args[0], args[1]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
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
	case SYS_fstat:
		ret = sys_fstat(args[0], args[1]);
		break;
	case SYS_linkat:
		ret = sys_linkat(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_unlinkat:
		ret = sys_unlinkat(args[0], args[1], args[2]);
		break;
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