#include "vm.h"
#include "defs.h"
#include "plic.h"   // Project 4
#include "riscv.h"

pagetable_t kernel_pagetable;

extern char e_text[];
extern char trampoline[];

// Make a direct-map page table for the kernel.
pagetable_t kvmmake()
{
	pagetable_t kpgtbl;
	kpgtbl = (pagetable_t)kalloc();
	memset(kpgtbl, 0, PGSIZE);

	// Project 4: device mappings
	kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);
	kvmmap(kpgtbl, PLIC, PLIC, 0x400000, PTE_R | PTE_W);

	// kernel text
	kvmmap(kpgtbl, KERNBASE, KERNBASE,
	       (uint64)e_text - KERNBASE, PTE_R | PTE_X);

	// kernel data
	kvmmap(kpgtbl, (uint64)e_text, (uint64)e_text,
	       PHYSTOP - (uint64)e_text, PTE_R | PTE_W);

	kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline,
	       PGSIZE, PTE_R | PTE_X);

	return kpgtbl;
}

void kvm_init()
{
	kernel_pagetable = kvmmake();
	w_satp(MAKE_SATP(kernel_pagetable));
	sfence_vma();
	infof("enable paging at %p", r_satp());
}

pte_t *walk(pagetable_t pagetable, uint64 va, int alloc)
{
	if (va >= MAXVA)
		panic("walk");

	for (int level = 2; level > 0; level--) {
		pte_t *pte = &pagetable[PX(level, va)];
		if (*pte & PTE_V) {
			pagetable = (pagetable_t)PTE2PA(*pte);
		} else {
			if (!alloc || (pagetable = (pde_t *)kalloc()) == 0)
				return 0;
			memset(pagetable, 0, PGSIZE);
			*pte = PA2PTE(pagetable) | PTE_V;
		}
	}
	return &pagetable[PX(0, va)];
}

uint64 walkaddr(pagetable_t pagetable, uint64 va)
{
	if (va >= MAXVA)
		return 0;

	pte_t *pte = walk(pagetable, va, 0);
	if (!pte || !(*pte & PTE_V) || !(*pte & PTE_U))
		return 0;

	return PTE2PA(*pte);
}

uint64 useraddr(pagetable_t pagetable, uint64 va)
{
	uint64 page = walkaddr(pagetable, va);
	if (page == 0)
		return 0;
	return page | (va & 0xFFFULL);
}

void kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa,
            uint64 sz, int perm)
{
	if (mappages(kpgtbl, va, sz, pa, perm) != 0)
		panic("kvmmap");
}

int mappages(pagetable_t pagetable, uint64 va,
             uint64 size, uint64 pa, int perm)
{
	uint64 a = PGROUNDDOWN(va);
	uint64 last = PGROUNDDOWN(va + size - 1);

	for (;;) {
		pte_t *pte = walk(pagetable, a, 1);
		if (!pte) return -1;
		if (*pte & PTE_V) return -1;

		*pte = PA2PTE(pa) | perm | PTE_V;

		if (a == last) break;
		a += PGSIZE;
		pa += PGSIZE;
	}
	return 0;
}

void uvmunmap(pagetable_t pagetable, uint64 va,
              uint64 npages, int do_free)
{
	if (va % PGSIZE)
		panic("uvmunmap");

	for (uint64 a = va; a < va + npages * PGSIZE; a += PGSIZE) {
		pte_t *pte = walk(pagetable, a, 0);
		if (!pte) continue;

		if (*pte & PTE_V) {
			if (PTE_FLAGS(*pte) == PTE_V)
				panic("uvmunmap: not leaf");

			if (do_free)
				kfree((void *)PTE2PA(*pte));
		}
		*pte = 0;
	}
}

pagetable_t uvmcreate(uint64 trapframe)
{
	pagetable_t pt = (pagetable_t)kalloc();
	if (!pt) return 0;

	memset(pt, 0, PGSIZE);

	mappages(pt, TRAMPOLINE, PGSIZE,
	         (uint64)trampoline, PTE_R | PTE_X);

	mappages(pt, TRAPFRAME, PGSIZE,
	         trapframe, PTE_R | PTE_W);

	return pt;
}

// Project 3 FIX: no panic on leaf
void freewalk(pagetable_t pagetable)
{
	for (int i = 0; i < 512; i++) {
		pte_t pte = pagetable[i];

		if ((pte & PTE_V) &&
		    (pte & (PTE_R | PTE_W | PTE_X)) == 0) {
			freewalk((pagetable_t)PTE2PA(pte));
			pagetable[i] = 0;
		}
	}
	kfree((void *)pagetable);
}

void uvmfree(pagetable_t pagetable, uint64 max_page)
{
	if (max_page > 0)
		uvmunmap(pagetable, 0, max_page, 1);
	freewalk(pagetable);
}

int uvmcopy(pagetable_t old, pagetable_t new, uint64 max_page)
{
	for (uint64 i = 0; i < max_page * PGSIZE; i += PGSIZE) {
		pte_t *pte = walk(old, i, 0);
		if (!pte || !(*pte & PTE_V)) continue;

		char *mem = kalloc();
		if (!mem) goto err;

		memmove(mem, (void *)PTE2PA(*pte), PGSIZE);

		if (mappages(new, i, PGSIZE, (uint64)mem,
		             PTE_FLAGS(*pte)) != 0) {
			kfree(mem);
			goto err;
		}
	}
	return 0;

err:
	uvmunmap(new, 0, max_page, 1);
	return -1;
}

int copyout(pagetable_t pt, uint64 dst, char *src, uint64 len)
{
	while (len > 0) {
		uint64 va0 = PGROUNDDOWN(dst);
		uint64 pa0 = walkaddr(pt, va0);
		if (!pa0) return -1;

		uint64 n = PGSIZE - (dst - va0);
		if (n > len) n = len;

		memmove((void *)(pa0 + (dst - va0)), src, n);

		len -= n;
		src += n;
		dst = va0 + PGSIZE;
	}
	return 0;
}

int copyin(pagetable_t pt, char *dst, uint64 src, uint64 len)
{
	while (len > 0) {
		uint64 va0 = PGROUNDDOWN(src);
		uint64 pa0 = walkaddr(pt, va0);
		if (!pa0) return -1;

		uint64 n = PGSIZE - (src - va0);
		if (n > len) n = len;

		memmove(dst, (void *)(pa0 + (src - va0)), n);

		len -= n;
		dst += n;
		src = va0 + PGSIZE;
	}
	return 0;
}

int copyinstr(pagetable_t pt, char *dst, uint64 src, uint64 max)
{
	int got_null = 0, len = 0;

	while (!got_null && max > 0) {
		uint64 va0 = PGROUNDDOWN(src);
		uint64 pa0 = walkaddr(pt, va0);
		if (!pa0) return -1;

		uint64 n = PGSIZE - (src - va0);
		if (n > max) n = max;

		char *p = (char *)(pa0 + (src - va0));

		while (n-- > 0) {
			if (*p == '\0') {
				*dst = '\0';
				got_null = 1;
				break;
			}
			*dst++ = *p++;
			max--;
			len++;
		}

		src = va0 + PGSIZE;
	}
	return len;
}

// Project 4 helpers
int either_copyout(int user_dst, uint64 dst, char *src, uint64 len)
{
	if (user_dst)
		return copyout(curr_proc()->pagetable, dst, src, len);
	memmove((void *)dst, src, len);
	return 0;
}

int either_copyin(int user_src, uint64 src, char *dst, uint64 len)
{
	if (user_src)
		return copyin(curr_proc()->pagetable, dst, src, len);
	memmove(dst, (char *)src, len);
	return 0;
}