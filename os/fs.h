#ifndef __FS_H__
#define __FS_H__

#include "types.h"
// On-disk file system format.
// Both the kernel and user programs use this header file.

#define NFILE 100 // open files per system
#define NINODE 50 // maximum number of active i-nodes
#define NDEV 10 // maximum major device number
#define ROOTDEV 1 // device number of file system root disk
#define MAXOPBLOCKS 10 // max # of blocks any FS op writes
#define NBUF (MAXOPBLOCKS * 3) // size of disk block cache
#define FSSIZE 1000 // size of file system in blocks
#define MAXPATH 128 // maximum file path name

#define ROOTINO 1 // root i-number
#define BSIZE 1024 // block size

struct superblock {
	uint magic;
	uint size;
	uint nblocks;
	uint ninodes;
	uint inodestart;
	uint bmapstart;
};

#define FSMAGIC 0x10203040

#define NDIRECT 12
#define NINDIRECT (BSIZE / sizeof(uint))
#define MAXFILE (NDIRECT + NINDIRECT)

#define T_DIR 1
#define T_FILE 2

#define DIR  0x040000
#define FILE 0x100000

struct dinode {
	short type;
	short nlink;
	short pad[2];
	uint size;
	uint addrs[NDIRECT + 1];
};

#define IPB (BSIZE / sizeof(struct dinode))
#define IBLOCK(i, sb) ((i) / IPB + sb.inodestart)

#define BPB (BSIZE * 8)
#define BBLOCK(b, sb) ((b) / BPB + sb.bmapstart)

#define DIRSIZ 14

struct dirent {
	ushort inum;
	char name[DIRSIZ];
};

struct stat {
	uint64 dev;
	uint64 ino;
	uint32 mode;
	uint32 nlink;
	uint64 pad[7];
};

struct inode;

void fsinit();
int dirlink(struct inode *, char *, uint);
int dirunlink(struct inode *, char *);
struct inode *dirlookup(struct inode *, char *, uint *);
struct inode *ialloc(uint, short);
struct inode *idup(struct inode *);
void iinit();
void ivalid(struct inode *);
void iput(struct inode *);
void iunlock(struct inode *);
void iunlockput(struct inode *);
void iupdate(struct inode *);
void stati(struct inode *, struct stat *);
struct inode *namei(char *);
struct inode *root_dir();
int readi(struct inode *, int, uint64, uint, uint);
int writei(struct inode *, int, uint64, uint, uint);
void itrunc(struct inode *);
int dirls(struct inode *);

#endif