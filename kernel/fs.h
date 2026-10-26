#ifndef _FS_H
#define _FS_H

// On-disk file system format.
// Both the kernel and user programs use this header file.

#define ROOTINO 1    // root i-number
#define BSIZE   1024 // block size

// Disk layout:
// [ boot block | super block | log | inode blocks |
//                                          free bit map | data blocks]
//
// mkfs computes the super block and builds an initial file system. The
// super block describes the disk layout:
struct superblock {
  uint magic;      // Must be FSMAGIC
  uint size;       // Size of file system image (blocks)
  uint nblocks;    // Number of data blocks
  uint ninodes;    // Number of inodes.
  uint nlog;       // Number of log blocks
  uint logstart;   // Block number of first log block
  uint inodestart; // Block number of first inode block
  uint bmapstart;  // Block number of first free map block
};

#define FSMAGIC 0x10203040

#define NDIRECT   11
#define NINDIRECT (BSIZE / sizeof(uint))
#define MAXFILE   (NDIRECT + NINDIRECT)
#define NLINK_MAX 32767 // nlink is a short; refuse links past its maximum

// On-disk inode structure
struct dinode {
  short type;              // File type
  short major;             // Major device number (T_DEVICE only)
  short minor;             // Minor device number (T_DEVICE only)
  short nlink;             // Number of links to inode in file system
  short gid;               // Group ID for budget accounting
  ushort pad1;             // Explicit padding to keep struct 64 bytes
  uint size;               // Size of file (bytes)
  // Direct blocks in addrs[0..NDIRECT-1]; the indirect block lives in
  // addrs[NDIRECT], so the array needs NDIRECT+1 entries.
  uint addrs[NDIRECT + 1];
};

// Inodes per block.
#define IPB (BSIZE / sizeof(struct dinode))

// Block containing inode i
#define IBLOCK(i, sb) ((i) / IPB + sb.inodestart)

// Bitmap bits per block
#define BPB (BSIZE * 8)

// Block of free map containing bit for block b
#define BBLOCK(b, sb) ((b) / BPB + sb.bmapstart)

// Directory is a file containing a sequence of dirent structures.
// 30 (not the upstream 14) so that names like "test_budget_suite" fit;
// sizeof(struct dirent) is then 32, which still divides BSIZE evenly.
#define DIRSIZ 30

// The name field may have DIRSIZ characters and not end in a NUL
// character.
struct dirent {
  ushort inum;
  char name[DIRSIZ] __attribute__((nonstring));
};

#endif
