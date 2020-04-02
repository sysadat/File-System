#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define SIG_LENGTH 8
#define ROOT_PADDING_SIZE 10
#define PADDING_SIZE 4079
#define FAT_EOC 0xFFFF

struct __attribute__((__packed__)) SuperBlock {
	uint8_t signature[SIG_LENGTH];
	uint16_t total_blocks;
	uint16_t root_blocki;
	uint16_t data_starti;
	uint16_t num_blocks;
	uint8_t FAT_blocks;
	uint8_t padding[PADDING_SIZE];
};

struct __attribute__((__packed__)) Root {
	char filename[FS_FILENAME_LEN];
	uint32_t fsize;
	uint16_t findex;
	uint8_t padding[ROOT_PADDING_SIZE];
};

struct __attribute__((__packed__)) FAT {
	/* FAT is an array of 16 bit entries */
	uint16_t entries;
};

struct File {
	uint32_t offset;
	int fd;
	int root_i;
};

struct FileSystem {
	char *opened_disks;
	int files_open;
	struct File open_files[FS_OPEN_MAX_COUNT];
	struct Root *root_dir;
	struct FAT *fat;
	struct SuperBlock *super;
};

static struct FAT *fat;
static struct Root *root_dir;
static struct SuperBlock *super;
static struct File open_files[FS_OPEN_MAX_COUNT];
static int files_open = 0;
static int initialized = 0;

static int make_super(void)
{
	super = malloc(sizeof(struct SuperBlock));
	memset(super, 0, sizeof(struct SuperBlock));
	if (block_read(0, super) == -1)
		return -1;
	/* Signature must be equal to 'ECS150FS' */
	if (memcmp(super->signature, "ECS150FS", 8))
		return -1;
	if (super->total_blocks != block_disk_count())
		return -1;
	return 0;
}

static int make_root(void)
{
	root_dir = malloc(FS_FILE_MAX_COUNT * sizeof(struct Root));
	if (root_dir == NULL)
		return -1;
	/* Read starting from the root block's index we got from previous
	 * step */
	return block_read(super->root_blocki, (void *)root_dir);
}

static int make_fat(void)
{
	uint16_t num_blocks = super->num_blocks;
	uint16_t malloc_sz = num_blocks > BLOCK_SIZE ? num_blocks :
		BLOCK_SIZE;
	fat = malloc(malloc_sz * sizeof(struct FAT));
	uint16_t offset = 0;
	for (int i = 0; i < super->FAT_blocks; i++) {
		uint16_t *tmp = malloc(BLOCK_SIZE * sizeof(uint16_t));
		memset(tmp, 0, BLOCK_SIZE * sizeof(uint16_t));
		if (block_read(i + 1, (void *)tmp) == -1)
			return -1;
		memcpy(fat + offset, tmp, BLOCK_SIZE);
		/* 16 bit per entries, 8 bit per block */
		int incr = (i + 1) / 2;
		offset = BLOCK_SIZE * incr;
		free(tmp);
	}
	return 0;
}

// Helper function to assit fs_open
static int open_helper(int root_i)
{
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
		if (open_files[i].fd == -1) {
			open_files[i].fd = i;
			open_files[i].offset = 0;
			open_files[i].root_i = root_i;
			files_open++;
			return open_files[i].fd;
		}
	}
	return -1;
}

static int fd_to_index(int fd)
{
	if (fd < 0 || fd > FS_OPEN_MAX_COUNT)
		return -1;
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++)
		if (open_files[i].fd == fd)
			return i;
	return -1;
}

int fs_mount(const char *diskname)
{
	if (block_disk_open(diskname) == -1)
		return -1;
	initialized = 1;
	files_open = 0;
	for (int i = 0 ; i < FS_OPEN_MAX_COUNT; i++)
		open_files[i].fd = -1;
	/* Layout is Super, FAT then Root */
	if (make_super() == -1)
		return -1;
	if (make_fat() == -1)
		return -1;
	if (make_root() == -1)
		return -1;
	return 0;
}

int fs_umount(void)
{
	if (initialized == 0)
		return -1;
	initialized = 0;
	free(super);
	free(fat);
	free(root_dir);
	return block_disk_close();
}

static uint16_t get_fat_free(void)
{
	uint16_t fat_free = 0;
	for (int i = 0; i < super->num_blocks; i++) {
		if (fat[i].entries == 0)
			fat_free++;
	}
	return fat_free;
}

static int get_empty_fat(void)
{
	for (int i = 0; i <= super->num_blocks; i++) {
		if (fat[i].entries == 0)
			return i;
	}
	return -1;
}

static uint16_t get_root_free(void)
{
	uint16_t root_free = 0;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] == 0)
			root_free++;
	}
	return root_free;
}

static int fat_write(void)
{
	uint16_t offset = 0;
	for (int i = 0; i < super->FAT_blocks; i++) {
		uint16_t *tmp = malloc(BLOCK_SIZE * sizeof(uint16_t));
		memset(tmp, 0, BLOCK_SIZE * sizeof(uint16_t));
		memcpy(tmp, fat + offset, BLOCK_SIZE);
		if (block_write(i + 1, (void *)tmp) == -1)
			return -1;
		int incr = (i + 1) / 2;
		offset = BLOCK_SIZE * incr;
		free(tmp);
	}
	return 0;
}

int fs_info(void)
{
	/* exit right away if filesystem is not initialized */
	if (!initialized)
		return -1;

	printf("FS Info:\n");
	printf("total_blk_count=%d\n", super->total_blocks);
	printf("fat_blk_count=%d\n", super->FAT_blocks);
	printf("rdir_blk=%d\n", super->root_blocki);
	printf("data_blk=%d\n", super->data_starti);
	printf("data_blk_count=%d\n", super->num_blocks);
	printf("fat_free_ratio=%d/%d\n", get_fat_free(), super->num_blocks);
	printf("rdir_free_ratio=%d/%d\n", get_root_free(), FS_FILE_MAX_COUNT);
	return 0;
}

static int is_exist(const char *filename)
{
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
		if (!strcmp(root_dir[i].filename, filename))
			return 1;
	return 0;
}

static int find_empty_root(void)
{
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].filename[0] == 0)
			return i;
	}
	return -1;
}

static int find_tar_root(const char *filename)
{
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
		if (!strcmp(root_dir[i].filename, filename))
			return i;
	return -1;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
	int empty_rooti = find_empty_root();
	size_t len = strlen(filename);
	if (empty_rooti == -1 || filename == NULL || is_exist(filename) || len
			>= FS_FILENAME_LEN)
		return -1;
	memcpy(root_dir[empty_rooti].filename, filename, len);
	/* Initially, size is 0 and pointer to first data block is FAT_EOC
	 * */
	int free_fat_i = get_empty_fat();
	root_dir[empty_rooti].fsize = 0;
	root_dir[empty_rooti].findex = free_fat_i;
	fat[free_fat_i].entries = FAT_EOC;
	return block_write(super->root_blocki, (void *)root_dir);
}

int fs_delete(const char *filename)
{
	if (filename == NULL)
		return -1;
	/* TODO: Phase 2 */
	size_t len = strlen(filename);
	int tar_rooti = find_tar_root(filename);
	if (tar_rooti == -1 || filename == NULL || len >= FS_FILENAME_LEN)
		return -1;
	root_dir[tar_rooti].filename[0] = 0;
	root_dir[tar_rooti].fsize = 0;
	int i = root_dir[tar_rooti].findex;
	while (i != FAT_EOC) {
		int next = fat[i].entries;
		fat[i].entries = 0;
		i = next;
	}
	if (fat_write() == -1)
		return -1;
	int ok = block_write(super->root_blocki, (void*)root_dir);
	return ok;
}

int fs_ls(void)
{
	printf("FS Ls:\n");
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		int is_exist = root_dir[i].filename[0] != 0;
		if (is_exist) {
			printf("file: %s", root_dir[i].filename);
			printf(", size: %d", root_dir[i].fsize);
			printf(", data_blk: %hu\n", root_dir[i].findex);
		}
	}
	return 0;
}


int fs_open(const char *filename)
{
	/* Check if filename is invalid, there is no file to open or if there
	 * are already FS_OPEN_MAX_COUNT files currently open */
	if (filename == NULL)
		return -1;
	if (!initialized || strlen(filename) > FS_FILENAME_LEN || !filename ||
			files_open >= FS_OPEN_MAX_COUNT) {
		return -1;
	}
	/* Check to see if file is in the root directory and call helper
	 * function, 'open_helper', if it is */
	int helper_caller = 0;
	int root_i = 0;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (!strcmp(root_dir[i].filename, filename)) {
			helper_caller = 1;
			root_i = i;
		}
	}

	if (helper_caller) {
		return open_helper(root_i);
	}

	return -1;
}

int fs_close(int fd)
{
	if (files_open == 0)
		return -1;
	// Check if file descriptor is out of bounds or not currently open
	int file_index = fd_to_index(fd);
	if (file_index == -1) {
		return -1;
	}
	if (fd < 0 || fd > FS_OPEN_MAX_COUNT || files_open
			> FS_OPEN_MAX_COUNT - 1 || open_files[file_index].fd ==
			-1) {
		return -1;
	}

	open_files[file_index].fd = -1;
	open_files[file_index].offset = 0;
	open_files[file_index].root_i = -1;
	files_open--;

	return 0;
}

int fs_stat(int fd)
{
	// Check if file descriptor is out of bounds or not currently open
	if (fd < 0 || files_open > FS_OPEN_MAX_COUNT || open_files[fd].fd == -1) {
		return -1;
	}

	char *file = root_dir[fd].filename;
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
		if (!strcmp(root_dir[i].filename, file)) {
			return root_dir[i].fsize;
		}
	}

	return -1;
}

int fs_lseek(int fd, size_t offset)
{
	/* Check if file descriptor is out of bounds or not currently open or
	 * if offset is larger than current file size */
	if (fd < 0 || files_open > FS_OPEN_MAX_COUNT || open_files[fd].fd == -1 || offset > root_dir[fd].fsize) {
		return -1;
	}

	open_files[fd].offset = offset;

	return 0;
}


static int get_blocks(int bytes, int offset)
{
	int bytes_left = bytes + offset;
	int num_blocks = 0;
	while (bytes_left > 0) {
		bytes_left -= BLOCK_SIZE;
		num_blocks++;
	}
	/* return ((bytes + offset) / BLOCK_SIZE) + 1; */
	return num_blocks;
}

static int get_extra_blocks(int file_index, size_t count)
{
	int extra_blocks = 1;
	struct File f = open_files[file_index];
	/* Writing within file size, no need to extend */
	if (f.offset + count <= root_dir[f.root_i].fsize)
		return 0;
	uint32_t bytes_needed = count + f.offset - root_dir[f.root_i].fsize;

	uint16_t cur_block = root_dir[f.root_i].findex;
	uint16_t prev_block = cur_block;
	for (prev_block = cur_block;cur_block != FAT_EOC; cur_block =
			fat[cur_block].entries) {
		prev_block = cur_block;
	}
	int a = 1;
	if (bytes_needed <= BLOCK_SIZE)	
		a = 0;
	cur_block = prev_block;
	if (a) {
		for (extra_blocks = 1; bytes_needed >= BLOCK_SIZE; bytes_needed -=
				BLOCK_SIZE) {
			extra_blocks++;
			int next_block = get_empty_fat();
			/* Cannot find available blocks */
			if (next_block == -1)
				return -1;
			/* if prev block is FAT_EOC, we need to create a new file,
			 * else we write in current fat */
			fat[cur_block].entries = next_block;
			cur_block = next_block;
		}
	}
	fat[cur_block].entries = FAT_EOC;
	if (fat_write() == -1)
		return -1;
	block_write(super->root_blocki, (void*)root_dir);
	return extra_blocks;
}

int fs_write(int fd, void *buf, size_t count)
{
	if (buf == NULL)
		return -1;
	if (count == 0)
		return 0;
	int file_index = fd_to_index(fd);
	if (file_index == -1)
		return -1;
	struct File *f = &open_files[file_index];
	int root_i = f->root_i;
	int blocks_to_write = get_blocks(count, f->offset % BLOCK_SIZE);
	int extra_blocks = get_extra_blocks(file_index, count);
	if (extra_blocks == -1)
		return -1;
	int block_i = root_dir[root_i].findex;
	int is_aligned = f->offset == 0;	
	uint8_t bounce_buf[BLOCK_SIZE];
	int bounce_buf_ptr = 0;
	uint32_t bytes_left = count;
	int bytes_written = 0;
	/* Generic, for all the other cases */
	for (int i = 0; i < blocks_to_write; i++) {
		uint32_t bytes_to_write = bytes_left > BLOCK_SIZE - f->offset ?
			BLOCK_SIZE - f->offset : bytes_left;
		if (!is_aligned) {
			block_read(block_i + super->data_starti,
					bounce_buf);
			memcpy(bounce_buf + f->offset, buf, bytes_to_write);
		} else {
			memcpy(bounce_buf, bounce_buf + bounce_buf_ptr,
					bytes_to_write);
		}
		block_read(block_i + super->data_starti, bounce_buf);
		memcpy(bounce_buf + f->offset, buf, bytes_to_write);
		bytes_left -= bytes_to_write;
		bytes_written += bytes_to_write;
		bounce_buf_ptr += bytes_to_write;
		is_aligned = bytes_to_write + f->offset == BLOCK_SIZE;
		block_write(block_i + super->data_starti, bounce_buf);
		memset(bounce_buf, 0, sizeof(bounce_buf));

		block_i = fat[block_i].entries;
	}
	
	f->offset += bytes_written;
	root_dir[root_i].fsize += bytes_written;
	block_write(super->root_blocki, (void *)root_dir);

	return bytes_written;
}

int fs_read(int fd, void *buf, size_t count)
{
	if (buf == NULL || fd > FS_FILE_MAX_COUNT)
		return -1;

	int file_index = fd_to_index(fd);	
	struct File *f = &open_files[file_index];
	int block_i = root_dir[f->root_i].findex;
	if (file_index == -1)
		return -1;
	size_t file_size = root_dir[f->root_i].fsize;
	char bounce_buf[file_size * BLOCK_SIZE];
	memset(bounce_buf, 0, sizeof(bounce_buf));
	int cur_block = block_i;

	while (fat[cur_block].entries != FAT_EOC) {
		block_read(cur_block + super->data_starti, (void *)bounce_buf);
		cur_block = fat[cur_block].entries;
	}

	block_read(cur_block + super->data_starti, (void *)bounce_buf);
	char *entry_point = &bounce_buf[f->offset];
	memcpy(buf, entry_point, count);
	return f->offset + count > file_size ? file_size - f->offset : count;
}
