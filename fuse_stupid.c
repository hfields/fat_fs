/*
  fuse_stupid: stupid but simple file system

  gcc -Wall `pkg-config fuse --cflags --libs` fuse_stupid.c -o fuse_stupid
*/

#define FUSE_USE_VERSION 26

#include <assert.h>
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STUPID_MAGIC_BIG_ENDIAN 0x7374757069642121L
#define STUPID_MAGIC_LITTLE_ENDIAN 0x2121646970757473L

#define BLOCK_SIZE      4096
#define BLOCKS_PER_FILE 100             /* Maximum file size, in blocks */
#define MAX_FILES       100             /* Maximum number of files supported */
#define DISK_SIZE       ((1 + BLOCKS_PER_FILE * MAX_FILES) * BLOCK_SIZE)

typedef size_t          block_t;        /* Block-address type */

static int              backing_file_fd; /* Fd for all access to backing file */
static gid_t            gid;            /* GID we were invoked under */
static uid_t            uid;            /* UID we were invoked under */
static time_t           mount_time;     /* Time the filesystem was mounted */

struct sblock {
    unsigned long       magic;          /* Magic number identifying filesys */
    size_t              total_blocks;   /* Total blocks (disk size) */
    size_t              block_size;     /* Size of each block */
    size_t              blocks_per_file; /* How big each file is, in blocks */
    block_t             files_start;    /* First block of first file */
    size_t              next_file_no;   /* Next file number to use */
};

static union {
    struct sblock       s;
    char                pad[BLOCK_SIZE];
}
                        superblock;

/*
 * Directory entries are hacked to be exactly 64 bytes.  NAME_LENGTH
 * must incorporate the sizes of all fields in stupid_dirent.  Also
 * note that NAME_LENGTH must be 255 or less, so that the namelen
 * field in dirent can be only one byte.
 */
#define DIRENT_LENGTH   64
#define NAME_LENGTH     (DIRENT_LENGTH - 1 - 1 - 2 * sizeof (size_t))

/*
 * Directory entry.
 */
typedef struct {
    size_t              file_no;        /* Number of the file in the system */
    size_t              size;           /* Size of the file */
    unsigned char       type;           /* Entry type (see below) */
    unsigned char       namelen;        /* Length of name */
    char                name[NAME_LENGTH];  /* File name */
}
                        stupid_dirent;

#define DIR_SIZE        (BLOCKS_PER_FILE * BLOCK_SIZE / sizeof (stupid_dirent))
                                        /* Number of entries in a directory */

/*
 * Space for holding a directory block in memory.
 */
static block_t          dirblock = 0;   /* Block represented by dirbuf */
static stupid_dirent*   dirbuf;         /* Current directory block buffer */
static stupid_dirent*   dirend;         /* End of directory block buffer */

/*
 * File types.  Note that these do *not* match unix types!
 */
#define TYPE_EMPTY      0               /* Empty directory entry MUST BE ZERO */
#define TYPE_DIR        1               /* Subdirectory */
#define TYPE_FILE       2               /* Plain file */

/*
 * Handy macros for converting between block numbers (used in block
 * pointers of type block_t) and byte offsets (used by the Unix I/O
 * interface).  Note that BYTES_TO_BLOCKS rounds *upward* if the
 * offset isn't an exact multiple of the block size.
 */
#define BLOCKS_TO_BYTES(x)      ((x) * superblock.s.block_size)
#define BYTES_TO_BLOCKS(x)      (((x) + superblock.s.block_size - 1) \
                                  / superblock.s.block_size)

/*
 * Macro to convert from a file number to the address of its first
 * block.  Note that there is no file number zero (file 0 is the root
 * directory).
 */
#define FILE_NO_TO_BLOCK(x)     (((x) - 1) * superblock.s.blocks_per_file \
                                  + superblock.s.files_start)

/*
 * Macro to generate the number of the last block of a file (actually
 * the last + 1 block), given the first block.
 */
#define LAST_BLOCK(x)           ((x) + superblock.s.blocks_per_file)

/*
 * Macros to convert a byte offset to a block in a file.
 */
#define OFFSET_TO_BLOCK(dirent, x) \
                                (FILE_NO_TO_BLOCK(dirent->file_no) + (x) \
                                  / superblock.s.block_size)
#define OFFSET_IN_BLOCK(x)      ((x) % superblock.s.block_size)

/*
 * Number of directory entries stored in a block.
 */
#define DIRENTS_PER_BLOCK       (superblock.s.block_size / DIRENT_LENGTH)


/*
 * Read from a given block on the backing file/device.  We always read
 * in one-block units.  Always succeeds; aborts the program on failures.
 */
static void read_block(block_t block, void *buf)
{
    assert(lseek(backing_file_fd, BLOCKS_TO_BYTES(block), SEEK_SET) != -1);
    assert(read(backing_file_fd, buf, superblock.s.block_size)
      == superblock.s.block_size);
}

/*
 * Write to a given block on the backing file/device.  We always write
 * in one-block units.  Always succeeds; aborts the program on failures.
 */
static void write_block(block_t block, const void *buf)
{
    assert(lseek(backing_file_fd, BLOCKS_TO_BYTES(block), SEEK_SET) != -1);
    assert(write(backing_file_fd, buf, superblock.s.block_size)
      == superblock.s.block_size);
}

/*
 * Rewrite the superblock.
 */
static void flush_superblock()
{
    write_block(0, &superblock);
}

/*
 * Fetch a directory block.
 */
static void fetch_dirblock(size_t block)
{
    if (dirblock == block)
        return;                         /* Efficiency: no work needed */
    dirblock = block;
    read_block(dirblock, dirbuf);
}

/*
 * Rewrite the current directory block.
 */
static void flush_dirblock()
{
    write_block(dirblock, dirbuf);
}

static void* fuse_stupid_init(struct fuse_conn_info *conn)
{
    size_t              size;

    /*
     * Read superblock, if it exists.  We don't use read_block
     * because if we just created the backing file, the read will fail
     * and we'll need to initialize the backing file.
     */
    assert(lseek(backing_file_fd, 0, SEEK_SET) != -1);
    size = read(backing_file_fd, &superblock, sizeof superblock);
    if (size == sizeof superblock
       &&  superblock.s.magic == STUPID_MAGIC_LITTLE_ENDIAN) {
        /*
         * The backing file exists and is valid. Create a buffer for
         * holding directory blocks.  We don't need to fill it.
         */
        dirbuf = (stupid_dirent*)calloc(superblock.s.block_size, 1);
        dirend = (stupid_dirent*)((char *)dirbuf + superblock.s.block_size);
        return NULL;
    }
    /*
     * The filesystem doesn't exist.  Make it.
     *
     * Create superblock.
     */
    memset(&superblock, 0, sizeof superblock);
    superblock.s.magic = STUPID_MAGIC_LITTLE_ENDIAN;
    superblock.s.total_blocks = DISK_SIZE / BLOCK_SIZE;
    superblock.s.block_size = BLOCK_SIZE;
    superblock.s.blocks_per_file = BLOCKS_PER_FILE;

    /*
     * The root directory always starts just past the superblock,
     * and has file number 1.  So the next available file number is 2.
     */
    superblock.s.files_start = sizeof(superblock) / superblock.s.block_size;
    superblock.s.next_file_no = 2;

    /*
     * Create an initial root directory and write it to disk.  We
     * depend on the fact that calloc zeros the memory it allocates,
     * and the fact that TYPE_EMPTY is zero.
     */
    dirbuf = (stupid_dirent*)calloc(superblock.s.block_size, 1);
    dirend = (stupid_dirent*)((char *)dirbuf + superblock.s.block_size);

    dirblock = superblock.s.files_start;
    dirbuf[0].type = TYPE_DIR;
    dirbuf[0].file_no = 1;
    dirbuf[0].size = DIR_SIZE * DIRENT_LENGTH;
    dirbuf[0].namelen = 1;
    memcpy(dirbuf[0].name, ".", 1);

    dirbuf[1].type = TYPE_DIR;
    dirbuf[1].file_no = 1;
    dirbuf[1].size = DIR_SIZE * DIRENT_LENGTH;
    dirbuf[1].namelen = 2;
    memcpy(dirbuf[1].name, "..", 2);
    write_block(superblock.s.files_start, dirbuf);

    /*
     * The rest of the code will be simpler if the backing file is the
     * size of the "true" disk.  We can do that with truncate.  We
     * deliberately don't check the return code because you can't
     * truncate a real device.
     */
    ftruncate(backing_file_fd, DISK_SIZE);

    /*
     * Finally, write the superblock to disk.  We write it last so
     * that if we crash, the disk won't appear valid.
     */
    flush_superblock();

    /*
     * We're expected to return a pointer to user data; we have none.
     */
    return NULL;
}

/*
 * Look up a pathname component in a directory that starts at "block".
 */
static stupid_dirent* lookup_component(block_t block,
  const char *start, const char *end)
{
    stupid_dirent*      dirent;
    size_t              len;
    block_t             last_block;

    len = end - start;
    if (len > NAME_LENGTH)
        len = NAME_LENGTH;
    for (last_block = LAST_BLOCK(block);  block < last_block;  block++) {
        fetch_dirblock(block);
        for (dirent = dirbuf;  dirent < dirend;  dirent++) {
            if (dirent->type != TYPE_EMPTY
              &&  len == dirent->namelen
              &&  memcmp(dirent->name, start, len) == 0)
                return dirent;
        }
    }
    return NULL;
}

/*
 * Find a directory entry.  If parent is nonzero, return the parent instead
 * of the entry itself.  If it succeeds, returns a pointer to the dirent.
 * On failure, returns NULL.
 */
static stupid_dirent* find_dirent(const char *path, int parent)
{
    const char *        component_start;
    const char *        cp;
    stupid_dirent*      dirent;
    block_t             parent_dirblock;
    stupid_dirent*      parent_dirent;

    /*
     * File #1 is the root directory, so we can just start there.
     */
    fetch_dirblock(superblock.s.files_start);
    parent_dirblock = dirblock;
    parent_dirent = dirent = &dirbuf[0];
    for (cp = component_start = path;  *cp != '\0';  cp++) {
        if (*cp == '/') {
            if (cp != component_start) {
                /* Descend a directory level */
                parent_dirblock = dirblock;
                parent_dirent = dirent;
                dirent = lookup_component(FILE_NO_TO_BLOCK(dirent->file_no),
                  component_start, cp);
                if (dirent == NULL  ||  dirent->type != TYPE_DIR)
                    return NULL;
            }
            component_start = cp + 1;
        }
    }
    if (component_start == cp) {
        if (parent) {
            fetch_dirblock(parent_dirblock);
            return parent_dirent;
        }
        else
            return dirent;
    }
    else {
        if (!parent) {
            dirent = lookup_component(FILE_NO_TO_BLOCK(dirent->file_no),
              component_start, cp);
        }
        return dirent;
    }
}

static int fuse_stupid_getattr(const char *path, struct stat *stbuf)
{
    stupid_dirent*      dirent;

    memset(stbuf, 0, sizeof(struct stat));

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type == TYPE_DIR) {
        /*
         * We don't support permissions so we make everything the same.
         */
        stbuf->st_mode = S_IFDIR | 0755;
        /*
         * NEEDSWORK: nlink should be 2 plus number of subdirectories.
         */
        stbuf->st_nlink = 2;
    }
    else {
        /*
         * We don't support permissions so we make everything the same.
         */
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
    }
    stbuf->st_ino = dirent->file_no;
    stbuf->st_size = dirent->size;
    stbuf->st_uid = uid;
    stbuf->st_gid = gid;
    stbuf->st_blksize = superblock.s.block_size;
    /* For historical reasons, the block count is in 512-byte blocks. */
    stbuf->st_blocks =
      superblock.s.blocks_per_file * (superblock.s.block_size / 512);
    /*
     * Since we don't support timestamps, set everything to the mount time.
     */
    stbuf->st_atime = stbuf->st_ctime = stbuf->st_mtime = mount_time;
    return 0;
}

static int fuse_stupid_fgetattr(const char *path, struct stat *stbuf,
  struct fuse_file_info *fi)
{
    return fuse_stupid_getattr(path, stbuf);
}

static int fuse_stupid_access(const char *path, int mask)
{
    stupid_dirent*      dirent;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    /*
     * If a file exists, we allow access--except we disallow writing
     * directories.
     */
    if (dirent->type == TYPE_DIR  &&  mask == W_OK)
        return -EACCES;
    return 0;
}

static int fuse_stupid_readdir(const char *path, void *buf,
  fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    block_t             block;
    stupid_dirent*      dirent;
    block_t             last_block;
    char                name[NAME_LENGTH + 1];

    (void) fi;          /* Suppress unused-argument warnings */

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_DIR)
        return -ENOTDIR;

    name[sizeof name - 1] = '\0';
    block = FILE_NO_TO_BLOCK(dirent->file_no);
    for (last_block = LAST_BLOCK(block);  block < last_block;  block++) {
        fetch_dirblock(block);
        for (dirent = dirbuf;  dirent < dirend;  dirent++) {
            if (offset > 0) {
                offset -= sizeof (dirent);
                continue;
            }
            if (dirent->type != TYPE_EMPTY) {
                memcpy(name, dirent->name, dirent->namelen);
                name[dirent->namelen] = '\0';
                if (filler(buf, name, NULL, 0))
                    return 0;
            }
        }
    }

    return 0;
}

/*
 * Get a new file number.  We're really dumb here: we just allocate
 * file numbers sequentially until we run out.  Note that deleting a
 * file doesn't free space!  If we can't find a number, we return 0.
 */
static size_t get_new_file_number()
{
    size_t              file_no;

    if (FILE_NO_TO_BLOCK(superblock.s.next_file_no + 1)
      >= superblock.s.total_blocks)
        return 0;
    file_no = superblock.s.next_file_no++;
    flush_superblock();
    return file_no;
}

static int fuse_stupid_mknod(const char *path, mode_t mode, dev_t rdev)
{
    block_t             block;
    const char*         cp;
    stupid_dirent*      dirent;
    block_t             last_block;
    size_t              len;
    block_t             parent_block;

    if (find_dirent(path, 0) != NULL)
        return -EEXIST;                 /* Pathname already exists */
    if (!S_ISREG(mode))
        return -EACCES;                 /* Only supported for plain files */

    /*
     * Find the directory to make the new file in.
     */
    dirent = find_dirent(path, 1);
    block = parent_block = FILE_NO_TO_BLOCK(dirent->file_no);
    /*
     * Find an empty slot.
     */
    for (last_block = LAST_BLOCK(block);  block < last_block;  block++) {
        fetch_dirblock(block);
        for (dirent = dirbuf;  dirent < dirend;  dirent++) {
            if (dirent->type == TYPE_EMPTY)
                goto doublebreak;
        }
    }
doublebreak:
    if (block >= last_block)
        return -EFBIG;                  /* No room in the directory */
    dirent->file_no = get_new_file_number();
    if (dirent->file_no == 0)
        return -ENOSPC;                 /* No space for new files */
    dirent->type = TYPE_FILE;
    dirent->size = 0;
    cp = strrchr(path, '/');
    if (cp == NULL)
        cp = path;
    else
        cp++;
    len = strlen(cp);
    if (len > NAME_LENGTH)
        len = NAME_LENGTH;
    dirent->namelen = len;
    memcpy(dirent->name, cp, len);
    flush_dirblock();

    return 0;
}

static int fuse_stupid_create(const char *path, mode_t mode,
  struct fuse_file_info *fi)
{
    return fuse_stupid_mknod(path, mode | S_IFREG, 0);
}

/*
 * NEEDSWORK: This shares a lot of code with fuse_stupid_mknod.  The
 * common code should be factored out.
 */
static int fuse_stupid_mkdir(const char *path, mode_t mode)
{
    block_t             block;
    const char*         cp;
    stupid_dirent*      dirent;
    block_t             last_block;
    size_t              len;
    size_t              parent_file_no;
    size_t              parent_size;

    if (find_dirent(path, 0) != NULL)
        return -EEXIST;                 /* Pathname already exists */

    /*
     * Find the directory to make the directory in.
     */
    dirent = find_dirent(path, 1);
    parent_file_no = dirent->file_no;
    parent_size = dirent->size;
    /*
     * Find an empty slot.  We depend on the fact that fetch_dirblock
     * sets dirblock as a side effect.
     */
    block = FILE_NO_TO_BLOCK(parent_file_no);
    for (last_block = LAST_BLOCK(block);  block < last_block;  block++) {
        fetch_dirblock(block);
        for (dirent = dirbuf;  dirent < dirend;  dirent++) {
            if (dirent->type == TYPE_EMPTY)
                goto doublebreak;
        }
    }
doublebreak:
    if (block >= last_block)
        return -EFBIG;                  /* No room in the directory */
    dirent->file_no = get_new_file_number();
    if (dirent->file_no == 0)
        return -ENOSPC;                 /* No space for new files */
    dirent->type = TYPE_DIR;
    dirent->size = DIR_SIZE * DIRENT_LENGTH;
    cp = strrchr(path, '/');
    if (cp == NULL)
        cp = path;
    else
        cp++;
    len = strlen(cp);
    if (len > NAME_LENGTH)
        len = NAME_LENGTH;
    dirent->namelen = len;
    memcpy(dirent->name, cp, len);
    flush_dirblock();

    /*
     * Initialize the new directory block.
     */
    dirblock = FILE_NO_TO_BLOCK(dirent->file_no);
    memset(dirbuf, 0, superblock.s.block_size);
    dirbuf[0].type = TYPE_DIR;
    dirbuf[0].file_no = dirent->file_no;
    dirbuf[0].size = DIR_SIZE * DIRENT_LENGTH;
    dirbuf[0].namelen = 1;
    memcpy(dirbuf[0].name, ".", 1);
    dirbuf[1].type = TYPE_DIR;
    dirbuf[1].file_no = parent_file_no;
    dirbuf[1].size = parent_size;
    dirbuf[1].namelen = 2;
    memcpy(dirbuf[1].name, "..", 2);
    flush_dirblock();

    return 0;
}

static int fuse_stupid_unlink(const char *path)
{
    stupid_dirent*      going_dirent;

    /*
     * Find the file being removed.
     */
    going_dirent = find_dirent(path, 0);
    if (going_dirent == NULL)
        return -ENOENT;

    /*
     * Remove the file by zeroing its directory entry.  We make no
     * attempt to free its space.
     */
    memset(going_dirent, 0, sizeof *going_dirent);

    /*
     * Write the directory back.
     */
    flush_dirblock();
    return 0;
}

static int fuse_stupid_rmdir(const char *path)
{
    block_t             block;
    stupid_dirent*      dirent;
    int                 first_block;
    block_t             going_block;
    stupid_dirent*      going_dirent;
    size_t              last_block;

    /*
     * Find the directory being removed.
     */
    going_dirent = find_dirent(path, 0);
    if (going_dirent == NULL)
        return -ENOENT;
    going_block = dirblock;
    /*
     * Make sure it's empty.
     */
    block = FILE_NO_TO_BLOCK(going_dirent->file_no);
    first_block = 1;
    for (last_block = LAST_BLOCK(block);  block < last_block;  block++) {
        fetch_dirblock(block);
        for (dirent = first_block ? dirbuf + 2 : dirbuf;
          dirent < dirend;
          dirent++) {
            if (dirent->type != TYPE_EMPTY)
                return -ENOTEMPTY;
        }
        first_block = 0;
    }
    /*
     * Remove the directory.  Note that we don't free its space!
     */
    fetch_dirblock(going_block);
    memset(going_dirent, 0, sizeof *going_dirent);

    /*
     * Write the parent back.
     */
    flush_dirblock();
    return 0;
}

static int fuse_stupid_rename(const char *from, const char *to)
{
    /*
     * Getting rename right is hard; you may need to remove the destination,
     * and it has to support cross-directory renames.  I'm just going to
     * prohibit it.
     */
    return -ENOSYS;
}

static int fuse_stupid_truncate(const char *path, off_t size)
{
    block_t             block;
    char                buffer[BLOCK_SIZE];
    stupid_dirent*      dirent;
    size_t              oldsize;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    /*
     * If we are extending the file, we need to zero it.
     */
    assert(superblock.s.block_size == BLOCK_SIZE);
    oldsize = dirent->size;
    if (size > dirent->size) {
        block = OFFSET_TO_BLOCK(dirent, oldsize);
        if (OFFSET_IN_BLOCK(oldsize) != 0) {
            read_block(block, buffer);
            memset(buffer + OFFSET_IN_BLOCK(oldsize), 0,
              superblock.s.block_size - OFFSET_IN_BLOCK(oldsize));
            write_block(block, buffer);
            oldsize = BLOCKS_TO_BYTES(BYTES_TO_BLOCKS(oldsize));
        }
        memset(buffer, 0, superblock.s.block_size);
        while (oldsize < size) {
            write_block(block, buffer);
            oldsize += superblock.s.block_size;
        }
    }
    dirent->size = size;

    /*
     * Write the parent directory back.
     */
    flush_dirblock();
    return 0;
}

static int fuse_stupid_open(const char *path, struct fuse_file_info *fi)
{
    stupid_dirent*      dirent;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_FILE)
        return -EACCES;
    /*
     * Open succeeds if the file exists.
     */
    return 0;
}

static int fuse_stupid_read(const char *path, char *buf, size_t size,
  off_t offset, struct fuse_file_info *fi)
{
    block_t             block;
    char                blockbuf[BLOCK_SIZE];
    size_t              bytes_read;
    stupid_dirent*      dirent;
    size_t              read_size;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_FILE)
        return -EACCES;

    read_size = dirent->size;           /* Amount to read (max is file size) */
    if (offset >= read_size)
        return 0;
    if (offset + size > read_size)
        size = read_size - offset;      /* Don't read past EOF */

    block = OFFSET_TO_BLOCK(dirent, offset);
    offset = OFFSET_IN_BLOCK(offset);

    for (bytes_read = 0;  size > 0;  block++, offset = 0) {
        read_size = superblock.s.block_size - offset;
        if (read_size > size)
            read_size = size;
        read_block(block, blockbuf);    /* Read in full-block units */
        memcpy(buf, blockbuf, read_size);
        bytes_read += read_size;
        buf += read_size;
        size -= read_size;
    }

    return bytes_read;
}

static int fuse_stupid_write(const char *path, const char *buf, size_t size,
  off_t offset, struct fuse_file_info *fi)
{
    block_t             block;
    char                blockbuf[BLOCK_SIZE];
    size_t              bytes_written;
    stupid_dirent*      dirent;
    off_t               orig_offset = offset;
    size_t              write_size;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_FILE)
        return -EACCES;

    if (size > superblock.s.blocks_per_file * superblock.s.block_size - offset)
        size = superblock.s.blocks_per_file * superblock.s.block_size - offset;

    if (offset >= superblock.s.blocks_per_file * superblock.s.block_size)
        return -EFBIG;                          /* File is too big */
    else if (size == 0)
        return -EIO;                            /* Empty writes are illegal */

    assert(superblock.s.block_size == BLOCK_SIZE);

    block = OFFSET_TO_BLOCK(dirent, offset);
    offset = OFFSET_IN_BLOCK(offset);

    for (bytes_written = 0;  size > 0;  block++, offset = 0) {
        if (offset == 0  &&  size >= superblock.s.block_size)
            read_block(block, blockbuf);        /* Only read if necessary */
        write_size = size;
        if (write_size > superblock.s.block_size - offset)
            write_size = superblock.s.block_size - offset;
        memcpy(blockbuf + offset, buf, write_size);
        write_block(block, blockbuf);
        buf += write_size;
        size -= write_size;
        bytes_written += write_size;
        if (dirent->size < orig_offset + bytes_written)
            dirent->size = orig_offset + bytes_written;
    }

    flush_dirblock();
    return bytes_written;
}

static int fuse_stupid_statfs(const char *path, struct statvfs *stbuf)
{

    stbuf->f_bsize = superblock.s.block_size;   /* file system block size */
    stbuf->f_frsize = superblock.s.block_size;  /* fragment size */
    stbuf->f_blocks = superblock.s.total_blocks; /* fs size in f_frsize units */
    stbuf->f_files = 0;                         /* # inodes */
    stbuf->f_ffree = 0;                         /* # free inodes */
    stbuf->f_favail = 0;                        /* # free inodes for non-root */
    stbuf->f_fsid = 0;                          /* file system ID */
    stbuf->f_flag = 0;                          /* mount flags */
    stbuf->f_namemax = NAME_LENGTH;             /* max filename length */

    /*
     * f_bfree is hard to calculate, so we're just going to lie.
     */
    stbuf->f_bfree = BLOCKS_PER_FILE;           /* # free blocks */
    stbuf->f_bavail = stbuf->f_bfree;           /* # free blocks for non-root */
    return 0;
}

static struct fuse_operations fuse_stupid_oper = {
        .init           = fuse_stupid_init,
        .getattr        = fuse_stupid_getattr,
        .fgetattr       = fuse_stupid_fgetattr,
        .access         = fuse_stupid_access,
        .readdir        = fuse_stupid_readdir,
        .mknod          = fuse_stupid_mknod,
        .create         = fuse_stupid_create,
        .mkdir          = fuse_stupid_mkdir,
        .unlink         = fuse_stupid_unlink,
        .rmdir          = fuse_stupid_rmdir,
        .rename         = fuse_stupid_rename,
        .truncate       = fuse_stupid_truncate,
        .open           = fuse_stupid_open,
        .read           = fuse_stupid_read,
        .write          = fuse_stupid_write,
        .statfs         = fuse_stupid_statfs,
};

int main(int argc, char *argv[])
{
    /*
     * The first argument must be the name of the backing disk (or the
     * file that masquerades as the backing disk).
     */
    if (argc < 2) {
        (void) fprintf (stderr,
          "Usage: fuse_stupid backing-file [fuse-args] mount-point\n");
        exit(2);
    }
    backing_file_fd = open(argv[1], O_RDWR | O_CREAT, 0600);
    if (backing_file_fd < 0) {
        perror("fuse_stupid: Couldn't open disk: ");
        exit(1);
    }

    uid = getuid();
    gid = getgid();
    time(&mount_time);

    /*
     * Force the -s switch.  We take advantage of the fact that the first
     * argument, above, is the backing file name and thus won't be passed
     * to fuse.  Yes, this is a hack.
     */
    argv[1] = "-s";
    return fuse_main(argc, argv, &fuse_stupid_oper, NULL);
}