#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/mm.h> // for_each_vma_range()
#include <linux/fs.h>
#include <linux/file.h> // kernel_write()
#include <linux/uaccess.h> // copy_from_user()
#include <linux/slab.h> // kmalloc(), kfree()
#include <linux/mm_types.h> // VMA_ITERATOR
#include <linux/time.h>
#include <linux/time64.h> // struct timespec64
#include <linux/timekeeping.h> // ktime_get_real_ts64()
#include <linux/types.h> // pid_t
#include <linux/minmax.h>
#include <uapi/asm-generic/errno-base.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/fcntl.h>

#define CP_FILE_PREFIX "/tmp/cp_"
#define CP_FILENAME_MAX_LENGTH 256

static int get_cp_filename(char *cp_filename, size_t cp_filename_max_length, pid_t pid)
{
	struct timespec64 ts;
	struct tm tm_result;
	int ret;

	if (!cp_filename)
		return -EINVAL;

	// Get the current time
	ktime_get_real_ts64(&ts);
	time64_to_tm(ts.tv_sec, 0, &tm_result);

	ret = snprintf(cp_filename, cp_filename_max_length,
		       CP_FILE_PREFIX "%d_%04ld-%02d-%02dT%02d:%02d:%02d.%09ld",
		       pid,
		       tm_result.tm_year + 1900,
		       tm_result.tm_mon + 1,
		       tm_result.tm_mday,
		       tm_result.tm_hour,
		       tm_result.tm_min,
		       tm_result.tm_sec,
		       ts.tv_nsec);

	if (ret < 0 || ret >= cp_filename_max_length)
		return -ENAMETOOLONG;

	return 0;
}

// used by `do_mmap()` when restored
struct cp_vma_header {
	unsigned long start_addr;
	unsigned long len;
	unsigned long prot_flags; // Page Protection Flags
	unsigned long map_flags;  // Map Type Flags
};

static int write_vma_metadata(struct file *file, struct cp_vma_header *header, loff_t *pos)
{
	int ret;

	printk("sizeof(cp_vma_header): %lu", sizeof(struct cp_vma_header));
	ret = kernel_write(file, &header, sizeof(struct cp_vma_header), pos);
	if (ret != sizeof(header)) {
		pr_err("kernel_write(vma_metadata). failed\n");
		return -EIO;
	}

	return 0;
}

static int write_vma_data(struct file *file, struct cp_vma_header *header, loff_t *pos)
{
	int ret;
	ssize_t written;

	void *kbuffer = kvmalloc(header->len, GFP_KERNEL);
	if (!kbuffer) {
		pr_err("kvmalloc(%lu) for vma_data failed\n", header->len);
		ret = -ENOMEM;
		return ret;
	}

	if (copy_from_user(kbuffer, (const void *)header->start_addr, header->len)) {
		kvfree(kbuffer);
		pr_err("copy_from_user(..., cp_start=%lu, len=%lu) failed\n",
		       header->start_addr, header->len);
		ret = -EFAULT;
		return ret;
	}

	// A real persistent operation!
	written = kernel_write(file, kbuffer, header->len, pos);
	kvfree(kbuffer);
	if (written != header->len) {
		pr_err("kernel_write(vma_data) failed\n");
		ret = -EIO;
		return ret;
	}

	return 0;
}

static int checkpoint_memory_range(struct file *file, void __user *start_addr, void __user *end_addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct cp_vma_header header;
	loff_t file_offset = 0;
	int ret = 0;

	VMA_ITERATOR(vmi, mm, (unsigned long)start_addr);
	for_each_vma_range(vmi, vma, (unsigned long)end_addr) {

		// Only Checkpoint: Heap, Stack, .bss segment, private
		// & anon memory-mapped regions, shared & anon memory-mapped regions
		if (!vma_is_anonymous(vma))
			continue;

		header.start_addr = max_t(unsigned long, vma->vm_start, start_addr);
		header.len = min_t(unsigned long, vma->vm_end, end_addr) - header.start_addr;
		header.prot_flags = (unsigned long)vma->vm_page_prot.pgprot;
		header.map_flags = (unsigned long)vma->vm_flags;

		// Write metadata
		ret = write_vma_metadata(file, &header, &file_offset);
		if (ret < 0)
			return ret;


		// Write VMA data
		ret = write_vma_data(file, &header, &file_offset);
		if (ret < 0)
			return ret;

	}

	return ret;
}

static struct file *get_filp(pid_t pid)
{
	struct file *filp;

	// Generate a unique filename for each checkpoint
	char cp_filename[CP_FILENAME_MAX_LENGTH];
	int err = get_cp_filename(cp_filename, sizeof(cp_filename), pid);
	if (err != 0)
		return NULL;

	// Create a file
	filp = filp_open(cp_filename, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (IS_ERR(filp)) {
		pr_err("filp_open(%s) failed\n", cp_filename);
		return NULL;
	}

	return filp;
}

SYSCALL_DEFINE2(cp_range, void __user *, start_addr, void __user *, end_addr)
{
	int err = 0;
	struct mm_struct *mm = current->mm;
	pid_t pid;
	struct file *filp;

	if (start_addr >= end_addr)
		return -EINVAL;

	// handle multithreading cases; used for get cp filename;
	pid = current->group_leader->pid;

	filp = get_filp(pid);
	if (!filp) {
		pr_err("get file pointer failed\n");
		return -EIO;
	}


	// Guarantee the virtual memory layout unchanged.
	down_read(&mm->mmap_lock);

	// Checkpoint!
	err = checkpoint_memory_range(filp, start_addr, end_addr);

	// Close the file and release the lock
	up_read(&mm->mmap_lock);
	filp_close(filp, NULL);

	return err;
}
