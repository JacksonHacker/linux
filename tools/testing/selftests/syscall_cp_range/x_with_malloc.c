#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_cp_range 451

#define SMALL_BLOCK_SIZE 10
#define LARGE_BLOCK_SIZE (1024 * 1024)

int u; // uninitialized.

static int test_cp_range(void)
{
	int arr1[10] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	int arr2[10] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
	void *small_block1, *small_block2;
	void *large_block1, *large_block2;
	long ret;

	printf("checkpoint arr1 with 10 int.\n");
	ret = syscall(__NR_cp_range, arr1, arr1 + 10);
	if (ret) {
		perror("cp_range(arr1) failed");
		return -1;
	}
	printf("checkpoint successfully!\n");

	printf("checkpoint arr2 with 10 int.\n");
	ret = syscall(__NR_cp_range, arr2, arr2 + 10);
	if (ret) {
		perror("cp_range(arr2) failed");
		return -1;
	}
	printf("checkpoint successfully!\n");


	// Allocate small blocks of memory
	small_block1 = malloc(SMALL_BLOCK_SIZE);
	small_block2 = malloc(SMALL_BLOCK_SIZE);

	// Allocate large blocks of memory
	large_block1 = malloc(LARGE_BLOCK_SIZE);
	large_block2 = malloc(LARGE_BLOCK_SIZE);

	if (!small_block1 || !small_block2 || !large_block1 || !large_block2) {
		perror("Memory allocation failed\n");
		return 1;
	}

	// Checkpoint the small blocks of memory
	printf("checkpoint small_block1 with %d bytes.\n", SMALL_BLOCK_SIZE);
	ret = syscall(__NR_cp_range, small_block1, small_block1 + SMALL_BLOCK_SIZE);
	if (ret < 0) {
		printf("cp_range syscall for small_block1 failed: %ld\n", ret);
		return 1;
	}
	printf("checkpoint successfully!\n");

	printf("checkpoint small_block2 with %d bytes.\n", SMALL_BLOCK_SIZE);
	ret = syscall(__NR_cp_range, small_block2, small_block2 + SMALL_BLOCK_SIZE);
	if (ret < 0) {
		printf("cp_range syscall for small_block2 failed: %ld\n", ret);
		return 1;
	}
	printf("checkpoint successfully!\n");

	// Checkpoint the large blocks of memory
	printf("checkpoint large_block1 with %d bytes.\n", LARGE_BLOCK_SIZE);
	ret = syscall(__NR_cp_range, large_block1, large_block1 + LARGE_BLOCK_SIZE);
	if (ret < 0) {
		printf("cp_range syscall for large_block1 failed: %ld\n", ret);
		return 1;
	}
	printf("checkpoint successfully!\n");

	printf("checkpoint large_block2 with %d bytes.\n", LARGE_BLOCK_SIZE);
	ret = syscall(__NR_cp_range, large_block2, large_block2 + LARGE_BLOCK_SIZE);
	if (ret < 0) {
		printf("cp_range syscall for large_block2 failed: %ld\n", ret);
		return 1;
	}
	printf("checkpoint successfully!\n");


	printf("checkpoint 0x0 - 0x7FFFFFFFFFFF.\n");
	ret = syscall(__NR_cp_range, 0x0, 0x7FFFFFFFFFFF);
	if (ret) {
		perror("cp_range(whole user space) failed");
		return -1;
	}
	printf("checkpoint successfully!\n");

	printf("checkpoint 0x0 - 0xFFFFFFFFFFFFFFFF.\n");
	ret = syscall(__NR_cp_range, 0x0, 0xFFFFFFFFFFFFFFFF);
	if (ret) {
		perror("cp_range(whole virtual space) failed");
		return -1;
	}
	printf("checkpoint successfully!\n");

	printf("\nSleeping...\n");
	sleep(999999999);

	printf("\nFreeing Memory Blocks...\n");
	// Free allocated memory
	free(small_block1);
	free(small_block2);
	free(large_block1);
	free(large_block2);

	return 0;
}

int main(void)
{
	int ret;

	ret = test_cp_range();
	if (ret) {
		fprintf(stderr, "cp_range test failed\n");
		return 1;
	} else {
		printf("cp_range test passed\n");
		return 0;
	}
}
