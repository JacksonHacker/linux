#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>


#define __NR_cp_range 451

#define SMALL_BLOCK_SIZE 10
#define LARGE_BLOCK_SIZE (1024 * 1024)

void *thread_func(void *arg)
{
	int arr[10] = {(int) arg, (int) arg, (int) arg, (int) arg, (int) arg, (int) arg, (int) arg, (int) arg, (int) arg, (int) arg};
	void *small_block, *large_block;

	small_block = malloc(SMALL_BLOCK_SIZE);
	large_block = malloc(LARGE_BLOCK_SIZE);



	// Sleep for a long time
	printf("\nThread %ld sleeping...\n", (long)arg);
	sleep(999999999);
	printf("Thread %ld task wakes up.\n", (long)arg);

	free(small_block);
	free(large_block);

	return NULL;
}

int main(void)
{
	pthread_t thread1, thread2;
	int ret;

	pthread_create(&thread1, NULL, thread_func, (void *)1);
	pthread_create(&thread2, NULL, thread_func, (void *)2);

	printf("Group leader task is sleeping...\n");
	sleep(3);
	printf("Group leader task wakes up.\n");

	printf("\nGroup leader task: checkpoint 0x0 - 0xFFFFFFFFFFFFFFFF.\n");
	ret = syscall(__NR_cp_range, 0x0, 0xFFFFFFFFFFFFFFFF);
	if (ret)
		perror("cp_range(whole virtual space) failed");

	printf("checkpoint successfully!\n");


	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

	return 0;
}
