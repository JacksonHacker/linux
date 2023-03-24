// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include "../kselftest_harness.h"

#define __NR_cp_range 451


/* Test function */
TEST(cp_range_test)
{
	int arr1[5] = {1, 1, 1, 1, 1};
	int arr2[5] = {2, 2, 2, 2, 2};
	int ret;

	ret = syscall(__NR_cp_range, arr1, arr1 + sizeof(arr1));
	EXPECT_EQ(0, ret);

	ret = syscall(__NR_cp_range, arr2, arr2 + sizeof(arr2));
	EXPECT_EQ(0, ret);
}

/* Test main */
TEST_HARNESS_MAIN
