// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky
 */

struct __pthread_rwlock_arch_t {
	unsigned int __readers;
	unsigned int __writers;
	unsigned int __wrphase_futex;
	unsigned int __writers_futex;
	unsigned int __pad3;
	unsigned int __pad4;
	int __cur_writer;
	int __shared;
	signed char __rwelision;
	unsigned char __pad1[7];
	unsigned long int __pad2;
	unsigned int __flags;
};

typedef union
{
	struct __pthread_rwlock_arch_t __data;
	char __size[56];
	long int __align;
} pthread_rwlock_t;

typedef union
{
	char __size[8];
	long int __align;
} pthread_rwlockattr_t;

int main()
{
	pthread_rwlock_t lock = {0, };

	return 0;
}
