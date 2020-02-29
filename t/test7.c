#include <linux/types.h>
#include <stddef.h>

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

#define __compiletime_error(message)

#define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)

#define compiletime_assert(condition, msg) \
	__compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)

#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

struct foo {
	int			bar;
	int			buzz;
};

static int process(int *ptr)
{
	struct foo *ctr = container_of(ptr, struct foo, buzz);

	ctr->bar++;
	ctr->bar++;

	return ctr->bar;
}

int main()
{
	struct foo foo = { .bar = 1, .buzz = 2 };
	int *ptr = &foo.buzz;

	process(ptr);
	return 0;
}
