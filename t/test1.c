// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky
 */

#define MIN_VERSION	1

#ifndef MIN_VERSION
#include <stdlib.h>
#include <stdio.h>
#endif

struct buzz;

struct buzz {
	int		__buzz__a;
	int		__buzz__b;
	union {
		char		__buzz__s;
		int		__buzz__ss;
		long long	__buzz__sss;
	} __buzz__union;

	int		__buzz__ss;
	long long	__buzz__sss;

	union {
		const char	*__buzz__priv;
		struct buzz	*__buzz__next;
	};

	int		__buzz__m:3;
	int		__buzz__n:2;

	int		__buzz__k[16];

	struct __buzz_internal {
		union {
			int	__buzz_internal__a;
			int	__buzz_internal__b;
		} __buzz_internal_union;
	} __internal_struct;

	struct buzz	*buzz;
};

int main()
{
	struct buzz b1;
	int *priv1;
	int *priv2;

#ifndef MIN_VERSION
	struct timeval			tv;
#endif

	b1.__buzz__a			= 10;
	b1.__buzz__union.__buzz__ss	= 12;
	b1.__buzz__priv			= "test_assign";

	b1.__buzz__b = b1.__buzz__a++;

	b1.__internal_struct.__buzz_internal_union.__buzz_internal__a = b1.__buzz__union.__buzz__ss;

	struct buzz b2 = {0, 1, 'a', 2, 3, "test_ctor", 4};

	struct buzz *b3			= &b1;

	b3->__buzz__a			= 11;
	b3->__buzz__b			= 12;
	b3->__buzz__next		= &b1;

	priv1				= &b1.__internal_struct.__buzz_internal_union.__buzz_internal__a;
	priv2				= &b3->__internal_struct.__buzz_internal_union.__buzz_internal__a;

#ifndef MIN_VERSION
	printf("%d %s\n", b1.__buzz__union.__buzz__ss, b1.__buzz__priv);
	printf("%d %s\n", b3->__buzz__b, b3->__buzz__priv);
#endif
	return 0;
}
