#include <stdlib.h>

struct foo {
	int arr[12];
};

int main()
{
	struct foo *f = malloc(sizeof(*f));

	if (!f)
		return 1;

	f->arr[0] = 0x00;
	return 0;
}
