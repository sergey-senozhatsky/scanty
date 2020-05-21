struct foo {
	int i;
};

struct bar {
	struct foo	x;
	struct foo	y;
	struct foo	*z;
};

int main()
{
	struct bar b;
	struct foo *p = &b.x;

	p->i = 1;

	p = &b.y;
	p->i = 2;

	return 0;
}
