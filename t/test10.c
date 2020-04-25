struct in;

struct out {
	struct in {
		int a;
		int b;
	} __in;
	int x;
	int y;
};

void foo(struct in *in)
{
	in->a = 1;
	in->b = 1;
	in->a = 2;
	in->b = 2;
}

int main()
{
	struct out o = {0, };

	foo(&o.__in);
	return 0;
}
