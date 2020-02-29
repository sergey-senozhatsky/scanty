struct foo {
	union {
		struct {
			int bar;
		};
	};

	union {
		struct {
			int buz;
		};
	};
};

int main()
{
	struct foo f;

	f.bar = 0x1;
	f.buz = 0x2;
	return 0;
}
