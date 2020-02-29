typedef long int __fd_mask;

typedef struct
{
	__fd_mask fds_bits[32];
} fd_set;

int main()
{
	fd_set test;

	test.fds_bits[1] = 0x00;
	return 0;
}
