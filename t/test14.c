struct lock1 {
	int locked;
};

struct lock2 {
	int locked;
	int num_waiters;
};

static int spin_lock(struct lock1 *l)
{
	while (l->locked);
	l->locked = 1;
}

static int spin_unlock(struct lock1 *l)
{
	l->locked = 0;
}

static int spin_lock_irqsave(struct lock1 *l, unsigned long *flags)
{
	*flags = 0x01;
	while (l->locked);
	l->locked = 1;
}

static int spin_unlock_irqrestore(struct lock1 *l, unsigned long flags)
{
	l->locked = 0;
}

static int up(struct lock2 *l)
{
	l->num_waiters++;
	while (l->locked);
	l->num_waiters--;
	l->locked = 1;
}

static int down(struct lock2 *l)
{
	l->locked = 0;
}

struct mmu {
	int a,b,c;
};

static void test(struct mmu *mmu)
{
	unsigned long flags;
	struct lock1 l1 = {0, };

	spin_lock_irqsave(&l1, &flags);
	mmu->a = 1;
	spin_unlock_irqrestore(&l1, flags);
}

int main()
{
	struct lock1 l1 = {0, };
	struct lock2 l2 = {0, };
	unsigned long flags = 0;
	struct mmu mmu;

	spin_lock(&l1);
	spin_lock(&l1);

	spin_unlock_irqrestore(&l1, flags);
	down(&l2);

	test(&mmu);
	return 0;
}
