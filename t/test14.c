#include <stddef.h>

struct raw_lock1 {
	int locked;
};

struct lock1 {
	struct raw_lock1 rlock;
};

struct lock2 {
	int locked;
	int num_waiters;
};

static inline struct raw_lock1 *check_lock(struct lock1 *l,
					   int *just_for_gimple)
{
	return &l->rlock;
}

static int spin_lock(struct raw_lock1 *l)
{
	while (l->locked);
	l->locked = 1;
}

static int spin_unlock(struct raw_lock1 *l)
{
	l->locked = 0;
}

static int spin_lock_irqsave(struct raw_lock1 *l, unsigned long *flags)
{
	*flags = 0x01;
	while (l->locked);
	l->locked = 1;
}

static int spin_unlock_irqrestore(struct raw_lock1 *l, unsigned long flags)
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

struct vma {
	struct vma	*next, *prev;
	struct lock1	l1;
};

struct mmu {
	int		a;
	struct vma	vma;
};

static void test(struct mmu *mmu)
{
	unsigned long flags;

	spin_lock_irqsave(check_lock(&mmu->vma.l1, NULL), &flags);
	mmu->a = 1;
	spin_unlock_irqrestore(check_lock(&mmu->vma.l1, NULL), flags);
}

int main()
{
	struct lock1 l1 = {0, };
	struct lock2 l2 = {0, };
	unsigned long flags = 0;
	struct mmu mmu = {0, };

	spin_lock(check_lock(&l1, NULL));
	spin_lock(check_lock(&l1, NULL));

	spin_unlock_irqrestore(check_lock(&l1, NULL), flags);
	down(&l2);

	test(&mmu);
	return 0;
}
