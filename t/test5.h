#ifndef __TEST5__
#define __TEST5__

struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

struct rb_root {
	struct rb_node *rb_node;
};


struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

#define INIT_CACHE(r)				\
	do {					\
		(r).rb_leftmost 	= NULL;	\
		(r).rb_root.rb_node	= NULL;	\
	} while (0)

#endif /* __TEST5__ */
