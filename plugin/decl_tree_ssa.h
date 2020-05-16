// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#ifndef __PARSE_TREE_SSA_H
#define __PARSE_TREE_SSA_H 1

#include <gcc-common.h>
#include <list>

enum SSA_NODE_TYPE {
	SSA_NODE_TYPE_INVALID,
	SSA_NODE_TYPE_INNER,
	SSA_NODE_TYPE_LEAF,
};

struct ssa_node {
	int				type;

	tree				op;
	std::list<unsigned long>	chain;
};

int parse_gimple_assign_ssa_lhs(tree lop, gimple stmt);
int for_each_ssa_leaf(gimple stmt,
		      tree op,
		      int (*cb)(gimple, tree, int),
		      int dir);

bool artificial_node(tree op);

#endif /* __PARSE_TREE_SSA_H */
