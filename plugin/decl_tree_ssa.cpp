// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#include <unordered_map>
#include <stdlib.h>
#include <logger.h>
#include <decl_tree_ssa.h>

using namespace std;

static unordered_map<unsigned long, struct ssa_node *>	ssa_tree;

#define SSA_NODE_KEY(n)		((unsigned long)(n))

static struct ssa_node *alloc_ssa_node(void)
{
	struct ssa_node *node;

	node = new(std::nothrow) struct ssa_node;
	if (!node)
		return NULL;

	node->type = SSA_NODE_TYPE_INVALID;
	return node;
}

static struct ssa_node *lookup_ssa_node(unsigned long key)
{
	return ssa_tree[key];
}

static struct ssa_node *get_ssa_node(unsigned long key)
{
	if (ssa_tree.find(key) == ssa_tree.end())
		ssa_tree[key] = alloc_ssa_node();

	return ssa_tree[key];
}

static int chain_ssa_rhs(struct ssa_node *lssa, tree rop)
{
	struct ssa_node *rssa;

	if (rop == NULL_TREE)
		return -EINVAL;

	rssa = get_ssa_node(SSA_NODE_KEY(rop));
	if (!rssa)
		return -ENOMEM;

	if (TREE_CODE(rop) == SSA_NAME) {
		rssa->type = SSA_NODE_TYPE_INNER;
	} else {
		rssa->type = SSA_NODE_TYPE_LEAF;
		rssa->op = rop;
	}

	lssa->chain.push_back(SSA_NODE_KEY(rop));
	return 0;
}

int parse_gimple_assign_ssa_lhs(tree op, gimple stmt)
{
	struct ssa_node *lssa;
	int ret;

	lssa = get_ssa_node(SSA_NODE_KEY(op));
	if (!lssa)
		return -ENOMEM;

	switch (gimple_assign_rhs_class(stmt)) {
	case GIMPLE_SINGLE_RHS:
		ret = chain_ssa_rhs(lssa, gimple_assign_rhs1(stmt));
		break;
	case GIMPLE_BINARY_RHS:
		ret = chain_ssa_rhs(lssa, gimple_assign_rhs1(stmt));
		ret |= chain_ssa_rhs(lssa, gimple_assign_rhs2(stmt));
		break;
	case GIMPLE_TERNARY_RHS:
		ret = chain_ssa_rhs(lssa, gimple_assign_rhs1(stmt));
		ret |= chain_ssa_rhs(lssa, gimple_assign_rhs2(stmt));
		ret |= chain_ssa_rhs(lssa, gimple_assign_rhs3(stmt));
		break;
	case GIMPLE_UNARY_RHS:
		break;
	default:
		pr_err("Unknown rhs class: %d\n",
			gimple_assign_rhs_class(stmt));
		return -EINVAL;
	}
	return ret;
}

static int __for_each_ssa_leaf(gimple stmt,
			       unsigned long key,
			       int (*cb)(gimple, tree, int),
			       int dir)
{
	struct ssa_node *ssa = lookup_ssa_node(key);
	int ret;

	if (!ssa)
		return -EINVAL;

	if (ssa->type == SSA_NODE_TYPE_LEAF)
		return cb(stmt, ssa->op, dir);

	for (auto &n : ssa->chain) {
		ret = __for_each_ssa_leaf(stmt, n, cb, dir);
		if (ret)
			return ret;
	}
	return 0;
}

int for_each_ssa_leaf(gimple stmt,
		      tree op,
		      int (*cb)(gimple, tree, int),
		      int dir)
{
	if (op == NULL_TREE)
		return -EINVAL;

	if (TREE_CODE(op) != SSA_NAME)
		return cb(stmt, op, dir);

	return __for_each_ssa_leaf(stmt, SSA_NODE_KEY(op), cb, dir);
}
