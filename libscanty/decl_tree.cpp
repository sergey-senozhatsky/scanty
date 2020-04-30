// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#include <stdlib.h>
#include <logger.h>
#include <decl_tree.h>
#include <stack>
#include <configuration.h>
#include <protocol.h>

using namespace std;

static struct decl_tree tree_root = {
	.num_loads	= 0,
	.num_stores	= 0,
	.node_type	= DECL_NODE_RECORD_TYPE,
};

static struct decl_tree parm_tree_root = {
	.num_loads	= 0,
	.num_stores	= 0,
	.node_type	= DECL_NODE_FUNCTION_TYPE,
};

static struct decl_tree gimple_tree_root = {
	.num_loads	= 0,
	.num_stores	= 0,
	.node_type	= DECL_NODE_FUNCTION_TYPE,
};

static struct decl_tree *get_tree_root(struct decl_chain *chain)
{
	if (chain->flags & CF_RECORD_CALLER)
		return &parm_tree_root;
	return &tree_root;
}

static void walk_decl_chain(struct decl_chain *chain,
			    const char *prefix)
{
	auto iter = chain->chain.begin();
	string chain_str;

	for (auto &iter : chain->chain) {
		struct decl_node *node = iter;

		chain_str += " ";
		chain_str += node->type_name.c_str();
	}

	pr_info("decl_chain:: %s%s\n", prefix, chain_str.c_str());
}

void debug_walk_decl_tree(struct decl_tree *tree)
{
	if (!tree)
		tree = &tree_root;
	serialize_decl_tree_to_stdout(tree);
}

void debug_walk_call_tree(struct decl_tree *tree)
{
	if (!tree)
		tree = &gimple_tree_root;
	serialize_decl_tree_to_stdout(tree);
}

void decl_tree_stdout_dump(void)
{
	serialize_decl_tree_to_stdout(&tree_root);
}

proto_payload *decl_tree_to_protocol_representation(void)
{
	return serialize_decl_tree(&tree_root);
}

proto_payload *decl_name_to_protocol_representation(std::string &decl_name)
{
	struct decl_tree *tree;

	if (tree_root.fields.find(decl_name) == tree_root.fields.end())
		return serialize_decl_tree(NULL);
	return serialize_decl_name(tree_root.fields[decl_name],
				   decl_name.c_str());
}

int decl_tree_from_protocol_representation(proto_payload *payload)
{
	return deserialize_decl_tree(payload);
}

void lock_decl_tree(struct decl_tree *tree)
{
	tree->lock.lock();
}

void unlock_decl_tree(struct decl_tree *tree)
{
	tree->lock.unlock();
}

static struct decl_tree *__lookup_tree(struct decl_tree *parent,
				       struct decl_node *node)
{
	struct decl_tree *field = NULL;

	if (parent->fields.find(node->type_name) != parent->fields.end())
		field = parent->fields[node->type_name];
	return field;
}

static struct decl_tree *lookup_tree(struct decl_tree *parent,
				     struct decl_node *node)
{
	struct decl_tree *field = NULL;

	lock_decl_tree(parent);
	field = __lookup_tree(parent, node);
	unlock_decl_tree(parent);
	return field;
}

static struct decl_tree *alloc_decl_tree(void)
{
	struct decl_tree *tree;

	tree = new(std::nothrow) struct decl_tree;
	if (!tree)
		return NULL;

	tree->num_loads		= 0;
	tree->num_stores	= 0;
	tree->node_type		= DECL_NODE_INVALID_TYPE;
	return tree;
}

struct decl_node *alloc_decl_node(void)
{
	struct decl_node *node;

	node = new(std::nothrow) struct decl_node;
	if (!node)
		return NULL;

	node->type_name		= DECL_NODE_INVALID_TYPE_NAME;
	node->type		= DECL_NODE_INVALID_TYPE;
	node->hash		= DECL_NODE_INVALID_HASH;
	node->num_loads		= 0;
	node->num_stores	= 0;
	return node;
}

void free_decl_node(struct decl_node *node)
{
	delete node;
}

struct decl_chain *alloc_decl_chain(int flags)
{
	struct decl_chain *chain;

	chain = new(std::nothrow) struct decl_chain;
	if (chain)
		chain->flags = flags;
	return chain;
}

void free_decl_chain(struct decl_chain *chain)
{
	while (!chain->chain.empty()) {
		struct decl_node *node;

		node = chain->chain.back();
		chain->chain.pop_back();
		free_decl_node(node);
	}

	delete chain;
}

static bool check_known_typedecl(struct decl_chain *chain,
				 int type,
				 unsigned long long hash)
{
	if (type == DECL_NODE_FIELD_TYPE)
		return false;

	if (chain->types.find(hash) != chain->types.end()) {
		if (trace_decl_tree())
			pr_err("node is already in the chain\n");
		return true;
	}
	return false;
}

int chain_decl_node(struct decl_chain *chain, struct decl_node *node)
{
	if (trace_decl_tree())
		pr_info("chain parse node: %s [%llu]\n",
			node->type_name.c_str(), node->hash);

	if (chain->flags == CF_CHECK_RECURSIVE_DECL) {
		if (check_known_typedecl(chain, node->type, node->hash))
			return -EEXIST;

		chain->types.insert(node->hash);
	}

	chain->chain.push_back(node);
	return 0;
}

int chain_end_of_type_decl(struct decl_chain *chain)
{
	struct decl_node *node = alloc_decl_node();

	if (!node)
		return -ENOMEM;
	node->type_name = DECL_NODE_END_OF_DECL_TYPE_NAME;
	node->type = DECL_NODE_END_OF_DECL_TYPE;
	node->tree = NULL;
	chain->chain.push_back(node);

	if (trace_decl_tree())
		pr_info("chain parse node: %s\n", node->type_name.c_str());
	return 0;
}

static void decl_tree_update_counters(struct decl_tree *current,
				      unsigned int num_stores,
				      unsigned int num_loads)
{
	lock_decl_tree(current);
	current->num_stores	+= num_stores;
	current->num_loads	+= num_loads;
	unlock_decl_tree(current);
}

static struct decl_tree *insert_decl_node(struct decl_tree *parent,
					  struct decl_node *node)
{
	struct decl_tree *tree;

	lock_decl_tree(parent);
	tree = __lookup_tree(parent, node);
	if (tree)
		goto out;

	tree = alloc_decl_tree();
	if (!tree)
		goto out;

	tree->node_type			= node->type;
	parent->fields[node->type_name]	= tree;
out:
	unlock_decl_tree(parent);

	if (tree)
		decl_tree_update_counters(tree,
					  node->num_stores,
					  node->num_loads);
	return tree;
}

static int __parse_field_decl_chain(struct decl_chain *chain,
				    struct decl_tree *parent,
				    list<struct decl_node *>::iterator &iter)
{
	struct decl_tree *current = NULL;
	struct decl_tree *sub_parent = NULL;

	if (parent == NULL)
		return -ENOMEM;

	while (iter != chain->chain.end()) {
		struct decl_node *node = *iter;

		iter++;
		if (node->type == DECL_NODE_END_OF_DECL_TYPE)
			return 0;

		current = lookup_tree(parent, node);
		if (current) {
			decl_tree_update_counters(current,
						  node->num_stores,
						  node->num_loads);
			if (node->type == DECL_NODE_FIELD_TYPE)
				continue;
			if (__parse_field_decl_chain(chain, current, iter))
				return -EINVAL;
			continue;
		}

		if (node->type == DECL_NODE_FIELD_TYPE) {
			if (insert_decl_node(parent, node) == NULL)
				return -ENOMEM;
			continue;
		}

		sub_parent = insert_decl_node(parent, node);
		if (__parse_field_decl_chain(chain, sub_parent, iter))
			return -ENOMEM;
	}
	return 0;
}

static int chain_caller_id(struct decl_chain *chain)
{
	struct decl_node *node;

	if (!(chain->flags & CF_RECORD_CALLER))
		return 0;
	if (chain->flags & CF_RECORD_CALLER_DONE)
		return 0;
	if (chain->chain.empty())
		return 0;

	node = alloc_decl_node();
	if (!node)
		return -ENOMEM;

	node->type_name = chain->caller_id;
	node->type = DECL_NODE_CALLER_TYPE;
	node->tree = chain->caller_block;
	chain->flags |= CF_RECORD_CALLER_DONE;
	chain->chain.push_front(node);
	return 0;
}

static int chain_callee_id(struct decl_chain *chain)
{
	struct decl_node *node;

	if (!(chain->flags & CF_RECORD_CALLEE))
		return 0;
	if (chain->flags & CF_RECORD_CALLEE_DONE)
		return 0;
	if (chain->chain.empty())
		return 0;

	node = alloc_decl_node();
	if (!node)
		return -ENOMEM;

	node->num_loads++;
	node->type_name = chain->callee_id;
	node->type = DECL_NODE_CALLEE_TYPE;
	node->tree = chain->callee_block;
	chain->flags |= CF_RECORD_CALLEE_DONE;
	chain->chain.push_front(node);
	return 0;
}

static int new_type_chain(struct decl_chain *chain)
{
	struct decl_tree *parent = get_tree_root(chain);
	list<struct decl_node *>::iterator iter;

	chain_callee_id(chain);
	chain_caller_id(chain);
	iter = chain->chain.begin();

	if (trace_decl_tree())
		walk_decl_chain(chain, "new_type_decl chain::");

	return __parse_field_decl_chain(chain, parent, iter);
}

static int __ld_st_chain(struct decl_tree *parent,
			 struct decl_chain *chain,
			 const char *prefix)
{
	struct decl_tree *current = NULL;
	auto iter = chain->chain.begin();

	if (chain->chain.empty())
		return DECL_TREE_OK;

	if (trace_decl_tree())
		walk_decl_chain(chain, prefix);

	while (iter != chain->chain.end()) {
		struct decl_node *node = *iter;

		current = lookup_tree(parent, node);
		if (!current) {
			if (trace_decl_tree())
				pr_err("Unknown decl_node: %s\n",
					node->type_name.c_str());
			return DECL_TREE_UNKNOWN_TYPE;
		}
		parent = current;
		iter++;
	}

	if (chain->flags & CF_OP_LHS)
		decl_tree_update_counters(current, 1, 0);
	else if (chain->flags & CF_OP_RHS)
		decl_tree_update_counters(current, 0, 1);
	else
		pr_err("Unknown chain op\n");
	return DECL_TREE_OK;
}

static int ld_st_chain(struct decl_chain *chain)
{
	struct decl_tree *parent = get_tree_root(chain);

	chain_callee_id(chain);
	chain_caller_id(chain);
	return __ld_st_chain(parent, chain, "ld_st chain::");
}

static int parm_ld_st_chain(struct decl_chain *chain)
{
	struct decl_tree *parent = get_tree_root(chain);

	chain_callee_id(chain);
	chain_caller_id(chain);
	return __ld_st_chain(parent, chain, "parm ld_st chain::");
}

static int gimple_call_chain(struct decl_chain *chain)
{
	struct decl_tree *parent = &gimple_tree_root;
	list<struct decl_node *>::iterator iter;

	chain_callee_id(chain);
	chain_caller_id(chain);
	iter = chain->chain.begin();

	if (trace_decl_tree())
		walk_decl_chain(chain, "call chain::");

	return __parse_field_decl_chain(chain, parent, iter);
}

static int dummy_chain(struct decl_chain *chain)
{
	if (trace_decl_tree())
		walk_decl_chain(chain, "dummy chain::");

	pr_err("Dummy chain parser\n");
	return DECL_TREE_OK;
}

void *decl_chain_get_type(struct decl_chain *chain)
{
	auto &iter = chain->chain.front();
	struct decl_node *node = iter;

	return node->tree;
}

int decl_chain_lookup_parm(struct decl_chain *chain)
{
	struct decl_tree *parent;
	struct decl_node *node;

	if (parm_tree_root.fields.find(chain->caller_id) ==
					parm_tree_root.fields.end())
		return -EINVAL;

	node = chain->chain.back();
	parent = parm_tree_root.fields[chain->caller_id];

	if (parent->fields.find(node->type_name) == parent->fields.end())
		return -EINVAL;
	return 0;
}

void decl_chain_set_format(struct decl_chain *chain, int format)
{
	chain->flags |= format;

	if (format == CF_FORMAT_NEW_TYPE) {
		chain->parse = new_type_chain;
		return;
	}

	if (format == CF_FORMAT_LD_ST) {
		chain->parse = ld_st_chain;
		return;
	}

	if (format == CF_FORMAT_PARM_LD_ST) {
		chain->flags |= CF_RECORD_CALLER;
		chain->parse = parm_ld_st_chain;
		return;
	}

	if (format == CF_FORMAT_GIMPLE_CALL) {
		chain->flags |= CF_RECORD_CALLER;
		chain->flags |= CF_RECORD_CALLEE;
		chain->parse = gimple_call_chain;
		return;
	}

	pr_err("Unknown chain format: %d\n", format);
	chain->parse = dummy_chain;
}

void decl_chain_set_op(struct decl_chain *chain, int op)
{
	chain->flags |= op;
	if (!(op & (CF_OP_LHS | CF_OP_RHS |
		CF_RECORD_CALLER | CF_RECORD_CALLEE)))
		pr_err("Unknown chain op: %d\n", op);
}

void decl_chain_set_caller(struct decl_chain *chain,
			   std::string caller_id,
			   void *block)
{
	chain->caller_id	= caller_id;
	chain->caller_block	= block;
}

void decl_chain_set_callee(struct decl_chain *chain,
			   std::string callee_id,
			   void *block)
{
	chain->callee_id	= callee_id;
	chain->callee_block	= block;
}
bool decl_chain_is_parm_decl(struct decl_chain *chain)
{
	return chain->flags & CF_RECORD_CALLER;
}
