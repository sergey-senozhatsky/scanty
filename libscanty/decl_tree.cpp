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
		pr_err("chain parse node: %s [%llu]\n",
			node->type_name.c_str(), node->hash);

	if (chain->flags == VERIFY_RECURSIVE_DECL_TYPE) {
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
		pr_err("chain parse node: %s\n", node->type_name.c_str());
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

int parse_field_decl_chain(struct decl_chain *chain)
{
	struct decl_tree *parent = &tree_root;
	auto iter = chain->chain.begin();

	if (trace_decl_tree())
		walk_decl_chain(chain, "field_decl chain::");

	return __parse_field_decl_chain(chain, parent, iter);
}

enum DECL_TREE_RET parse_gimple_assign_chain(struct decl_chain *chain,
					     int dir)
{
	struct decl_tree *parent = &tree_root, *current = NULL;
	auto iter = chain->chain.begin();

	if (chain->chain.empty())
		return DECL_TREE_OK;

	if (trace_decl_tree())
		walk_decl_chain(chain, "gimple_assign chain::");

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

	if (dir == PARSE_ASSIGN_OP_DIR_LHS)
		decl_tree_update_counters(current, 1, 0);
	else
		decl_tree_update_counters(current, 0, 1);
	return DECL_TREE_OK;
}

void *decl_chain_get_type(struct decl_chain *chain)
{
	struct decl_node *node = chain->chain.front();

	return node->tree;
}
