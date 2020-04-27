// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#ifndef __DECL_TREE_H
#define __DECL_TREE_H 1

#include <unordered_map>
#include <unordered_set>
#include <list>
#include <string>
#include <protocol.h>
#include <mutex>

#define DECL_NODE_INVALID_TYPE_NAME		"<invalid>"
#define DECL_NODE_END_OF_DECL_TYPE_NAME		"<end_of_decl_type>"
#define DECL_NODE_INVALID_HASH			((size_t)-1)

enum DECL_NODE_TYPE {
	DECL_NODE_INVALID_TYPE,
	DECL_NODE_RECORD_TYPE,
	DECL_NODE_UNION_TYPE,
	DECL_NODE_FIELD_TYPE,
	DECL_NODE_END_OF_DECL_TYPE,
};

#define PARSE_ASSIGN_OP_LHS		0
#define PARSE_ASSIGN_OP_RHS		1

enum DECL_TREE_RET {
	DECL_TREE_OK,
	DECL_TREE_UNKNOWN_TYPE,
};

struct decl_node {
	std::string				type_name;
	int					type;
	void					*tree;
	size_t					hash;
	unsigned int				num_loads;
	unsigned int				num_stores;
};

#define CF_CHECK_RECURSIVE_DECL		(0)
#define CF_DONT_CHECK_RECURSIVE_DECL	(1 << 0)
#define CF_FORMAT_LD_ST			(1 << 1)
#define CF_FORMAT_PARM_LD_ST		(1 << 2)
#define CF_FORMAT_NEW_TYPE		(1 << 3)
#define CF_OP_LHS			(1 << 4)
#define CF_OP_RHS			(1 << 5)

struct decl_chain {
	std::list<struct decl_node *>		chain;
	std::unordered_set<unsigned long long>	types;
	std::string				block_id;
	int					flags;
	void					*block;
	int (*parse)(struct decl_chain *chain);
};

/*
 * A recursive structure:
 * each RECORD keeps its fields in a hashtable, each field
 * can be a RECORD.
 */
struct decl_tree {
	std::unordered_map<std::string, struct decl_tree *>	fields;
	std::mutex						lock;

	/* number of times this field was RHS, approx */
	unsigned int						num_loads;
	/* number of times this field was LHS, approx */
	unsigned int						num_stores;

	int							node_type;
};

void debug_walk_decl_tree(struct decl_tree *tree);

struct decl_node *alloc_decl_node(void);
void free_decl_node(struct decl_node *node);

struct decl_chain *alloc_decl_chain(int flags);
void free_decl_chain(struct decl_chain *chain);

void decl_chain_set_format(struct decl_chain *chain, int format);
void decl_chain_set_op(struct decl_chain *chain, int op);
void decl_chain_set_block(struct decl_chain *chain,
			  std::string block_id,
			  void *block);

int chain_decl_node(struct decl_chain *chain, struct decl_node *node);
int chain_end_of_type_decl(struct decl_chain *chain);

void *decl_chain_get_type(struct decl_chain *chain);

proto_payload *decl_tree_to_protocol_representation(void);
proto_payload *decl_name_to_protocol_representation(std::string &decl_name);
int decl_tree_from_protocol_representation(proto_payload *payload);

void lock_decl_tree(struct decl_tree *tree);
void unlock_decl_tree(struct decl_tree *tree);

void decl_tree_stdout_dump(void);
#endif /* __DECL_TREE_H */
