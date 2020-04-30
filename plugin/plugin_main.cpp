// SPDX-License-Identifier: GPL-2.0-only

/*
 * POC GCC plugin.
 *
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#include <gcc-common.h>
#include <logger.h>
#include <decl_tree.h>
#include <decl_tree_ssa.h>
#include <configuration.h>
#include <transport.h>

using namespace std;

struct walk_stmt_info;
static tree callback_stmt(gimple_stmt_iterator *gsi,
			  bool *handled_all_ops,
			  struct walk_stmt_info *wi);
static tree callback_op(tree *tree, int *walk_subtrees, void *data);
static unsigned int scanty_execute(function *fun);

#define PASS_NAME scanty
#define NO_GATE
#include <gcc-generate-gimple-pass.h>

int plugin_is_GPL_compatible;

static struct plugin_info scanty_plugin_info = {
	.version	= "2020",
	.help		= "scanty plugin\n",
};

/*
 * @FIXME workaroud, rework this later
 */
static std::unordered_set<std::string> lock_fns = {
	"spin_lock", "spin_unlock",
	"spin_lock_irqsave", "spin_unlock_irqrestore",
	"up", "down",
	"mutex_lock", "mutex_unlock",
	"rcu_read_lock", "rcu_read_unlock",
	"read_trylock", "write_trylock",
	"read_lock", "write_lock",
	"read_unlock", "write_unlock",
	"read_unlock_irq", "write_unlock_irq",
	"read_lock_irq", "write_lock_irq",
	"read_lock_bh", "write_lock_bh",
	"read_unlock_bh", "write_unlock_bh",
	"read_lock_irqsave", "write_lock_irqsave",
	"read_unlock_irqresore", "write_unlock_irqestore"
};

static void __BUG(const char *msg, tree op)
{
	static volatile int *crash = NULL;

	pr_err("\n\n BUG :: BUG :: BUG :: BUG :: %s\n\n", msg);
	if (op && op != NULL_TREE)
		debug_tree(op);
	*crash = 0xdead;
}

/*
 * When field declaration is also a type declaration:
 *
 * struct foo {
 * 	struct bar {
 * 		int a;
 * 	} buz;
 * };
 */
static bool field_decl_is_type_decl(tree field)
{
	if (TREE_TYPE(field) == NULL_TREE)
		return false;

	return RECORD_OR_UNION_TYPE_P(TREE_TYPE(field));
}

static tree get_field_tree_type(tree field)
{
	if (RECORD_OR_UNION_TYPE_P(field))
		return field;
	if (POINTER_TYPE_P(TREE_TYPE(field)))
		field = TREE_TYPE(field);
	return TREE_TYPE(field);
}

static tree field_type_decl(tree field)
{
	field = get_field_tree_type(field);
	if (field == NULL_TREE)
		return NULL_TREE;

	if (!TYPE_NAME(field))
		return NULL_TREE;

	field = TYPE_NAME(field);
	if (field == NULL_TREE)
		return NULL_TREE;

	if (TREE_CODE(field) == IDENTIFIER_NODE)
		return field;

	return DECL_NAME(field);
}

static const char *field_identifier_pointer(tree field)
{
	static char fixup_name[128] = {0, };

	if (field == NULL_TREE) {
		snprintf(fixup_name, sizeof(fixup_name) - 1, "<null_tree>");
		return fixup_name;
	}
	if (!IDENTIFIER_POINTER(field)) {
		snprintf(fixup_name, sizeof(fixup_name) - 1, "<invalid node>");
		return fixup_name;
	}
	return IDENTIFIER_POINTER(field);
}

/*
 * There can be multiple anon RECORD_OR_UNION fields, each of them can
 * can have multiple nested anon RECORD_OR_UNION field_decls. Consider
 * the following case:
 *
 * struct foo {
 * 	union {
 * 		struct {
 * 			int bar;
 * 		};
 * 	};
 * 	union {
 * 		struct {
 * 			int buz;
 * 		};
 * 	};
 * };
 *
 * We need to generate unique names. So what is happening here - we walk
 * recursively such field_decls and generate hash based on collected
 * field_decl names.
 *
 * This might be hacky and maybe we need to do something better here.
 */
static void walk_anon_subtype_fields(tree arg, string &fields)
{
	for (tree field = TYPE_FIELDS(arg); field; field = TREE_CHAIN(field)) {
		if (field == NULL_TREE)
			continue;

		fields += field_identifier_pointer(DECL_NAME(field));

		if (TREE_TYPE(field) &&
			RECORD_OR_UNION_TYPE_P(TREE_TYPE(field))) {
			walk_anon_subtype_fields(TREE_TYPE(field), fields);
			continue;
		}
	}
}

static void walk_anon_type_fields(tree arg, std::string &name, size_t &hash)
{
	char fixup[64];
	string fields;
	tree ori;

	if (!RECORD_OR_UNION_TYPE_P(arg))
		arg = get_field_tree_type(arg);

	if (arg == NULL_TREE)
		return;

	walk_anon_subtype_fields(arg, fields);
	hash = std::hash<std::string>{}(fields);
	sprintf(fixup, "<anon::0x%lx>", hash);
	name = fixup;
}

static int chain_append_field(struct decl_chain *chain, tree arg, int type)
{
	struct decl_node *node;
	string name;
	size_t hash;
	int ret;

	if (EXCEPTIONAL_CLASS_P(arg)) {
		__BUG("Exceptional field", arg);
		return -EINVAL;
	}

	if (RECORD_OR_UNION_TYPE_P(arg) || field_decl_is_type_decl(arg)) {
		tree type_field;

		type_field = field_type_decl(arg);

		if (type_field == NULL_TREE) {
			walk_anon_type_fields(arg, name, hash);
		} else {
			name = field_identifier_pointer(type_field);
			hash = IDENTIFIER_HASH_VALUE(type_field);
		}
	}

	if (name.empty()) {
		if (TREE_CODE(arg) == IDENTIFIER_NODE && TYPE_NAME(arg)) {
			name = field_identifier_pointer(TYPE_NAME(arg));
			hash = IDENTIFIER_HASH_VALUE(TYPE_NAME(arg));
		} else if (DECL_NAME(arg)) {
			name = field_identifier_pointer(DECL_NAME(arg));
			hash = IDENTIFIER_HASH_VALUE(DECL_NAME(arg));
		}
	}

	if (name.empty()) {
		name = DECL_NODE_INVALID_TYPE_NAME;
		hash = 0x00;
		if (trace_debug_tree())
			debug_tree(arg);
	}

	node = alloc_decl_node();
	if (!node)
		return -ENOMEM;

	node->type_name	= name;
	node->tree	= arg;
	node->type	= type;
	node->hash	= hash;

	ret = chain_decl_node(chain, node);
	if (ret)
		free_decl_node(node);
	return ret;
}

static int tree_arg_type(tree field)
{
	int type;
	tree fixup;

	if (field == NULL_TREE)
		return DECL_NODE_INVALID_TYPE;

	if (trace_debug_tree())
		debug_tree(field);

	switch (TREE_CODE(field)) {
	case UNION_TYPE:
		return DECL_NODE_UNION_TYPE;
	case RECORD_TYPE:
		return DECL_NODE_RECORD_TYPE;
	case POINTER_TYPE:
		return DECL_NODE_FIELD_TYPE;
	}

	/*
	 * FIELD_DECL can actually declare both FIELD and TYPE - i.e.
	 * a union or a struct inside of a union or a struct.
	 *
	 * Example:
	 *
	 * struct buzz {
	 * 	...
	 * 	struct __buzz_internal {
	 * 		union {
	 * 			int     __buzz_internal__a;
	 * 			int     __buzz_internal__b;
	 * 		} __buzz_internal_union;
	 * 	} __internal_struct;
	 * 	...
	 * };
	 *
	 * For which we will see the following tree node:
	 *
	 *  <field_decl 0x7f2dba32fd10 __internal_struct
	 *  	type <record_type 0x7f2dba32df18 __buzz_internal ...
	 *  		size <integer_cst 0x7f2dba95d0d8 constant 32>
	 *  		unit-size <integer_cst 0x7f2dba95d0f0 constant 4>
	 *  	...
	 */
	type = DECL_NODE_FIELD_TYPE;
	if (!field_decl_is_type_decl(field))
		return type;

	fixup = TREE_TYPE(field);
	if (fixup != NULL_TREE)
		type = tree_arg_type(fixup);
	return type;
}

static int decl_tree_operand_list(struct decl_chain *chain, tree node);

static int parse_var_decl_arg(struct decl_chain *chain, tree arg)
{
	tree node;
	int type;

	if (TREE_TYPE(arg) == NULL_TREE)
		return -EINVAL;

	node = get_field_tree_type(arg);
	if (node == NULL_TREE)
		return -EINVAL;

	if (!RECORD_OR_UNION_TYPE_P(node))
		return -EINVAL;
	type = tree_arg_type(arg);
	return chain_append_field(chain, node, type);
}

static int parse_parm_decl_arg(struct decl_chain *chain, tree arg)
{
	tree node;
	int type;

	if (TREE_TYPE(arg) == NULL_TREE)
		return -EINVAL;

	if (!POINTER_TYPE_P(TREE_TYPE(arg)))
		return parse_var_decl_arg(chain, arg);

	node = get_field_tree_type(arg);
	if (node == NULL_TREE)
		return -EINVAL;

	if (!RECORD_OR_UNION_TYPE_P(node))
		return -EINVAL;

	decl_chain_set_format(chain, CF_FORMAT_PARM_LD_ST);
	type = tree_arg_type(arg);
	return chain_append_field(chain, node, type);
}

static int parse_field_decl_arg(struct decl_chain *chain, tree arg)
{
	tree node;
	int type;

	type = tree_arg_type(arg);
	return chain_append_field(chain, arg, type);
}

static int decl_tree_operand(struct decl_chain *chain, tree arg)
{
	if (arg == NULL_TREE)
		return 0;

	if (TREE_CODE(arg) == PARM_DECL)
		return parse_parm_decl_arg(chain, arg);

	if (TREE_CODE(arg) == VAR_DECL)
		return parse_var_decl_arg(chain, arg);

	if (TREE_CODE(arg) == FIELD_DECL)
		return parse_field_decl_arg(chain, arg);

	/*
	 * Example:
	 *
	 *  <component_ref 0x7f2f14565db0
	 *  	type <union_type 0x7f2f1458cbd0 ._anon_21 sizes-gimplified ...
	 *  ...
	 *  arg:0 <mem_ref 0x7f2f1458df78
	 *  	type <record_type 0x7f2f1458c930 buzz sizes-gimplified ...
	 *  		arg:0 <var_decl 0x7f2f14566ab0 b3 type <pointer_type 0x7f2f1458cd20>
	 *  		...
	 *  		arg:1 <integer_cst 0x7f2f145992b8 constant 0>
	 *  		...
	 *  arg:1 <field_decl 0x7f2f1458e688 D.3743 type <union_type 0x7f2f1458cbd0 ._anon_21>
	 *  ...
	 */
	if (TREE_CODE(arg) == COMPONENT_REF)
		return decl_tree_operand_list(chain, arg);

	/*
	 * Example:
	 *
	 *  <mem_ref 0x7f0122323438
	 *  	type <record_type 0x7f012230f930 buzz ...
	 *  ...
	 *  	arg:0 <var_decl 0x7f01222e9c60 b3
	 *  		type <pointer_type 0x7f012230fd20 type <record_type 0x7f012230f930 buzz>
	 *  		...
	 *  	arg:1 <integer_cst 0x7f012231e318 type <pointer_type 0x7f012230fd20> constant 0>
	 *  ...
	 */
	if (TREE_CODE(arg) == MEM_REF)
		return decl_tree_operand_list(chain, arg);
	return 0;
}

static int __decl_tree_operand_list(struct decl_chain *chain, tree node)
{
	int len, i, ret;

	len = TREE_OPERAND_LENGTH(node);
	for (i = 0; i < len; i++) {
		tree op = TREE_OPERAND(node, i);

		if (op == NULL_TREE)
			break;

		if (EXCEPTIONAL_CLASS_P(op)) {
			//__BUG("Exceptional tree_operand", op);
			break;
		}

		ret = decl_tree_operand(chain, op);
		if (ret)
			return ret;
	}
	return 0;
}

static int decl_tree_operand_list(struct decl_chain *chain, tree node)
{
	if (node == NULL_TREE)
		return 0;

	if (TREE_CODE(node) == VAR_DECL)
		return decl_tree_operand(chain, node);

	return __decl_tree_operand_list(chain, node);
}

/*
 * This not only constructs the type, but also unfolds it recursive.
 * For instance, for
 *
 * struct task_struct {
 * ...
 * 	struct sched_entity se;
 * ...
 * };
 *
 * will be parsed to
 *
 * struct task_struct {
 * ...
 * 	struct sched_entity
 * 		struct sched_avg
 * 			struct util_est
 * 				field ewma
 * 				field enqueued
 * 			field util_avg
 * 			field period_contrib
 * 			...
 * ...
 * };
 */
static int __construct_new_type(struct decl_chain *chain, tree arg)
{
	int node_type, ret;
	tree field, type;

	if (arg == NULL_TREE || arg == error_mark_node)
		return 0;

	type = get_field_tree_type(arg);
	if (type == NULL_TREE)
		return -EINVAL;

	if (!RECORD_OR_UNION_TYPE_P(type)) {
		tree context;

		if (trace_gimple())
			debug_tree(arg);

		context = DECL_CONTEXT(arg);
		if (context == NULL_TREE)
			return -EINVAL;
		if (!RECORD_OR_UNION_TYPE_P(context))
			return -EINVAL;
		type = context;
	}

	node_type = tree_arg_type(arg);
	if (node_type != DECL_NODE_RECORD_TYPE &&
			node_type != DECL_NODE_UNION_TYPE)
		return -EINVAL;
	ret = chain_append_field(chain, type, node_type);
	if (ret == -EEXIST)
		return 0;
	if (ret)
		return ret;

	for (field = TYPE_FIELDS(type); field; field = TREE_CHAIN(field)) {
		if (TREE_CODE(field) == FUNCTION_DECL)
			continue;

		if (EXCEPTIONAL_CLASS_P(field)) {
			__BUG("Exceptional field in tree_chain", field);
			break;
		}

		if (TREE_CODE(field) == FIELD_DECL) {
			node_type = tree_arg_type(field);

			/*
			 * POINTER_TYPE is treated as FIELD_DECL.
			 */
			if (RECORD_OR_UNION_TYPE_P(TREE_TYPE(field)))
				ret = __construct_new_type(chain, field);
			else
				ret = chain_append_field(chain, field,
							DECL_NODE_FIELD_TYPE);
		}

		if (TREE_CODE(field) == TYPE_DECL)
			ret = __construct_new_type(chain, field);

		if (ret == -EEXIST)
			continue;
		if (ret)
			return ret;
	}

	chain_end_of_type_decl(chain);
	return 0;
}

static void find_decl_chain_caller(gimple stmt, struct decl_chain *chain)
{
	tree block;

	block = gimple_block(stmt);
	if (block == NULL_TREE)
		return;

	while (block != NULL_TREE && TREE_CODE(block) != FUNCTION_DECL) {
		block = BLOCK_SUPERCONTEXT(block);
	}

	if (block == NULL_TREE)
		return;

	if (DECL_NAME(block)) {
		std::string caller_id;

		caller_id = IDENTIFIER_POINTER(DECL_NAME(block));
		decl_chain_set_caller(chain, caller_id, block);
	}
}

static std::string find_decl_chain_callee(gimple stmt,
					  struct decl_chain *chain)
{
	static std::string invalid = "<invalid>";
	std::string callee_id = "";
	tree block = NULL_TREE;
	tree node;

	if (gimple_code(stmt) != GIMPLE_CALL)
		return "";

	node = gimple_call_fn(stmt);
	if (node == NULL_TREE)
		return invalid;

	for (int i = 0; i < TREE_OPERAND_LENGTH(node); i++) {
		block = TREE_OPERAND(node, i);

		if (block == NULL_TREE)
			return invalid;
		if (TREE_CODE(block) == FUNCTION_DECL)
			break;
	}

	if (block == NULL_TREE)
		return invalid;
	if (!DECL_NAME(block))
		return invalid;

	callee_id = IDENTIFIER_POINTER(DECL_NAME(block));
	if (chain)
		decl_chain_set_callee(chain, callee_id, block);
	return callee_id;
}

static int construct_new_type(gimple stmt, tree type, int op)
{
	struct decl_chain *chain;
	int ret;

	if (type == NULL_TREE)
		return -EINVAL;
	chain = alloc_decl_chain(CF_CHECK_RECURSIVE_DECL);
	if (!chain)
		return -ENOMEM;

	ret = __construct_new_type(chain, type);
	if (ret) {
		free_decl_chain(chain);
		return ret;
	}

	decl_chain_set_format(chain, CF_FORMAT_NEW_TYPE);
	decl_chain_set_op(chain, op);
	find_decl_chain_caller(stmt, chain);

	chain->parse(chain);
	free_decl_chain(chain);
	return 0;
}

static int parse_gimple_assign_op(gimple stmt, tree node, int op)
{
	struct decl_chain *chain = alloc_decl_chain(CF_CHECK_RECURSIVE_DECL);
	int ret;

	if (!chain)
		return -ENOMEM;

	decl_chain_set_format(chain, CF_FORMAT_LD_ST);
	decl_chain_set_op(chain, op);
	find_decl_chain_caller(stmt, chain);
	find_decl_chain_callee(stmt, chain);

	if (decl_tree_operand_list(chain, node)) {
		ret = -ENOMEM;
		goto out;
	}

	if (decl_chain_is_parm_decl(chain))
		op |= CF_RECORD_CALLER;

	if (chain->parse(chain) == DECL_TREE_OK) {
		ret = 0;
		goto out;
	}

	ret = construct_new_type(stmt, (tree)decl_chain_get_type(chain), op);
	if (ret)
		goto out;

	if (decl_chain_is_parm_decl(chain)) {
		ret = decl_chain_lookup_parm(chain);
	}

	if (chain->parse(chain) != DECL_TREE_OK)
		ret = -EINVAL;
out:
	free_decl_chain(chain);
	return ret;
}

static int parse_gimple_call_op(gimple stmt, tree node, int op)
{
	struct decl_chain *chain = alloc_decl_chain(CF_CHECK_RECURSIVE_DECL);
	int ret;

	if (!chain)
		return -ENOMEM;

	find_decl_chain_caller(stmt, chain);
	find_decl_chain_callee(stmt, chain);

	if (decl_tree_operand_list(chain, node)) {
		ret = -ENOMEM;
		goto out;
	}

	decl_chain_set_format(chain, CF_FORMAT_GIMPLE_CALL);
	decl_chain_set_op(chain, op);
	ret = chain->parse(chain);
out:
	free_decl_chain(chain);
	return ret;
}

static int parse_gimple_assign_stmt(gimple stmt)
{
	int ret;
	tree op;

	if (gimple_clobber_p(stmt))
		return 0;

	if (trace_gimple())
		debug_gimple_stmt(stmt);

	op = gimple_assign_lhs(stmt);

	if (TREE_CODE(op) == SSA_NAME) {
		/*
		 * This creates SSA chains. Each chain has SSA node
		 * as LHS. For examle, this
		 *
		 *   b1.__buzz__b = b1.__buzz__a++;
		 *
		 * is repsented as follows:
		 *
		 *   gimple_assign:
		 *   _1 = b1.__buzz__a;
		 *   gimple_assign:
		 *   _2 = _1;
		 *   gimple_assign:
		 *   _3 = _2 + 1;
		 *   gimple_assign:
		 *   b1.__buzz__a = _3;
		 *   gimple_assign:
		 *   b1.__buzz__b = _2;
		 */
		return parse_gimple_assign_ssa_lhs(op, stmt);
	}

	parse_gimple_assign_op(stmt, op, CF_OP_LHS);

	/*
	 * This should walk the SSA chains, resolve to LEAF nodes and
	 * build decl_tree chains for update.
	 */
	switch (gimple_assign_rhs_class(stmt)) {
	case GIMPLE_SINGLE_RHS:
		ret = for_each_ssa_leaf(stmt,
					gimple_assign_rhs1(stmt),
					parse_gimple_assign_op,
					CF_OP_RHS);
		break;
	case GIMPLE_BINARY_RHS:
		ret = for_each_ssa_leaf(stmt,
					gimple_assign_rhs1(stmt),
					parse_gimple_assign_op,
					CF_OP_RHS);

		ret |= for_each_ssa_leaf(stmt,
					gimple_assign_rhs2(stmt),
					parse_gimple_assign_op,
					CF_OP_RHS);
		break;
	case GIMPLE_TERNARY_RHS:
		ret = for_each_ssa_leaf(stmt,
					gimple_assign_rhs1(stmt),
					parse_gimple_assign_op,
					CF_OP_RHS);

		ret |= for_each_ssa_leaf(stmt,
					gimple_assign_rhs2(stmt),
					parse_gimple_assign_op,
					CF_OP_RHS);

		ret |= for_each_ssa_leaf(stmt,
					gimple_assign_rhs3(stmt),
					parse_gimple_assign_op,
					CF_OP_RHS);
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

static int parse_gimple_call_stmt(gimple stmt)
{
	int ret;

	if (trace_gimple())
		debug_gimple_stmt(stmt);

	for (int i = 0; i < gimple_call_num_args(stmt); ++i) {
		/*
		 * This should parse GIMPLE_CALL SSA chains.
		 *
		 * Examlple:
		 *
		 *   gimple_assign at ..
		 *   _7 = b3->D.3743.__buzz__priv;
		 *   gimple_assign at ..
		 *   _8 = b3->__buzz__b;
		 *   gimple_call at ..
		 *   printf ("%d %s\n", _8, _7);
		 */
		ret = for_each_ssa_leaf(stmt,
					gimple_call_arg(stmt, i),
					parse_gimple_assign_op,
					CF_OP_RHS | CF_RECORD_CALLER);
		if (ret)
			return ret;
	}

	return ret;
}

static int parse_gimple_call_stmt_filter(gimple stmt,
					 std::unordered_set<std::string> &db)
{
	std::string callee_id;
	tree fn;
	int ret;

	if (trace_gimple())
		debug_gimple_stmt(stmt);

	callee_id = find_decl_chain_callee(stmt, NULL);
	if (db.find(callee_id) == db.end())
		return 0;

	for (int i = 0; i < gimple_call_num_args(stmt); ++i) {
		ret = for_each_ssa_leaf(stmt,
					gimple_call_arg(stmt, i),
					parse_gimple_call_op,
					0);
		if (ret)
			return ret;
	}
	return ret;
}

static tree callback_stmt(gimple_stmt_iterator *gsi,
		bool *handled_all_ops,
		struct walk_stmt_info *wi)
{
	gimple stmt = gsi_stmt(*gsi);
	enum gimple_code code = gimple_code(stmt);

	if (trace_gimple()) {
		location_t l = gimple_location(stmt);

		pr_info("Statement of type: %s at %s:%d\n",
				gimple_code_name[code],
				LOCATION_FILE(l),
				LOCATION_LINE(l));
	}

	if (code == GIMPLE_ASSIGN) {
		parse_gimple_assign_stmt(stmt);
	}
	if (code == GIMPLE_CALL) {
		parse_gimple_call_stmt(stmt);
		parse_gimple_call_stmt_filter(stmt, lock_fns);
	}

	return NULL;
}

static tree callback_op(tree *tree, int *walk_subtrees, void *data)
{
	return NULL;
}

static void tree_type_decl(tree type)
{
	/*
	 * Seeme like we don't really need this as of now, as we get
	 * complete chain from field_decl. The code here here, just
	 * in case, looks pretty much the same - context chain traverse.
	 */
}

static void finish_type(void *event_data, void *data)
{
	/*
	 * This has been replaced with a reverse typedecl, which is
	 * done from gimple processing stage.
	 */
}

static void processing_done(void *event_data, void *data)
{
	struct transport_cmd *cmd;

	if (!scanty_db_backend()) {
		debug_walk_decl_tree(NULL);
		debug_walk_call_tree(NULL);
		return;
	}

	cmd = alloc_transport_cmd();
	if (!cmd)
		return;

	if (transport_init_client(cmd)) {
		pr_err("Unable to init client\n");
		goto out;
	}

	cmd->payload = decl_tree_to_protocol_representation();
	if (!cmd->payload) {
		pr_err("Unable to serialize decl_tree\n");
		goto out;
	}

	if (serialize_proto_cmd(cmd->payload, PROTO_COMMAND_WRITE_DECL_TREE)) {
		pr_err("Unable to serialize proto command\n");
		goto out;
	}

	transport_write(cmd);
out:
	free_transport_cmd(cmd);
}

static unsigned int scanty_execute(function *fun)
{
	gimple_seq gimple_body = fun->gimple_body;
	struct walk_stmt_info walk_stmt_info;

	memset(&walk_stmt_info, 0, sizeof(walk_stmt_info));
	walk_gimple_seq(gimple_body, callback_stmt,
			callback_op, &walk_stmt_info);
	return 0;
}

int plugin_init(struct plugin_name_args *plugin_info,
		struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	struct register_pass_info pass_info;

	set_logger_app_name("plugin");
	pass_info.pass = make_scanty_pass();
	pass_info.reference_pass_name = "cfg";
	pass_info.ref_pass_instance_number = 1;
	pass_info.pos_op = PASS_POS_INSERT_BEFORE;

	if (!plugin_default_version_check(version, &gcc_version)) {
		pr_err("incompatible gcc/plugin versions");
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO,
			  NULL, &scanty_plugin_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP,
			  NULL, &pass_info);
	register_callback(plugin_name, PLUGIN_FINISH_TYPE,
			  finish_type, NULL);
	register_callback(plugin_name, PLUGIN_FINISH_UNIT,
			  processing_done, NULL);
	return 0;
}
