// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */
#include <errno.h>
#include <json-c/json.h>
#include <decl_tree.h>
#include <protocol.h>
#include <logger.h>

using namespace std;

#define JSO_KEY_NAME		"N"
#define JSO_KEY_TYPE		"T"
#define JSO_KEY_LOADS		"L"
#define JSO_KEY_STORES		"S"
#define JSO_KEY_FIELDS		"F"

#define JSO_KEY_PROTO_CMD	"CMD"
#define JSO_KEY_PROTO_DECL_NAME	"DECLNAME"
#define JSO_KEY_PROTO_PAYLOAD	"PAYLOAD"

static void walk_decl_tree_stdout(struct decl_tree *tree, int tabs)
{
	if (tree->fields.empty())
		goto out;

	lock_decl_tree(tree);
	for (auto &iter : tree->fields) {
		struct decl_tree *field = iter.second;
		const char *type = "<\?\?\?\?>";

		if (field->node_type == DECL_NODE_FIELD_TYPE)
			type = "field";
		if (field->node_type == DECL_NODE_RECORD_TYPE)
			type = "struct";
		if (field->node_type == DECL_NODE_UNION_TYPE)
			type = "union";
		if (field->node_type == DECL_NODE_FUNCTION_TYPE)
			type = "func";
		if (field->node_type == DECL_NODE_CALLEE_TYPE)
			type = "to";
		if (field->node_type == DECL_NODE_CALLER_TYPE)
			type = "from";

		if (field->node_type == DECL_NODE_INVALID_TYPE) {
			pr_info("%*c%*c %-6s %-32s\n",
				18, ' ',
				tabs, ' ',
				type,
				iter.first.c_str());
			continue;
		}

		if (field->node_type == DECL_NODE_FIELD_TYPE) {
			pr_info("ld:%-5llu st:%-5llu %*c %s %s\n",
				field->num_loads,
				field->num_stores,
				tabs, ' ',
				type,
				iter.first.c_str());
			continue;
		}

		if (field->node_type == DECL_NODE_CALLER_TYPE ||
				field->node_type == DECL_NODE_CALLEE_TYPE) {
			pr_info("calls:%-5llu %*c %s %s()\n",
				field->num_loads,
				tabs, ' ',
				type,
				iter.first.c_str());
		} else if (field->node_type == DECL_NODE_LOCATION_TYPE) {
			pr_info("%*c%*c line:%s\n",
				tabs, ' ',
				tabs, ' ',
				iter.first.c_str());
		} else {
			pr_info("%*c%*c %-6s %-32s\n",
				18, ' ',
				tabs, ' ',
				type,
				iter.first.c_str());
		}
		walk_decl_tree_stdout(field, tabs + 4);
	}
	unlock_decl_tree(tree);

out:
	if (tabs == 4)
		pr_info("---------------------------------------------\n");
}

void serialize_decl_tree_to_stdout(struct decl_tree *tree)
{
	walk_decl_tree_stdout(tree, 0);
}

static int field_type(proto_payload *jso)
{
	jso = json_object_object_get(jso, JSO_KEY_TYPE);
	if (!jso) {
		pr_err("Invalid declaration type\n");
		return DECL_NODE_INVALID_TYPE;
	}
	return json_object_get_int(jso);
}

static int chain_append_field(struct decl_chain *chain, proto_payload *jso)
{
	struct decl_node *node;
	proto_payload *key;
	int ret;

	key = json_object_object_get(jso, JSO_KEY_NAME);
	if (!key) {
		pr_err("Declaration does not have name\n");
		return -EINVAL;
	}

	node = alloc_decl_node();
	if (!node)
		return -ENOMEM;

	node->type_name = json_object_get_string(key);
	node->hash = std::hash<std::string>{}(node->type_name);
	node->type = field_type(jso);
	if (node->type == DECL_NODE_FIELD_TYPE) {
		key = json_object_object_get(jso, JSO_KEY_LOADS);
		if (key)
			node->num_loads = json_object_get_int64(key);

		key = json_object_object_get(jso, JSO_KEY_STORES);
		if (key)
			node->num_stores = json_object_get_int64(key);
	}

	ret = chain_decl_node(chain, node);
	if (ret)
		free_decl_node(node);
	return ret;
}

static int parse_decl(struct decl_chain *chain, proto_payload *jso)
{
	proto_payload *key;
	int ret;
	int len, i;

	ret = chain_append_field(chain, jso);
	if (ret)
		return ret;

	jso = json_object_object_get(jso, JSO_KEY_FIELDS);
	if (!jso) {
		pr_err("Type declaraion does not have fields\n");
		return -EINVAL;
	}

	len = json_object_array_length(jso);
	for (i = 0; i < len; i++) {
		key = json_object_array_get_idx(jso, i);
		if (!key)
			return -EINVAL;

		if (field_type(key) == DECL_NODE_FIELD_TYPE)
			ret = chain_append_field(chain, key);
		else
			ret = parse_decl(chain, key);
		if (ret) {
			pr_err("Unable to parse declaration %d\n", ret);
			return ret;
		}
	}

	chain_end_of_type_decl(chain);
	return ret;
}

int deserialize_decl_tree(proto_payload *jso)
{
	struct decl_chain *chain;
	int i, len, ret;

	jso = json_object_object_get(jso, JSO_KEY_PROTO_PAYLOAD);
	if (!jso)
		return -EINVAL;

	len = json_object_array_length(jso);
	for (i = 0; i < len; i++) {
		proto_payload *node = json_object_array_get_idx(jso, i);

		if (!node)
			continue;

		chain = alloc_decl_chain(CF_DONT_CHECK_RECURSIVE_DECL);
		if (!chain)
			continue;

		decl_chain_set_format(chain, CF_FORMAT_NEW_TYPE);
		ret = parse_decl(chain, node);
		if (ret == 0)
			chain->parse(chain);
		free_decl_chain(chain);
	}

	return 0;
}

static proto_payload *serialize_decl_type(proto_payload *parent,
					  struct decl_tree *field,
					  const char *field_name)
{
	proto_payload *current;
	int ret;

	current = json_object_new_object();
	if (!current)
		return NULL;

	ret = json_object_object_add(current,
			JSO_KEY_NAME,
			json_object_new_string(field_name));
	if (ret)
		goto out;
	ret = json_object_object_add(current,
			JSO_KEY_TYPE,
			json_object_new_int(field->node_type));
	if (ret)
		goto out;

	if (field->node_type == DECL_NODE_FIELD_TYPE) {
		ret = json_object_object_add(current,
				JSO_KEY_LOADS,
				json_object_new_int64(field->num_loads));
		if (ret)
			goto out;
		ret = json_object_object_add(current,
				JSO_KEY_STORES,
				json_object_new_int64(field->num_stores));
		if (ret)
			goto out;
	}

	ret = json_object_array_add(parent, current);
	if (ret)
		goto out;
	return current;
out:
	json_object_put(current);
	return NULL;
}

static int walk_decl_tree(struct decl_tree *tree,
			  proto_payload *parent)
{
	proto_payload *current, *sub_parent;
	int ret;

	lock_decl_tree(tree);
	if (tree->fields.empty()) {
		unlock_decl_tree(tree);
		return 0;
	}

	for (auto &iter : tree->fields) {
		struct decl_tree *field = iter.second;

		if (field->node_type == DECL_NODE_INVALID_TYPE)
			continue;

		current = serialize_decl_type(parent,
					      field,
					      iter.first.c_str());
		if (!current)
			goto out;

		if (field->node_type == DECL_NODE_FIELD_TYPE)
			continue;

		sub_parent = json_object_new_array();
		if (!sub_parent) {
			ret = -ENOMEM;
			goto out;
		}
		ret = json_object_object_add(current,
				JSO_KEY_FIELDS,
				sub_parent);
		if (ret)
			goto out;
		ret = walk_decl_tree(field, sub_parent);
		if (ret)
			goto out;
	}
out:
	unlock_decl_tree(tree);
	return ret;
}

proto_payload *serialize_decl_tree(struct decl_tree *tree)
{
	proto_payload *payload, *jso;

	jso = json_object_new_object();
	if (!jso)
		return NULL;

	payload = json_object_new_array();
	if (!payload) {
		json_object_put(jso);
		return NULL;
	}

	if (tree)
		walk_decl_tree(tree, payload);
	json_object_object_add(jso, JSO_KEY_PROTO_PAYLOAD, payload);
	return jso;
}

proto_payload *serialize_decl_name(struct decl_tree *tree,
				   const char *decl_name)
{
	proto_payload *payload, *jso;

	jso = json_object_new_object();
	if (!jso)
		return NULL;

	payload = json_object_new_array();
	if (!payload) {
		json_object_put(jso);
		return NULL;
	}

	if (tree) {
		proto_payload *current;
		/*
		 * XXX dirty hack. FIXME
		 */
		current = serialize_decl_type(payload, tree, decl_name);
		if (current) {
			json_object *sub_parent = json_object_new_array();
			if (!sub_parent)
				goto out;
			json_object_object_add(current,
				JSO_KEY_FIELDS,
				sub_parent);
			walk_decl_tree(tree, sub_parent);
		}
	}
out:
	json_object_object_add(jso, JSO_KEY_PROTO_PAYLOAD, payload);
	return jso;
}

int deserialize_proto_cmd(proto_payload *payload)
{
	payload = json_object_object_get(payload, JSO_KEY_PROTO_CMD);
	if (!payload)
		return PROTO_COMMAND_INVALID;
	return json_object_get_int(payload);
}

int serialize_proto_cmd(proto_payload *payload, int type)
{
	return json_object_object_add(payload,
			JSO_KEY_PROTO_CMD,
			json_object_new_int(type));
}

const char *deserialize_proto_cmd_decl_name(proto_payload *payload)
{
	payload = json_object_object_get(payload, JSO_KEY_PROTO_PAYLOAD);
	if (!payload)
		return "";
	payload = json_object_object_get(payload, JSO_KEY_PROTO_DECL_NAME);
	if (!payload)
		return "";
	return json_object_get_string(payload);
}

int serialize_proto_cmd_decl_name(proto_payload *payload,
				  const char *decl_name)
{
	proto_payload *jso;
	int ret;

	jso = json_object_new_object();
	if (!jso)
		return -ENOMEM;

	ret = json_object_object_add(jso,
				     JSO_KEY_PROTO_DECL_NAME,
				     json_object_new_string(decl_name));
	if (ret)
		goto out_error;
	ret = json_object_object_add(payload, JSO_KEY_PROTO_PAYLOAD, jso);
	if (ret)
		goto out_error;
	return 0;

out_error:
	pr_err("Unable to serialize cmd decl_name\n");
	json_object_put(jso);
	return ret;
}

const char *proto_payload_to_transport_representation(proto_payload *payload,
						      size_t *len)
{
	return json_object_to_json_string_length(payload, 0, len);
}

proto_payload *proto_payload_from_transport_representation(const char *rep)
{
	proto_payload *jso = json_tokener_parse(rep);

	if (!jso)
		pr_err("Unable to parse transport representation\n");
	return jso;
}

void proto_payload_put(proto_payload *payload)
{
	if (payload)
		json_object_put(payload);
}

proto_payload *proto_payload_get(void)
{
	return json_object_new_object();
}

int proto_payload_save_to_file(const char *fn, proto_payload *payload)
{
	return json_object_to_file(fn, payload);
}

proto_payload *proto_payload_load_from_file(const char *fn)
{
	return json_object_from_file(fn);
}
