// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#ifndef __PROTOCOL_H
#define __PROTOCOL_H 1

enum PROTO_COMMAND {
	PROTO_COMMAND_READ_DECL_TREE,
	PROTO_COMMAND_READ_DECL_NAME,
	PROTO_COMMAND_WRITE_DECL_TREE,
	PROTO_COMMAND_SERVER_STDOUT_DEBUG_DUMP,
	PROTO_COMMAND_INVALID,
};

struct json_object;
typedef struct json_object proto_payload;

void serialize_decl_tree_to_stdout(struct decl_tree *tree);

int deserialize_decl_tree(proto_payload *payload);
proto_payload *serialize_decl_tree(struct decl_tree *tree);
proto_payload *serialize_decl_name(struct decl_tree *tree,
				   const char *decl_name);

int serialize_proto_cmd(proto_payload *payload, int type);
int deserialize_proto_cmd(proto_payload *payload);

const char *deserialize_proto_cmd_decl_name(proto_payload *payload);
int serialize_proto_cmd_decl_name(proto_payload *payload,
				  const char *decl_name);

int proto_payload_size(proto_payload *payload);

const char *proto_payload_to_transport_representation(proto_payload *payload,
						      size_t *len);
proto_payload *proto_payload_from_transport_representation(const char *rep);
int proto_payload_save_to_file(const char *fn, proto_payload *payload);
proto_payload *proto_payload_load_from_file(const char *fn);

proto_payload *proto_payload_get(void);
void proto_payload_put(proto_payload *payload);
#endif /* __PROTOCOL_H */
