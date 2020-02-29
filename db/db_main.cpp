// SPDX-License-Identifier: GPL-2.0-only

/*
 * Trivial scanty "database".
 *
 * Sergey Senozhatsky, 2020, <sergey.senozhatsky@gmail.com>
 */

#include <errno.h>
#include <logger.h>
#include <configuration.h>
#include <protocol.h>
#include <transport.h>
#include <decl_tree.h>

using namespace std;

static int process_cmd(struct transport_cmd *cmd)
{
	int type = deserialize_proto_cmd(cmd->payload);

	if (type == PROTO_COMMAND_INVALID) {
		pr_err("Unknown protocol command\n");
		return -EINVAL;
	}

	if (type == PROTO_COMMAND_WRITE_DECL_TREE) {
		return decl_tree_from_protocol_representation(cmd->payload);
	}

	if (type == PROTO_COMMAND_READ_DECL_TREE) {
		proto_payload_put(cmd->payload);
		cmd->payload = decl_tree_to_protocol_representation();
		if (!cmd->payload)
			return -EINVAL;
		return transport_write(cmd);
	}

	if (type == PROTO_COMMAND_READ_DECL_NAME) {
		string decl_name;

		decl_name = deserialize_proto_cmd_decl_name(cmd->payload);
		proto_payload_put(cmd->payload);
		cmd->payload = decl_name_to_protocol_representation(decl_name);
		if (!cmd->payload)
			return -EINVAL;
		return transport_write(cmd);
	}

	if (type == PROTO_COMMAND_SERVER_STDOUT_DEBUG_DUMP) {
		decl_tree_stdout_dump();
		return 0;
	}
	return -EINVAL;
}

int main()
{
	int ret;

	set_logger_app_name("db");

	ret = transport_init_server(process_cmd);
	if (ret)
		return ret;
	ret = transport_recv_msg_loop();
	if (ret)
		return ret;
	return 0;
}
