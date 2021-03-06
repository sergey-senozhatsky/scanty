// SPDX-License-Identifier: GPL-2.0-only

/*
 * Trivial scanty "database" client.
 *
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#include <errno.h>
#include <getopt.h>
#include <logger.h>
#include <configuration.h>
#include <protocol.h>
#include <transport.h>
#include <decl_tree.h>

using namespace std;

static int command;
static string file_name;
static string decl_name;

static struct option opts[] = {
	{"command",	required_argument,	NULL,	'c' },
	{"file",	required_argument,	NULL,	'f' },
	{"type",	required_argument,	NULL,	't' },
	{"help",	no_argument,		NULL,	'h' },
	{NULL,		0,			NULL,	 0  }
};

enum COMMAND {
	COMMAND_READ_DB,
	COMMAND_READ_TYPE,
	COMMAND_SAVE_DB_TO_FILE,
	COMMAND_LOAD_DB_FROM_FILE,
	COMMAND_SERVER_DEBUG_DUMP,
};

static void usage(void)
{
	pr_info("Usage: scantyclient [-c CMD [options]]\n");
	pr_info("\t-c|--command $CMD\trequest command\n");
	pr_info("\t\t%d\t\tprint db contents (stdout)\n",
		COMMAND_READ_DB);
	pr_info("\t\t%d\t\tprint particular type stats\n",
		COMMAND_READ_TYPE);
	pr_info("\t\t%d\t\tsave database to a file\n",
		COMMAND_SAVE_DB_TO_FILE);
	pr_info("\t\t%d\t\tload database from a file\n",
		COMMAND_LOAD_DB_FROM_FILE);
	pr_info("\t\t%d\t\tdebug database dump on the server (stdout)\n",
		COMMAND_SERVER_DEBUG_DUMP);
	pr_info("\t-f|--file $NAME\t\tdb file name\n");
	pr_info("\t-t|--type $NAME\t\tdeclaration type\n");
	pr_info("\t-h|--help\t\tprint this message\n");

	exit(EXIT_FAILURE);
}

static int __serialize_cmd(struct transport_cmd *cmd)
{
	int type;

	if (command < 0 || command > COMMAND_SERVER_DEBUG_DUMP) {
		pr_err("Unknown command: %d\n", command);
		return -EINVAL;
	}

	if (command == COMMAND_READ_DB)
		type = PROTO_COMMAND_READ_DECL_TREE;
	if (command == COMMAND_READ_TYPE)
		type = PROTO_COMMAND_READ_DECL_NAME;
	if (command == COMMAND_SAVE_DB_TO_FILE)
		type = PROTO_COMMAND_READ_DECL_TREE;
	if (command == COMMAND_LOAD_DB_FROM_FILE)
		type = PROTO_COMMAND_WRITE_DECL_TREE;
	if (command == COMMAND_SERVER_DEBUG_DUMP)
		type = PROTO_COMMAND_SERVER_STDOUT_DEBUG_DUMP;

	return serialize_proto_cmd(cmd->payload, type);
}

static int handle_read_decl_tree(struct transport_cmd *cmd)
{
	int ret;

	ret = transport_write(cmd);
	if (ret)
		return ret;
	ret = transport_read(cmd);
	if (ret)
		return ret;
	ret = decl_tree_from_protocol_representation(cmd->payload);
	if (ret)
		return ret;

	decl_tree_stdout_dump();
	return ret;
}

static int handle_read_decl_name(struct transport_cmd *cmd)
{
	int ret;

	if (decl_name.empty()) {
		pr_err("[-t]ype name should be provided\n");
		return -EINVAL;
	}

	ret = serialize_proto_cmd_decl_name(cmd->payload, decl_name.c_str());
	if (ret)
		return ret;

	ret = transport_write(cmd);
	if (ret)
		return ret;
	ret = transport_read(cmd);
	if (ret)
		return ret;
	ret = decl_tree_from_protocol_representation(cmd->payload);
	if (ret)
		return ret;

	pr_info("stats for type %s\n", decl_name.c_str());
	decl_tree_stdout_dump();
	return ret;
}

static int handle_save_db_to_file(struct transport_cmd *cmd)
{
	int ret;

	if (file_name.empty()) {
		pr_err("[-f]ile name should be provided\n");
		return -EINVAL;
	}

	ret = transport_write(cmd);
	if (ret)
		return ret;
	ret = transport_read(cmd);
	if (ret)
		return ret;

	return proto_payload_save_to_file(file_name.c_str(), cmd->payload);
}

static int handle_load_db_from_file(struct transport_cmd *cmd)
{
	if (file_name.empty()) {
		pr_err("[-f]ile name should be provided\n");
		return -EINVAL;
	}

	proto_payload_put(cmd->payload);
	cmd->payload = proto_payload_load_from_file(file_name.c_str());
	if (!cmd->payload) {
		pr_err("Unable to load database from file\n");
		return -EINVAL;
	}

	if (__serialize_cmd(cmd))
		return -EINVAL;

	return transport_write(cmd);
}

static int handle_server_stdout_debug_dump(struct transport_cmd *cmd)
{
	return transport_write(cmd);
}

static int handle_cmd()
{
	struct transport_cmd *cmd;
	int ret;

	cmd = alloc_transport_cmd();
	if (!cmd)
		return -ENOMEM;

	cmd->payload = proto_payload_get();
	if (!cmd->payload) {
		ret = -ENOMEM;
		goto out;
	}

	ret = transport_init_client(cmd);
	if (ret) {
		pr_err("Unable to init client\n");
		goto out;
	}

	ret = __serialize_cmd(cmd);
	if (ret)
		goto out;

	switch (command) {
	case COMMAND_READ_DB:
		ret = handle_read_decl_tree(cmd);
		break;
	case COMMAND_READ_TYPE:
		ret = handle_read_decl_name(cmd);
		break;
	case COMMAND_SAVE_DB_TO_FILE:
		ret = handle_save_db_to_file(cmd);
		break;
	case COMMAND_LOAD_DB_FROM_FILE:
		ret = handle_load_db_from_file(cmd);
		break;
	case COMMAND_SERVER_DEBUG_DUMP:
		ret = handle_server_stdout_debug_dump(cmd);
		break;
	default:
		pr_err("Unknown command: %d\n", command);
		ret = -EINVAL;
	}
out:
	free_transport_cmd(cmd);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret, c;

	set_logger_app_name("client");

	opterr = 0;
	while (1) {
		c = getopt_long(argc, argv, "c:f:t:hV", opts, NULL);

		if (c < 0)
			break;

		switch (c) {
		case 0: /* getopt_long() set a variable, just keep going */
			break;
		case 1:
			break;
		case 'c':
			command = atoi(optarg);
			break;
		case 'f':
			file_name = optarg;
			break;
		case 't':
			decl_name = optarg;
			break;
		case ':':
			pr_err("Missing option argument\n");
			/* Fall through */
		case '?':
		case 'h':
			/* Fall through */
		default:
			usage();
		}
	}

	return handle_cmd();
}
