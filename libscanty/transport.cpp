// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */
#include <mutex>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <logger.h>
#include <configuration.h>
#include <protocol.h>
#include <transport.h>

using namespace std;

#define BACKLOG_SZ	8
#define BUFFER_SZ	(4096 * 4)
#define MAX_WORKERS	128

static struct transport_server {
	int			sock;
	request_cb_t		req_cb;

	mutex			lock;
	int			num_running;
} server;

struct transport_client {
	int			sock;
};

static void server_finish_processing(void)
{
	server.lock.lock();
	server.num_running--;
	server.lock.unlock();
}

struct transport_cmd *alloc_transport_cmd(void)
{
	struct transport_cmd *cmd;
	struct transport_client *client;

	cmd = new(std::nothrow) struct transport_cmd;
	client = new(std::nothrow) struct transport_client;

	if (!cmd || !client)
		goto out_error;

	memset(cmd, 0x00, sizeof(struct transport_cmd));
	client->sock = -1;
	cmd->req_private = client;
	return cmd;

out_error:
	delete client;
	delete cmd;
	return NULL;
}

void free_transport_cmd(struct transport_cmd *cmd)
{
	struct transport_client *client = cmd->req_private;

	if (client->sock > 0)
		close(client->sock);
	proto_payload_put(cmd->payload);
	delete client;
	delete cmd;
}

int transport_read(struct transport_cmd *cmd)
{
	struct transport_client *client;
	char *buf;
	string rep;
	ssize_t ret;

	client = cmd->req_private;
	buf = new(std::nothrow) char[BUFFER_SZ];
	if (!buf)
		return -ENOMEM;

	memset(buf, 0x00, BUFFER_SZ);
	while ((ret = recv(client->sock, buf, BUFFER_SZ - 1, 0))) {
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			pr_err("Unable to recv() payload\n");
			return ret;
		}
		rep += buf;
		memset(buf, 0x00, BUFFER_SZ);
	}
	delete[] buf;

	if (rep.empty())
		return 0;

	cmd->payload = proto_payload_from_transport_representation(rep.c_str());
	if (!cmd->payload)
		return -EINVAL;
	return 0;
}

int transport_write(struct transport_cmd *cmd)
{
	struct transport_client *client;
	const char *buf;
	int offt = 0;
	size_t len;
	ssize_t ret;

	client = cmd->req_private;
	buf = proto_payload_to_transport_representation(cmd->payload, &len);
	while (len) {
		ret = send(client->sock, buf + offt,
			   min(len, (size_t)BUFFER_SZ), MSG_NOSIGNAL);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			pr_err("Unable to send() payload\n");
			return ret;
		}
		offt += ret;
		len -= ret;
	}

	shutdown(client->sock, SHUT_WR);
	return 0;
}

static int __handle_read(int client_sock)
{
	struct transport_cmd *cmd;
	int ret;

	cmd = alloc_transport_cmd();
	if (!cmd) {
		ret = -ENOMEM;
		goto out_error;
	}

	cmd->req_private->sock = client_sock;
	ret = transport_read(cmd);
	if (ret)
		goto out_error;

	ret = server.req_cb(cmd);

out_error:
	free_transport_cmd(cmd);
	server_finish_processing();
	return ret;
}

static void server_start_processing(int client_sock)
{
	bool ok = false;

	do {
		server.lock.lock();
		if (server.num_running + 1>= MAX_WORKERS) {
			server.lock.unlock();
			std::this_thread::yield();
		}
		server.num_running++;
		server.lock.unlock();

		ok = true;
		std::thread worker(__handle_read, client_sock);
		worker.detach();
	} while (ok == false);
}

int transport_recv_msg_loop(void)
{
	struct sockaddr_in addr = {0, };
	socklen_t len;
	int client_sock;
	int ret;

	ret = listen(server.sock, BACKLOG_SZ);
	if (ret) {
		pr_err("Unable to listen()\n");
		return ret;
	}

	while (1) {
		client_sock = accept(server.sock,
				     (struct sockaddr *)&addr,
				     &len);
		if (client_sock < 0) {
			pr_err("Unable to accept()\n");
			ret = -EINVAL;
			break;
		}

		server_start_processing(client_sock);
	}
	return ret;
}

int transport_init_client(struct transport_cmd *cmd)
{
	struct sockaddr_in addr = {0, };
	int ret;

	cmd->req_private->sock = socket(AF_INET, SOCK_STREAM, 0);
	if (cmd->req_private->sock < 0) {
		pr_err("Unable to open server socket\n");
		return -EINVAL;
	}

	addr.sin_family		= AF_INET;
	addr.sin_port		= htons(get_conf_int(CONF_DB_PORT));

	ret = inet_aton(get_conf_string(CONF_DB_HOST), &addr.sin_addr);
	if (ret < 0) {
		pr_err("Unable to get server address\n");
		return ret;
	}

	ret = connect(cmd->req_private->sock,
		      (struct sockaddr *)&addr,
		      sizeof(addr));
	if (ret)
		pr_err("Unable to connect\n");
	return ret;
}

int transport_init_server(request_cb_t cb)
{
	struct sockaddr_in addr = {0, };
	int ret;

	pr_info("Starting scantydb on %s : %d\n",
			get_conf_string(CONF_DB_HOST),
			get_conf_int(CONF_DB_PORT));

	server.req_cb = cb;
	server.sock = socket(AF_INET, SOCK_STREAM, 0);
	if (server.sock < 0) {
		pr_err("Unable to open server socket\n");
		return -EINVAL;
	}

	addr.sin_family		= AF_INET;
	addr.sin_addr.s_addr	= INADDR_ANY;
	addr.sin_port		= htons(get_conf_int(CONF_DB_PORT));

	ret = bind(server.sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		pr_err("Failed to bind()\n");
		return -EINVAL;
	}

	return 0;
}
