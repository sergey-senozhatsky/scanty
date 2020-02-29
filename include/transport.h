// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#ifndef __TRANSPORT_H
#define __TRANSPORT_H 1

struct json_object;
struct transport_client;

struct transport_cmd {
	json_object			*payload;
	struct transport_client		*req_private;
};

typedef int (*request_cb_t)(struct transport_cmd *cmd);

struct transport_cmd *alloc_transport_cmd(void);
void free_transport_cmd(struct transport_cmd *cmd);

int transport_init_server(request_cb_t cb);
int transport_init_client(struct transport_cmd *cmd);
int transport_recv_msg_loop(void);

int transport_read(struct transport_cmd *cmd);
int transport_write(struct transport_cmd *cmd);

#endif /* __TRANSPORT_H */
