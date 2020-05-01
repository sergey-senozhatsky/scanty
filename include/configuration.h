// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#ifndef __CONFIGURATION_H
#define __CONFIGURATION_H

enum CONF {
	CONF_DB_HOST,
	CONF_DB_PORT,
	CONF_DB_BACKEND,
	CONF_TRACE_LEVEL,
	CONF_FUNCTION_FILTER,
	CONF_INVALID,
};

const char *get_conf_string(enum CONF no);
int get_conf_int(enum CONF no);

bool scanty_db_backend(void);
bool trace_debug_tree(void);
bool trace_decl_tree(void);
bool trace_parse_ssa(void);
bool trace_gimple(void);

#endif /* __CONFIGURATION_H */
