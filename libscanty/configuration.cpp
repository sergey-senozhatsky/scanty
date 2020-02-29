// SPDX-License-Identifier: GPL-2.0-only

/*
 * Sergey Senozhatsky, 2020 <sergey.senozhatsky@gmail.com>
 */

#include <stdlib.h>
#include <configuration.h>

static char const *env_vars[CONF_INVALID + 1] = {
	"SCANTY_DB_HOST",
	"SCANTY_DB_PORT",
	"SCANTY_DB_BACKEND",
	"SCANTY_TRACE_LEVEL",
	NULL
};

static char const *default_vals[CONF_INVALID + 1] = {
	"127.0.0.1",
	"22122",
	"0",
	"0",
	NULL
};

#define TRACE_DEBUG_TREE	(1 << 0)
#define TRACE_DECL_TREE		(1 << 1)
#define TRACE_PARSE_SSA		(1 << 2)
#define TRACE_GIMPLE		(1 << 3)

const char *get_conf_string(enum CONF no)
{
	const char *ret;

	ret = getenv(env_vars[no]);
	if (ret != NULL)
		return ret;
	return default_vals[no];
}

int get_conf_int(enum CONF no)
{
	const char *ret;
	int ret_int;

	ret = getenv(env_vars[no]);
	if (ret == NULL)
		ret = default_vals[no];
	ret_int = atoi(ret);
	return ret_int;
}

bool scanty_db_backend(void)
{
	return get_conf_int(CONF_DB_BACKEND);
}

bool trace_debug_tree(void)
{
	return get_conf_int(CONF_TRACE_LEVEL) & TRACE_DEBUG_TREE;
}

bool trace_decl_tree(void)
{
	return get_conf_int(CONF_TRACE_LEVEL) & TRACE_DECL_TREE;
}

bool trace_parse_ssa(void)
{
	return get_conf_int(CONF_TRACE_LEVEL) & TRACE_PARSE_SSA;
}

bool trace_gimple(void)
{
	return get_conf_int(CONF_TRACE_LEVEL) & TRACE_GIMPLE;
}
