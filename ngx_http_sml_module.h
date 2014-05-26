/*
 * ngx_http_lua_logj.h
 *
 *  Created on: 2014年1月23日
 *      Author: yw
 */

#ifndef NGX_HTTP_LUA_LOGJ_H_
#define NGX_HTTP_LUA_LOGJ_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_lua_api.h"
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

typedef struct ngx_http_sml_log_conf {
	ngx_log_t 	*log;

	ngx_flag_t 	 log_tail;

}ngx_http_sml_log_conf_t;

typedef struct ngx_http_sml_loc_conf_s {

	ngx_http_sml_log_conf_t *log_conf;

}ngx_http_sml_loc_conf_t;

extern ngx_module_t ngx_http_sml_module;


#define DEFAULT_LOG "logs/sax.log"
#define DEFAULT_LEVEL NGX_LOG_INFO




int ngx_http_sml_inject_api(lua_State *L);


#endif /* NGX_HTTP_LUA_LOGJ_H_ */
