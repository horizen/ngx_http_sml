/*
 * ngx_http_sml_module.c
 *
 *  Created on: 2013年12月18日
 *      Author: yw
 */


#include "ngx_http_sml_module.h"

static char *ngx_http_sml_sml_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_sml_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sml_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_sml_log_set(ngx_conf_t *cf, ngx_http_sml_log_conf_t *lgcf);

#if defined(nginx_version) && nginx_version >= 1005002
static ngx_log_t *ngx_log_create(ngx_cycle_t *cycle, ngx_str_t *name);
#endif
static u_char *ngx_http_sml_log_error(ngx_log_t *log, u_char *buf, size_t len);
static ngx_int_t ngx_http_sml_preinit(ngx_conf_t *cf);
static ngx_int_t ngx_http_sml_init(ngx_conf_t *cf);

static ngx_str_t err_levels[] = {
    ngx_null_string,
    ngx_string("emerg"),
    ngx_string("alert"),
    ngx_string("crit"),
    ngx_string("error"),
    ngx_string("warn"),
    ngx_string("notice"),
    ngx_string("info"),
    ngx_string("debug")
};

static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_mysql"
};


static ngx_http_sml_log_conf_t *default_log;

static ngx_command_t  ngx_http_sml_commands[] = {

	{ ngx_string("sml_log"),
	  NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
	  ngx_http_sml_sml_log,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  0,
	  NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_sml_module_ctx = {
    ngx_http_sml_preinit,                  /* preconfiguration */
    ngx_http_sml_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sml_create_loc_conf,       /* create location configuration */
    ngx_http_sml_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_sml_module = {
    NGX_MODULE_V1,
    &ngx_http_sml_module_ctx,           /* module context */
    ngx_http_sml_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static
ngx_int_t ngx_http_sml_preinit(ngx_conf_t *cf)
{
	ngx_str_t name = ngx_string(DEFAULT_LOG);
	ngx_log_t *log;

	log = ngx_log_create(cf->cycle, &name);
	if (log == NULL) {
		return NGX_ERROR ;
	}
	log->log_level = DEFAULT_LEVEL;
	log->handler = ngx_http_sml_log_error;

	default_log = ngx_pcalloc(cf->pool, sizeof(ngx_http_sml_log_conf_t));
	if (default_log == NULL) {
	    return NGX_ERROR;
	}
	/* set by pcalloc
	    default_log->log_tail = 0
	*/
	default_log->log = log;

    return NGX_OK;
}

static
ngx_int_t ngx_http_sml_init(ngx_conf_t *cf)
{
	if (ngx_http_lua_add_package_preload(cf, "sml",
	                                     ngx_http_sml_inject_api)
	        != NGX_OK)
	    {
	        return NGX_ERROR;
	    }

	return NGX_OK;
}

static char *
ngx_http_sml_sml_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sml_loc_conf_t *slcf = conf;
    ngx_http_sml_log_conf_t *lgcf = slcf->log_conf;
    ngx_str_t  *value, name;

    if (lgcf) {
        return "is duplicate";
    }

    lgcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sml_log_conf_t));
    if (lgcf == NULL) {
        return NGX_CONF_ERROR;
    }
    /* set by pcalloc
       lgcf->log_tail = 0
     */
    slcf->log_conf = lgcf;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "stderr") == 0) {
        ngx_str_null(&name);

    } else {
        name = value[1];
    }

    lgcf->log = ngx_log_create(cf->cycle, &name);
    if (lgcf->log == NULL) {
        return NGX_CONF_ERROR;
    }
    return ngx_sml_log_set(cf, slcf->log_conf);
}

static void *
ngx_http_sml_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sml_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sml_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     * conf->log_conf = NULL;
     */

    return conf;
}


static char *
ngx_http_sml_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sml_loc_conf_t  *prev = parent;
    ngx_http_sml_loc_conf_t  *conf = child;

    if (conf->log_conf == NULL) {
		if (prev->log_conf) {
			conf->log_conf = prev->log_conf;
		} else {
			conf->log_conf = default_log;
		}
    }

    return NGX_CONF_OK;
}


static char *
ngx_sml_log_set(ngx_conf_t *cf, ngx_http_sml_log_conf_t *lgcf)
{
    ngx_uint_t   i, n, d, found;
    ngx_str_t   *value;
    ngx_log_t 	*log;

    log = lgcf->log;
    value = cf->args->elts;

    log->handler = ngx_http_sml_log_error;
    if (cf->args->nelts == 2) {
        log->log_level = DEFAULT_LEVEL;
        return NGX_CONF_OK;
    }

    i = 2;
    if (ngx_strncmp(value[i].data, "tail=o", 6) == 0) {
        if (ngx_strcmp(value[i].data + 6, "n") == 0) {
        	lgcf->log_tail = 1;

        } else if (ngx_strcmp(value[i].data + 6, "ff") == 0) {
        	lgcf->log_tail = 0;

        } else {
        	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        			          "invalid tail flags \"%s\"",
        			           &value[i].data + 5);
        	return NGX_CONF_ERROR;
        }
        i++;
    }

    for (; i < cf->args->nelts; i++) {
        found = 0;

        for (n = 1; n <= NGX_LOG_DEBUG; n++) {
            if (ngx_strcmp(value[i].data, err_levels[n].data) == 0) {

                if (log->log_level != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level = n;
                found = 1;
                break;
            }
        }

        for (n = 0, d = NGX_LOG_DEBUG_FIRST; d <= NGX_LOG_DEBUG_LAST; d <<= 1) {
            if (ngx_strcmp(value[i].data, debug_levels[n++]) == 0) {
                if (log->log_level & ~NGX_LOG_DEBUG_ALL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level |= d;
                found = 1;
                break;
            }
        }


        if (!found) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid log level or option \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    if (log->log_level == NGX_LOG_DEBUG) {
        log->log_level = NGX_LOG_DEBUG_ALL;
    } else if(log->log_level == 0) {
    	log->log_level = DEFAULT_LEVEL;
    }

    return NGX_CONF_OK;
}


#if defined(nginx_version) && nginx_version >= 1005002
static ngx_log_t *
ngx_log_create(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_log_t  *log;

    log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        return NULL;
    }

    log->file = ngx_conf_open_file(cycle, name);
    if (log->file == NULL) {
        return NULL;
    }

    return log;
}
#endif


static ngx_int_t
ngx_http_get_argument(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t *name = (ngx_str_t *) data;
    ngx_str_t   value;

    if (ngx_http_arg(r, name->data, name->len, &value) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = value.data;
    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static u_char *
ngx_http_sml_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                      *p;
    ngx_http_request_t          *r;
    ngx_http_log_ctx_t          *ctx;
    ngx_http_sml_loc_conf_t	    *slcf;
    ngx_http_request_body_t     *rb;
    ngx_http_variable_value_t    vv;
    ngx_chain_t                 *tmp;
    ngx_list_part_t             *part;
    ngx_table_elt_t             *data;
    ngx_uint_t					 i;

    static ngx_str_t   uri = ngx_string("debug_uri");
    static ngx_str_t   body = ngx_string("debug_body");
    static ngx_str_t   header = ngx_string("debug_header");

    p = buf;
    ctx = log->data;
    if (!ctx) {
    	return p;
    }

    r = ctx->request;
    if (!r) {
        return p;
    }

    if (log->log_level == NGX_LOG_DEBUG_ALL) {
        ngx_http_get_argument(r, &vv, (uintptr_t) &uri);
        if (!vv.not_found) {
            p = ngx_snprintf(buf, len, ", uri: %V", &r->request_line);
            len -= p - buf;
            buf = p;
        }

        ngx_http_get_argument(r, &vv, (uintptr_t) &body);
        rb = r->request_body;
        if (!vv.not_found && rb != NULL && rb->bufs != NULL) {
            p = ngx_snprintf(buf, len, ", body: ");
            len -= p - buf;
            buf = p;
            tmp = rb->bufs;
            while (tmp != NULL) {
                p = ngx_snprintf(buf, len, "%*s", tmp->buf->last - tmp->buf->pos, tmp->buf->pos);
                len -= p - buf;
                buf = p;
                tmp = tmp->next;
            }
        }

        ngx_http_get_argument(r, &vv, (uintptr_t) &header);
        if (!vv.not_found) {
            part = &r->headers_in.headers.part;
            data = part->elts;

            for (i = 0; /* void */; i++) {
                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    data = part->elts;
                    i = 0;
                }
                if (vv.len == 1 && vv.data[0] == '*') {
                    p = ngx_snprintf(buf, len, ", %V: %V", &data[i].key, &data[i].value);
                    len -= p - buf;
                    buf = p;
                    continue; 
                }

                if (data[i].key.len != vv.len) {
                    continue;
                }

                if (ngx_strncmp(data[i].lowcase_key, vv.data, vv.len) == 0) {
                    p = ngx_snprintf(buf, len, ", %V: %V", &data[i].key, &data[i].value);
                    len -= p - buf;
                    buf = p;
                    break;
                }
            }
        }
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_sml_module);
    
    if (!slcf->log_conf->log_tail) {
    	return p;
    }

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
    }

    p = ngx_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    if (r->log_handler) {
        return r->log_handler(r, ctx->current_request, p, len);
    }
    return p;
}

