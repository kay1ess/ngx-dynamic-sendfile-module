/*
 * @Author: kay 
 * @Date: 2021-03-18 14:21:10 
 */


#include <nginx.h>
#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_core.h>
#include <ngx_conf_file.h>
#include "ddebug.h"


typedef struct ngx_http_dynamic_sendfile_ctx_s ngx_http_dynamic_sendfile_ctx_t;

static void *ngx_http_dynamic_sendfile_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dynamic_sendfile_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_dynamic_sendfile_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_int_t ngx_http_dynamic_sendfile_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_dynamic_sendfile_header_needed(ngx_http_request_t *r);
static void ngx_http_dynamic_sendfile_add_cleanup(ngx_http_request_t *r);
void ngx_http_dynamic_sendfile_send_handler(ngx_event_t *ev);
void ngx_http_dynamic_sendfile_timeout_handler(ngx_event_t *ev);
ngx_int_t ngx_is_file_write_done(ngx_http_dynamic_sendfile_ctx_t *ctx);

typedef struct {
    ngx_str_t                   file_suffix;
    ngx_msec_t                  dy_send_interval;
    ngx_msec_t                  dy_send_timeout;
} ngx_http_dynamic_sendfile_loc_conf_t;


typedef struct ngx_http_dynamic_sendfile_ctx_s {
    ngx_event_t                 read_evt;                  /* read file */
    ngx_event_t                 timeout_evt;
    ngx_str_t                   *writing_filename;
    ngx_str_t                   *finished_filename;
    ngx_buf_t                   *file_buf;
    off_t                       offset;
} ngx_http_dynamic_sendfile_ctx_s;


static ngx_command_t ngx_http_dynamic_sendfile_commands[] = {
    {
        ngx_string("file_suffix"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dynamic_sendfile_loc_conf_t, file_suffix),
        NULL
    },
    {
        ngx_string("dy_send_interval"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dynamic_sendfile_loc_conf_t, dy_send_interval),
        NULL
    },
     {
        ngx_string("dy_send_timeout"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dynamic_sendfile_loc_conf_t, dy_send_timeout),
        NULL
    },
    {
        ngx_string("dy_send_file"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_dynamic_sendfile_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};


static ngx_http_module_t ngx_http_dynamic_sendfile_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    ngx_http_dynamic_sendfile_create_loc_conf,  /* create location configuration */
    ngx_http_dynamic_sendfile_merge_loc_conf    /* merge location configuration */
};


ngx_module_t ngx_http_dynamic_sendfile_module = {
    NGX_MODULE_V1,
    &ngx_http_dynamic_sendfile_module_ctx,      /* module context */
    ngx_http_dynamic_sendfile_commands,         /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_dynamic_sendfile_create_loc_conf(ngx_conf_t *cf) 
{
    ngx_http_dynamic_sendfile_loc_conf_t        *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dynamic_sendfile_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->dy_send_interval = NGX_CONF_UNSET_MSEC;
    conf->dy_send_timeout = NGX_CONF_UNSET_MSEC;
    return conf;
}


static char *
ngx_http_dynamic_sendfile_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dynamic_sendfile_loc_conf_t        *prev = parent;
    ngx_http_dynamic_sendfile_loc_conf_t        *conf = child;

    ngx_conf_merge_str_value(conf->file_suffix, prev->file_suffix, ".tmp");
    ngx_conf_merge_msec_value(conf->dy_send_interval, prev->dy_send_interval, 100); /* default 100ms */
    ngx_conf_merge_msec_value(conf->dy_send_timeout, prev->dy_send_timeout, 10000); /* default 10s */
    return NGX_CONF_OK;
}


static char *
ngx_http_dynamic_sendfile_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_http_dynamic_sendfile_loc_conf_t            *dscf;
    ngx_http_core_loc_conf_t                        *clcf;

    dscf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_dynamic_sendfile_module);
    if (dscf == NULL) {
        return NGX_CONF_ERROR;
    }
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (clcf == NULL) {
        return NGX_CONF_ERROR;
    }
    /* register content handler */
    clcf->handler = ngx_http_dynamic_sendfile_handler;
    return NGX_CONF_OK;
}


ngx_http_dynamic_sendfile_ctx_t *
ngx_http_dynamic_sendfile_create_ctx(ngx_http_request_t *r) 
{
    ngx_http_dynamic_sendfile_ctx_t         *ctx;
    ngx_http_dynamic_sendfile_loc_conf_t    *dscf;
    size_t                                  root;
    ngx_str_t                               path;
    u_char                                  *last;

    dscf = ngx_http_get_module_loc_conf(r, ngx_http_dynamic_sendfile_module);
    if (dscf == NULL || dscf->file_suffix.len == 0 || dscf->file_suffix.data == NULL) {
        return NULL;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dynamic_sendfile_ctx_t));
    if (ctx == NULL) {
        return ctx;
    }
    /* get full path according to uri */
    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NULL;
    }

    path.len = last - path.data;

    /* create finish filename */
    ctx->finished_filename = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (ctx->finished_filename == NULL) {
        return NULL;
    }

    ctx->finished_filename->data = ngx_palloc(r->pool, path.len);
    if (ctx->finished_filename->data == NULL) {
        return NULL;
    }

    ngx_memcpy(ctx->finished_filename->data, path.data, path.len);
    ctx->finished_filename->len = path.len;

    /* create writing filename */
    ctx->writing_filename = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (ctx->writing_filename == NULL) {
        return NULL;
    }

    ctx->writing_filename->data = ngx_palloc(r->pool, path.len + dscf->file_suffix.len);

    ngx_memcpy(ctx->writing_filename->data, path.data, path.len);
    ngx_memcpy(ctx->writing_filename->data + path.len, dscf->file_suffix.data, dscf->file_suffix.len);
    ctx->writing_filename->len = path.len + dscf->file_suffix.len;

    ctx->file_buf = ngx_calloc_buf(r->pool);
    if (ctx->file_buf == NULL) {
        return NULL;
    }
    ctx->file_buf->in_file = 1;
    ctx->file_buf->file = ngx_palloc(r->pool, sizeof(ngx_file_t));
    if (ctx->file_buf->file == NULL) {
        return NULL;
    }
    ctx->file_buf->file->log = r->connection->log;
    ctx->file_buf->file->name.data = ctx->writing_filename->data;
    ctx->file_buf->file->name.len = ctx->writing_filename->len;

    /* register event handler */
    ctx->read_evt.handler = ngx_http_dynamic_sendfile_send_handler;
    ctx->read_evt.data = r;
    ctx->read_evt.log = r->connection->log;
    ctx->timeout_evt.handler = ngx_http_dynamic_sendfile_timeout_handler;
    ctx->timeout_evt.data = r;
    ctx->timeout_evt.log = r->connection->log;
    ctx->offset = 0;

    return ctx;
}


ngx_int_t
ngx_http_dynamic_sendfile_handler(ngx_http_request_t *r)
{
    ngx_http_dynamic_sendfile_ctx_t         *ctx;
    ngx_http_dynamic_sendfile_loc_conf_t    *dscf;

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

   /* chunked transfer not support below http/1.1*/
    if (r->http_version < NGX_HTTP_VERSION_11) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, ngx_errno,
                        "chunked transfer need http/1.1 but now http version is '%V', now try open static file", 
                        &r->http_protocol);
        return NGX_DECLINED;
    } 

    if (ngx_http_discard_request_body(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "ngx_http_discard_request_body() failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    dscf = ngx_http_get_module_loc_conf(r, ngx_http_dynamic_sendfile_module);
    if (dscf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_sendfile_module);
    if (ctx == NULL) {
        ctx = ngx_http_dynamic_sendfile_create_ctx(r);
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_dynamic_sendfile_module);
    }

    /* make sure file path is right */
    *(ctx->finished_filename->data + ctx->finished_filename->len) = 0;
    *(ctx->writing_filename->data + ctx->writing_filename->len) = 0;
    
    r->read_event_handler = ngx_http_test_reading;
    
    if (ngx_is_file_write_done(ctx) == NGX_OK) { 
        dd("the file(%s) existed, next to static file handler", ctx->finished_filename->data);
        return NGX_DECLINED;
    }

    /* open file */
    ctx->file_buf->file->fd = ngx_open_file(ctx->writing_filename->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);
    if (ctx->file_buf->file->fd <= 0) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "open tmp file(%V) failed, try to open finished file(%V)", ctx->writing_filename, ctx->finished_filename);
        return NGX_DECLINED;
    }

    /* send http reponse header */
    if (ngx_http_dynamic_sendfile_header_needed(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->main->count++;

    ngx_add_timer(&ctx->read_evt, dscf->dy_send_interval);

    ngx_http_dynamic_sendfile_add_cleanup(r);

    return NGX_DONE;
}


ngx_int_t
ngx_is_file_write_done(ngx_http_dynamic_sendfile_ctx_t *ctx)
{
    /* whether the file write done according it's name */
    ngx_str_t           *finished_name = ctx->finished_filename;
    off_t               size; 

    ngx_file_info_t                     fi;

    ngx_file_info(finished_name->data, &fi);

    if (ngx_is_file(&fi)) {
        ctx->file_buf->file->name = *finished_name;
    } else {
        return NGX_ERROR;
    }
    
    size = ngx_file_size(&fi);

    if (size > 0 && (size == ctx->offset || ctx->offset == 0)) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_http_dynamic_sendfile_header_needed(ngx_http_request_t *r)
{
    dd("ngx_http_dynamic_sendfile_header_needed");
    if (!r->header_sent) {
        r->headers_out.status = NGX_HTTP_OK;
        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        /* Need these for chunked transfer */
        ngx_http_clear_content_length(r);
        ngx_http_clear_accept_ranges(r);
        return ngx_http_send_header(r);
    }
    return NGX_OK;
}


ngx_int_t
ngx_http_sendfile_contents(ngx_http_request_t *r) 
{

    /* read file and send to client */
    ngx_http_dynamic_sendfile_ctx_t         *ctx;
    ngx_chain_t                             *out;
    ngx_http_dynamic_sendfile_loc_conf_t    *dscf;
    long                                    size;
    ngx_connection_t                        *c;

    dd("ngx_http_sendfile_contents");

    c = r->connection;
    if (!c->write || c->error || c->destroyed) {
        return NGX_ERROR;
    }

    dscf = ngx_http_get_module_loc_conf(r, ngx_http_dynamic_sendfile_module);
    if (dscf == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_sendfile_module);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_file_info(ctx->file_buf->file->name.data, &ctx->file_buf->file->info) == NGX_FILE_ERROR) {
        return NGX_ERROR;
    }

    size = ctx->file_buf->file->info.st_size;
    dd("size=%lld ctx->offset=%lld", size, ctx->offset);
    if (size == ctx->offset || size == 0) {
        return NGX_AGAIN;
    }

    ctx->file_buf->file_pos = ctx->offset;
    ctx->file_buf->file_last = size;
    ctx->offset = size;
    ctx->file_buf->flush = 1;


    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out->buf = ctx->file_buf;
    out->next = NULL;

    return ngx_http_output_filter(r, out);
}


static void 
ngx_http_dynamic_sendfile_cleanup_timers(void* data)
{
    ngx_http_request_t              *r = data;
    ngx_http_dynamic_sendfile_ctx_t *ctx;
    if (r == NULL) {
        return;
    }

    dd("ngx_http_dynamic_sendfile_cleanup_timers");

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_sendfile_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->read_evt.timer_set) {
        ngx_del_timer(&ctx->read_evt);
    }

    if (ctx->timeout_evt.timer_set) {
        ngx_del_timer(&ctx->timeout_evt);
    }
}


static void 
ngx_http_dynamic_sendfile_add_cleanup(ngx_http_request_t *r)
{
    ngx_http_cleanup_t              *cln;
    ngx_pool_cleanup_t              *cln2;
    ngx_http_dynamic_sendfile_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_sendfile_module);
    if (ctx == NULL) {
        return;
    }

    dd("ngx_http_dynamic_sendfile_add_cleanup");

    /* request cleanup */
    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return;
    }
    cln->handler = ngx_http_dynamic_sendfile_cleanup_timers;
    cln->data = r;

    /* cleanup opening file */
    cln2 = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln2 == NULL) {
        return;
    }
    cln2->handler = ngx_pool_cleanup_file;
    ngx_pool_cleanup_file_t *clnf = cln2->data;
    clnf->fd = ctx->file_buf->file->fd;
    clnf->log = r->pool->log;
}


void
ngx_http_dynamic_sendfile_send_handler(ngx_event_t *ev)
{
    ngx_connection_t                        *c;
    ngx_http_request_t                      *r;
    ngx_http_dynamic_sendfile_ctx_t         *ctx;
    ngx_http_dynamic_sendfile_loc_conf_t    *dscf;
    ngx_int_t                               rc;

    dd("ngx_http_dynamic_sendfile_send_handler");

    r = ev->data;
    c = r->connection;

    if (c->destroyed) {
        return;
    }

    if (c->error) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    dscf = ngx_http_get_module_loc_conf(r, ngx_http_dynamic_sendfile_module);
    if (dscf == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_sendfile_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (ngx_is_file_write_done(ctx) == NGX_OK) {
        dd("the file(%s) is written, send last chunked", ctx->finished_filename->data);
        ngx_http_send_special(r, NGX_HTTP_LAST);
        ngx_http_finalize_request(r, NGX_OK);
    } else {
        rc = ngx_http_sendfile_contents(r);
        if (rc == NGX_ERROR) {
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }
        if (rc == NGX_AGAIN && !ctx->timeout_evt.timer_set) {
            ngx_add_timer(&ctx->timeout_evt, dscf->dy_send_timeout);
        }

        if (rc == NGX_OK) {
            dd("the file(%s) is writting, add timer", ctx->file_buf->file->name.data);
            ngx_add_timer(&ctx->read_evt, dscf->dy_send_interval);

            if (ctx->timeout_evt.timer_set && !ctx->timeout_evt.timedout) {
                ngx_del_timer(&ctx->timeout_evt);
            }
        }
    }
}


void
ngx_http_dynamic_sendfile_timeout_handler(ngx_event_t *ev) 
{
    ngx_connection_t                        *c;
    ngx_http_request_t                      *r;
    ngx_http_dynamic_sendfile_ctx_t         *ctx;
    ngx_http_dynamic_sendfile_loc_conf_t    *dscf;

    dd("ngx_http_dynamic_sendfile_timeout_handler");

    r = ev->data;
    c = r->connection;

    if (c->destroyed) {
        return;
    }

    if (c->error) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    dscf = ngx_http_get_module_loc_conf(r, ngx_http_dynamic_sendfile_module);
    if (dscf == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_sendfile_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "sendfile timed out, cause finished file(%V) not get", ctx->finished_filename);

    /* stop request */
    ngx_http_send_special(r, NGX_HTTP_LAST);
    ngx_http_finalize_request(r, NGX_OK);
}