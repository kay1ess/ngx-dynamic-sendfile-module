/*
 * @Author: kay 
 * @Date: 2021-03-18 14:21:10 
 */


#include <nginx.h>
#include <ngx_config.h>
#include <ngx_http.h>
#include <ngx_core.h>
#include <ngx_conf_file.h>


static void *ngx_http_dynamic_sendfile_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dynamic_sendfile_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_dynamic_sendfile_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_int_t ngx_http_dynamic_sendfile_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_dynamic_sendfile_header_needed(ngx_http_request_t *r);
static void ngx_http_dynamic_sendfile_add_cleanup(ngx_http_request_t *r);
void ngx_http_dynamic_sendfile_event_handler(ngx_event_t *ev);
ngx_int_t ngx_is_file_write_done(ngx_str_t *finished_name);

typedef struct {
    ngx_str_t                   file_suffix;
    ngx_msec_t                  dy_send_interval;
    size_t                      dy_send_buffer;
} ngx_http_dynamic_sendfile_loc_conf_t;


typedef struct {
    ngx_event_t                 read_evt;                  /* read file */
    ngx_str_t                   *writing_filename;
    ngx_str_t                   *finished_filename;
    ngx_fd_t                    fd;
} ngx_http_dynamic_sendfile_ctx_t;


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
        ngx_string("dy_send_file"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_dynamic_sendfile_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("dy_send_buffer"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_dynamic_sendfile_loc_conf_t, dy_send_buffer),
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
    conf->dy_send_buffer = NGX_CONF_UNSET_SIZE;
    return conf;
}


static char *
ngx_http_dynamic_sendfile_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dynamic_sendfile_loc_conf_t        *prev = parent;
    ngx_http_dynamic_sendfile_loc_conf_t        *conf = child;

    ngx_conf_merge_str_value(conf->file_suffix, prev->file_suffix, ".tmp");
    ngx_conf_merge_msec_value(conf->dy_send_interval, prev->dy_send_interval, 100); /* default 100ms */
    ngx_conf_merge_size_value(conf->dy_send_buffer, prev->dy_send_buffer, 1024*10);  /* default 10k */ 
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

    /* register event handler */
    ctx->read_evt.handler = ngx_http_dynamic_sendfile_event_handler;
    ctx->read_evt.data = r;
    ctx->read_evt.log = r->connection->log;

    return ctx;
}


ngx_int_t
ngx_http_dynamic_sendfile_handler(ngx_http_request_t *r)
{
    ngx_int_t                               rc;
    ngx_http_dynamic_sendfile_ctx_t         *ctx;
    ngx_http_dynamic_sendfile_loc_conf_t    *dscf;

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* chunked transfer not support below http/1.1*/
    if (r->http_version < NGX_HTTP_VERSION_11) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (ngx_http_discard_request_body(r) != NGX_OK) {
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
        /* open file */
        ctx->fd = ngx_open_file(ctx->writing_filename->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);
        if (ctx->fd < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "open file error '%V'", ctx->writing_filename);
            return NGX_HTTP_NOT_FOUND;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_dynamic_sendfile_module);
    }

    /* send http reponse header */
    if (ngx_http_dynamic_sendfile_header_needed(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->main->count++;

    ngx_add_timer(&ctx->read_evt, dscf->dy_send_interval);

    ngx_http_dynamic_sendfile_add_cleanup(r);

    return rc;
}


ngx_int_t
ngx_is_file_write_done(ngx_str_t *finished_name)
{
    /* whether the file write done according it's name */
    ngx_file_info_t                     fi;

    ngx_file_info(finished_name->data, &fi);

    if (ngx_is_file(&fi)) {
        return NGX_OK;
    }
    return NGX_ERROR;
}


ngx_int_t
ngx_http_dynamic_sendfile_header_needed(ngx_http_request_t *r)
{
    ngx_log_stderr(0, "ngx_http_dynamic_sendfile_header_needed");
    if (!r->header_sent) {
        r->keepalive = 0;
        r->headers_out.status = NGX_HTTP_OK;
        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        /* chunked transfer */
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
    ngx_buf_t                               *buf;
    ngx_chain_t                             *out;
    ngx_http_dynamic_sendfile_loc_conf_t    *dscf;
    size_t                                  n;

    ngx_log_stderr(0, "ngx_http_sendfile_contents");

    dscf = ngx_http_get_module_loc_conf(r, ngx_http_dynamic_sendfile_module);
    if (dscf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_sendfile_module);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf = ngx_create_temp_buf(r->pool, dscf->dy_send_buffer);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    n = ngx_read_fd(ctx->fd, buf->pos, dscf->dy_send_buffer);
    buf->last = buf->end = buf->pos + n;
    buf->temporary = 1;
    buf->flush = 1;

    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out->buf = buf;
    out->next = NULL;

    return ngx_http_output_filter(r, out);
}


static void 
ngx_http_dynamic_sendfile_cleanup_timer(void* data)
{
    ngx_http_request_t              *r = data;
    ngx_http_dynamic_sendfile_ctx_t *ctx;
    if (r == NULL) {
        return;
    }

    ngx_log_stderr(0, "ngx_http_dynamic_sendfile_cleanup_timer");

    ctx = ngx_http_get_module_ctx(r, ngx_http_dynamic_sendfile_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->read_evt.timer_set) {
        ngx_del_timer(&ctx->read_evt);
        return;
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

    ngx_log_stderr(0, "ngx_http_dynamic_sendfile_add_cleanup");

    /* request cleanup */
    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return;
    }
    cln->handler = ngx_http_dynamic_sendfile_cleanup_timer;
    cln->data = r;

    /* cleanup opening file */
    cln2 = ngx_pool_cleanup_add(r, sizeof(ngx_pool_cleanup_file_t));
    if (cln2 == NULL) {
        return;
    }
    cln2->handler = ngx_pool_cleanup_file;
    ngx_pool_cleanup_file_t *clnf = cln2->data;
    clnf->fd = ctx->fd;
    clnf->log = r->pool->log;

}



void
ngx_http_dynamic_sendfile_event_handler(ngx_event_t *ev)
{
    ngx_connection_t                        *c;
    ngx_http_request_t                      *r;
    ngx_http_dynamic_sendfile_ctx_t         *ctx;
    ngx_http_dynamic_sendfile_loc_conf_t    *dscf;

    ngx_log_stderr(0, "ngx_http_dynamic_sendfile_event_handler");

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

    if (ngx_is_file_write_done(ctx->finished_filename) == NGX_OK) {
        ngx_http_send_special(r, NGX_HTTP_LAST);
        ngx_http_finalize_request(r, NGX_OK);
    } else {
        ngx_http_sendfile_contents(r);
        ngx_add_timer(&ctx->read_evt, dscf->dy_send_interval);
    }
}