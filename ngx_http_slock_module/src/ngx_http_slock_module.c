


#include "ngx_http_slock_module.h"
#include "ngx_http_slock_lock.h"
#include "ngx_http_slock_shm.h"
#include "ngx_http_slock_ipc.h"

/**********************************/
/***  Definitions                **/
/**********************************/

typedef struct {
    ngx_uint_t slock;           /** on/off **/
} ngx_http_slock_srv_conf_t;

static ngx_int_t ngx_http_slock_init_module(ngx_cycle_t *cycle);
static void * ngx_http_slock_create_srv_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_slock_content_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_slock_init_pre_config(ngx_conf_t *cf);
static ngx_int_t ngx_http_slock_init_post_config(ngx_conf_t *cf);
static ngx_int_t ngx_http_slock_init_worker(ngx_cycle_t *cycle);

/**********************************/
/**********************************/
static ngx_command_t  ngx_http_slock_commands[] = {
    { ngx_string("slock"),
        NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_slock_srv_conf_t, slock),
        NULL },
};

static ngx_http_module_t ngx_http_slock_module_ctx = {
    ngx_http_slock_init_pre_config, /* preconfiguration */
    ngx_http_slock_init_post_config,/* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    ngx_http_slock_create_srv_conf, /* create server configuration */
    NULL,                           /* merge server configuration */

    NULL,                           /* create location configuration */
    NULL                            /* merge location configuration */
};


ngx_module_t ngx_http_slock_module = {
    NGX_MODULE_V1,
    &ngx_http_slock_module_ctx,     /* module context */
    ngx_http_slock_commands,        /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    ngx_http_slock_init_module,     /* init module */
    ngx_http_slock_init_worker,     /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_http_slock_init_module(ngx_cycle_t *cycle)
{
    ngx_int_t rc;
    /** 在master/init_module阶段 初始化IPC **/
    ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if ((rc = ngx_http_slock_ipc_init(cycle, ccf->worker_processes)) == NGX_OK) {
    }
    return rc;
}

static ngx_int_t ngx_http_slock_init_worker(ngx_cycle_t *cycle)
{
    ngx_int_t rc;
    /** 在worker阶段 初始化IPC **/
    if ((rc = ngx_http_slock_ipc_init_worker(cycle)) != NGX_OK) {
        return NGX_ERROR;
    }
    return rc;
}

static void * ngx_http_slock_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_slock_srv_conf_t *sscf;

    if ((sscf = ngx_pcalloc(cf->pool,
                    sizeof(ngx_http_slock_srv_conf_t))) == NULL) {
        return NULL;
    }
    sscf->slock = NGX_CONF_UNSET;
    return sscf;
}

static ngx_int_t ngx_http_slock_content_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_slock_srv_conf_t *sscf;

    if ((sscf = ngx_http_get_module_srv_conf(r, ngx_http_slock_module)) == NULL) {
        return NGX_DECLINED;
    }

    if (sscf->slock != 1) {
        return NGX_DECLINED;
    }

    if (r->method == NGX_HTTP_GET) { /** GET **/
        ngx_http_slock_ipc_alert(r->connection->log);
        rc = ngx_http_slock_lock(r);
    } else if (r->method == NGX_HTTP_PUT) { /** PUT **/
        rc = ngx_http_slock_unlock(r);
    } else {
        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        return NGX_OK;
    }

    if (rc == NGX_DONE) { /** 挂住 **/
        return rc;
    } else if (rc == NGX_ERROR) { /** 失败 **/
        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        return NGX_OK;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, rc);
    } else {
        r->keepalive = 1;
    }
    return rc;
}

static ngx_int_t ngx_http_slock_init_post_config(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t       *cmcf;
    ngx_http_handler_pt             *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) { return NGX_ERROR; }
    *h = ngx_http_slock_content_handler;

    return NGX_OK;
}

static ngx_int_t ngx_http_slock_init_pre_config(ngx_conf_t *cf)
{
    if (ngx_http_slock_shm_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

