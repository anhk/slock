

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_uint_t slock;           /** on/off **/
} ngx_http_slock_srv_conf_t;

static ngx_int_t ngx_http_slock_content_handler(ngx_http_request_t *r)
{
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
    //return NGX_DECLINED;
}


static ngx_int_t ngx_http_slock_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t       *cmcf;
    ngx_http_handler_pt             *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_slock_content_handler;
    return NGX_OK;
}


static void * ngx_http_slock_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_slock_srv_conf_t *smct;

    if ((smct = ngx_pcalloc(cf->pool,
                    sizeof(ngx_http_slock_srv_conf_t))) == NULL) {
        return NULL;
    }
    smct->slock = NGX_CONF_UNSET;
    return smct;
}

static ngx_command_t  ngx_http_slock_commands[] = {
    { ngx_string("slock"),
        NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_slock_srv_conf_t, slock),
        NULL },
};

static ngx_http_module_t ngx_http_slock_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_slock_init,            /* postconfiguration */

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
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

