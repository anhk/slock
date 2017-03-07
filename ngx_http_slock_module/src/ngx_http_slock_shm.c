
#include "ngx_http_slock_module.h"
#include "ngx_http_slock_shm.h"

typedef struct ngx_http_slock_sh_s {
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
} ngx_http_slock_sh_t;

static ngx_shm_zone_t *ngx_http_slock_shm_zone = NULL;

static ngx_int_t ngx_http_slock_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, 0, "[%s:%d]", __FUNCTION__, __LINE__);
    ngx_http_slock_shm_zone = shm_zone;
    return NGX_OK;
}


ngx_int_t ngx_http_slock_shm_init(ngx_conf_t *cf)
{
    size_t size = ngx_align(256*1024*1024, ngx_pagesize);
    ngx_str_t ngx_http_slock_shm_name = ngx_string("ngx_http_slock_shm");

    ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &ngx_http_slock_shm_name,
            size, &ngx_http_slock_module);

    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    shm_zone->init = ngx_http_slock_init_shm_zone;
    shm_zone->data = (void *) 1;

    return NGX_OK;
}


ngx_int_t ngx_http_slock_shm_add(ngx_str_t *key)
{
    return NGX_OK;
}

ngx_int_t ngx_http_slock_shm_del(ngx_str_t *key)
{
    return NGX_OK;
}
