
#include "ngx_http_slock_module.h"
#include "ngx_http_slock_shm.h"

typedef struct ngx_http_slock_sh_s {
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
} ngx_http_slock_sh_t;

static ngx_shm_zone_t *ngx_http_slock_shm_zone = NULL;

static ngx_int_t ngx_http_slock_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_slock_sh_t *sst;
    ngx_slab_pool_t *pool = (ngx_slab_pool_t*)shm_zone->shm.addr;

    if (data) { /** nginx -s reload **/
        shm_zone->data = data;
        ngx_http_slock_shm_zone = shm_zone;
        return NGX_OK;
    }

    if ((sst = ngx_slab_alloc(pool, sizeof(ngx_http_slock_sh_t))) == NULL) {
        return NGX_ERROR;
    }

    shm_zone->data = sst;
    ngx_rbtree_init(&sst->rbtree, &sst->sentinel, ngx_rbtree_insert_value);
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

ngx_rbtree_node_t *ngx_http_slock_rbtree_find(ngx_rbtree_t *tree, ngx_uint_t key)
{
    ngx_rbtree_node_t *root = tree->root;

    while (root != tree->sentinel) {
        if (key == root->key) {
            return root;
        }
        root = (key < root->key) ? root->left : root->right;
    }
    return NULL;
}


ngx_int_t ngx_http_slock_shm_add(ngx_str_t *str_key)
{
    ngx_shm_zone_t *shm_zone = ngx_http_slock_shm_zone;
    ngx_http_slock_sh_t *sst = shm_zone->data;
    ngx_slab_pool_t *pool = (ngx_slab_pool_t*)shm_zone->shm.addr;
    ngx_rbtree_node_t *node;

    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);

    /** TODO: Lock **/
    ngx_shmtx_lock(&pool->mutex);
    if ((node = ngx_http_slock_rbtree_find(&sst->rbtree, key)) != NULL) {
        ngx_shmtx_unlock(&pool->mutex);
        ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, 0, "[%s:%d] existed.", __FUNCTION__, __LINE__);
        return NGX_ERROR;   // existed
    }

    if ((node = ngx_slab_alloc_locked(pool, sizeof(ngx_rbtree_node_t))) == NULL) {
        ngx_shmtx_unlock(&pool->mutex);
        return NGX_ERROR; // no memory.
    }
    node->key = key;
    ngx_rbtree_insert(&sst->rbtree, node);
    ngx_shmtx_unlock(&pool->mutex);

    return NGX_OK;
}

ngx_int_t ngx_http_slock_shm_del(ngx_str_t *str_key)
{
    ngx_shm_zone_t *shm_zone = ngx_http_slock_shm_zone;
    ngx_http_slock_sh_t *sst = shm_zone->data;
    ngx_slab_pool_t *pool = (ngx_slab_pool_t*)shm_zone->shm.addr;
    ngx_rbtree_node_t *node;

    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);

    /** TODO: Lock **/
    ngx_shmtx_lock(&pool->mutex);
    if ((node = ngx_http_slock_rbtree_find(&sst->rbtree, key)) == NULL) {
        ngx_shmtx_unlock(&pool->mutex);
        return NGX_ERROR;   // non-existed
    }
    ngx_rbtree_delete(&sst->rbtree, node);
    ngx_shmtx_unlock(&pool->mutex);
    return NGX_OK;
}


