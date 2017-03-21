
#include "ngx_http_slock_module.h"
#include "ngx_http_slock_shm.h"

typedef struct ngx_http_slock_sh_s {
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
    ngx_queue_t queue;  /** ordered by timestamp **/
} ngx_http_slock_sh_t;

typedef struct ngx_http_slock_sh_node_s {
    ngx_queue_t qnode;  /** add to queue **/
    ngx_rbtree_node_t rbnode; /** add to rbtree, it contains the key **/
    ngx_uint_t key;     /** my key **/
    time_t last;        /** 创建节点的时间 **/
} ngx_http_slock_sh_node_t;

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
    ngx_queue_init(&sst->queue);
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


static void ngx_http_slock_shm_timer_handler(ngx_event_t *timer)
{
    ngx_shm_zone_t *shm_zone = ngx_http_slock_shm_zone;
    ngx_http_slock_sh_t *sst = shm_zone->data;
    ngx_slab_pool_t *pool = (ngx_slab_pool_t*)shm_zone->shm.addr;

    shm_timeout_rb callback = timer->data;

    ngx_http_slock_sh_node_t *node;
    ngx_queue_t queue, *q, *next;
    ngx_queue_init(&queue);

    time_t now = ngx_time();

    /** Scan sst->queue **/
    ngx_shmtx_lock(&pool->mutex);
    q = ngx_queue_head(&sst->queue);
    while (q != ngx_queue_sentinel(&sst->queue)) {
        next = ngx_queue_next(q);
        node = container_of(q, ngx_http_slock_sh_node_t, qnode);
        if (now - node->last < 60) {
            break;
        }
        ngx_rbtree_delete(&sst->rbtree, &node->rbnode);
        ngx_queue_remove(q);
        ngx_queue_insert_tail(&queue, q);

        q = next;
    }
    ngx_shmtx_unlock(&pool->mutex);

    /** 拿到了所有过期的节点 **/
    while (!ngx_queue_empty(&queue)) {
        q = ngx_queue_head(&queue);
        node = container_of(q, ngx_http_slock_sh_node_t, qnode);
        ngx_queue_remove(q);

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d], delete %uD",
                __FUNCTION__, __LINE__, node->key);

        callback(node->key);

        ngx_slab_free_locked(pool, node);
    }

    ngx_add_timer(timer, 2000);
}

ngx_int_t ngx_http_slock_shm_init_worker(ngx_cycle_t *cycle,
        shm_timeout_rb callback)
{
    ngx_event_t *timer;
    if ((timer = ngx_calloc(sizeof(ngx_event_t), cycle->log)) == NULL) {
        return NGX_ERROR;
    }
    timer->handler = ngx_http_slock_shm_timer_handler;
    timer->log = ngx_cycle->log;
    timer->data = callback;

    ngx_add_timer(timer, 2000);
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


ngx_int_t ngx_http_slock_shm_add(ngx_uint_t key)
{
    ngx_shm_zone_t *shm_zone = ngx_http_slock_shm_zone;
    ngx_http_slock_sh_t *sst = shm_zone->data;
    ngx_slab_pool_t *pool = (ngx_slab_pool_t*)shm_zone->shm.addr;
    ngx_http_slock_sh_node_t *node;
    ngx_rbtree_node_t *rbnode;

    ngx_shmtx_lock(&pool->mutex);
    if ((rbnode = ngx_http_slock_rbtree_find(&sst->rbtree, key)) != NULL) {
        ngx_shmtx_unlock(&pool->mutex);
        ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, 0, "[%s:%d] existed.", __FUNCTION__, __LINE__);
        return NGX_DONE;   // existed
    }

    if ((node = ngx_slab_alloc_locked(pool, sizeof(ngx_http_slock_sh_node_t))) == NULL) {
        ngx_shmtx_unlock(&pool->mutex);
        return NGX_ERROR; // no memory.
    }
    node->rbnode.key = node->key = key;
    node->last = ngx_time();
    ngx_rbtree_insert(&sst->rbtree, &node->rbnode);
    ngx_queue_insert_tail(&sst->queue, &node->qnode);
    ngx_shmtx_unlock(&pool->mutex);

    ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, 0, "[%s:%d] node: %p", __FUNCTION__, __LINE__, node);

    return NGX_OK;
}

ngx_int_t ngx_http_slock_shm_check_and_reorder(ngx_uint_t key)
{
    ngx_shm_zone_t *shm_zone = ngx_http_slock_shm_zone;
    ngx_http_slock_sh_t *sst = shm_zone->data;
    ngx_slab_pool_t *pool = (ngx_slab_pool_t*)shm_zone->shm.addr;
    ngx_rbtree_node_t *rbnode;
    ngx_http_slock_sh_node_t *node;

    ngx_shmtx_lock(&pool->mutex);
    if ((rbnode = ngx_http_slock_rbtree_find(&sst->rbtree, key)) != NULL) {

        node = container_of(rbnode, ngx_http_slock_sh_node_t, rbnode);
        node->last = ngx_time();
        ngx_queue_remove(&node->qnode);
        ngx_queue_insert_tail(&sst->queue, &node->qnode);

        ngx_shmtx_unlock(&pool->mutex);
        ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, 0, "[%s:%d] existed.", __FUNCTION__, __LINE__);
        return NGX_OK;   // existed
    }
    ngx_shmtx_unlock(&pool->mutex);

    return NGX_ERROR;
}

ngx_int_t ngx_http_slock_shm_del(ngx_uint_t key)
{
    ngx_shm_zone_t *shm_zone = ngx_http_slock_shm_zone;
    ngx_http_slock_sh_t *sst = shm_zone->data;
    ngx_slab_pool_t *pool = (ngx_slab_pool_t*)shm_zone->shm.addr;
    ngx_http_slock_sh_node_t *node;
    ngx_rbtree_node_t *rbnode;

    ngx_shmtx_lock(&pool->mutex);
    if ((rbnode = ngx_http_slock_rbtree_find(&sst->rbtree, key)) == NULL) {
        ngx_shmtx_unlock(&pool->mutex);
        return NGX_ERROR;   // non-existed
    }
    //node = (((void*)rbnode) - offsetof(ngx_http_slock_sh_node_t, rbnode));
    node = container_of(rbnode, ngx_http_slock_sh_node_t, rbnode);
    ngx_rbtree_delete(&sst->rbtree, rbnode);
    ngx_queue_remove(&node->qnode);
    ngx_slab_free_locked(pool, node);
    ngx_shmtx_unlock(&pool->mutex);

    ngx_log_error(NGX_LOG_ERR, shm_zone->shm.log, 0, "[%s:%d] node: %p", __FUNCTION__, __LINE__, node);

    return NGX_OK;
}



