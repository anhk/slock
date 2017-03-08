

#include "ngx_http_slock_lock.h"
#include "ngx_http_slock_ipc.h"
#include "ngx_http_slock_shm.h"
#include "ngx_http_slock_module.h"


typedef struct {
    ngx_rbtree_node_t rbnode;
    ngx_queue_t queue;
} slock_head_t;

typedef struct {
    ngx_queue_t qnode;
    ngx_http_request_t *r;
} slock_item_t;

static ngx_rbtree_t slock_tree;
static ngx_rbtree_node_t slock_sentinel;

static slock_head_t *slock_rbtree_find(ngx_uint_t key)
{
    ngx_rbtree_node_t *root = slock_tree.root;

    while (root != &slock_sentinel) {
        if (key == root->key) {
            return container_of(root, slock_head_t, rbnode);
        }
        root = (key < root->key) ? root->left : root->right;
    }
    return NULL;
}

static ngx_int_t slock_rbtree_add(ngx_uint_t key, ngx_http_request_t *r)
{
    slock_head_t *head;
    slock_item_t *item;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] key=%uD, add %p to rbtree",
            __FUNCTION__, __LINE__, key, r);

    if ((head = slock_rbtree_find(key)) == NULL) {
        if ((head = ngx_calloc(sizeof(slock_head_t), r->connection->log)) == NULL) {
            return NGX_ERROR;
        }
        ngx_queue_init(&head->queue);
        head->rbnode.key = key;
        ngx_rbtree_insert(&slock_tree, &head->rbnode);
    }
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d]", __FUNCTION__, __LINE__);

    if ((item = ngx_calloc(sizeof(slock_item_t), r->connection->log)) == NULL) {
        return NGX_ERROR;
    }
    item->r = r;
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d]", __FUNCTION__, __LINE__);
    ngx_queue_insert_tail(&head->queue, &item->qnode);

    return NGX_OK;
}

static ngx_int_t slock_rbtree_delete(ngx_uint_t key, ngx_http_request_t *r, ngx_int_t code)
{
    slock_head_t *head;
    ngx_queue_t *q, *next;
    ngx_int_t rc;

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d], check key: %uD", __FUNCTION__, __LINE__, key);
    if ((head = slock_rbtree_find(key)) == NULL) {
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d]", __FUNCTION__, __LINE__);

    for (q = ngx_queue_head(&head->queue);
            q != ngx_queue_sentinel(&head->queue);) {
        slock_item_t *item = container_of(q, slock_item_t, qnode);
        next = ngx_queue_next(q);

        if (r == NULL || item->r == r) { /** THIS IT IS **/
            ngx_queue_remove(q);
            if (code > 0) {
                if (code == NGX_HTTP_OK) {
                    r = item->r;
                    r->headers_out.status = code;
                    r->headers_out.content_length_n = 0;
                    r->header_only = 1;
                    rc = ngx_http_send_header(r);
                    if (rc == NGX_ERROR) {
                        /** FIXME **/
                    } else {
                        r->keepalive = 1;
                    }
                }

                ngx_http_finalize_request(item->r, code);
            }
            ngx_free(item);
        }
        q = next;
    }

    if (ngx_queue_empty(&head->queue)) {
        ngx_rbtree_delete(&slock_tree, &head->rbnode);
        ngx_free(head);
    }
    return NGX_OK;
}

/**
 * 在共享内存中的key，超时后的回调函数
 **/
ngx_int_t ngx_http_slock_lock_timeout(ngx_uint_t key)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d], key: %uD",
            __FUNCTION__, __LINE__, key);

    ipc_alert_t alert = {
        .cmd = NGX_HTTP_SLOCK_IPC_BAD,
        .key = key
    };
    ngx_http_slock_ipc_alert(&alert);

    return NGX_OK;
}
/**
 * 由ipc模块调用，回调函数
 * 收到通知，断连或释放锁
 **/
void ngx_http_slock_lock_notify(ipc_alert_t *alert)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d] cmd: %uD, key: %uD",
            __FUNCTION__, __LINE__, alert->cmd, alert->key);
    if (alert->cmd == NGX_HTTP_SLOCK_IPC_BAD) { /** 超时 **/
        slock_rbtree_delete(alert->key, NULL, NGX_HTTP_NOT_FOUND);
    } else if (alert->cmd == NGX_HTTP_SLOCK_IPC_DEL) { /** 锁的持有者主动释放 **/
        slock_rbtree_delete(alert->key, NULL, NGX_HTTP_OK);
    }
}

/**
 * 客户端断连
 **/
void ngx_http_slock_lock_collapse(ngx_http_request_t *r)
{
    /** 只有subscriber会断，摘链即可 **/
    ngx_str_t *str_key = &r->unparsed_uri;
    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] uri: %V",
            __FUNCTION__, __LINE__, &r->unparsed_uri);

    slock_rbtree_delete(key, r, 0);
}

ngx_uint_t ngx_http_slock_lock(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] uri: %V",
            __FUNCTION__, __LINE__, &r->unparsed_uri);
    ngx_str_t *str_key = &r->unparsed_uri;
    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);
    ngx_int_t rc;

    if ((rc = ngx_http_slock_shm_add(key)) == NGX_DONE) {
        /** 未拿到锁，需要挂起 **/
        if ((rc = slock_rbtree_add(key, r)) != NGX_OK) {
            return NGX_ERROR;
        }
    } else if (rc == NGX_OK) {
        /** 加锁成功，加token **/
        ngx_table_elt_t  *h;

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            ngx_http_slock_shm_del(key);
            return NGX_ERROR;
        }

        h->hash = 1;
        ngx_str_set(&h->key, "Slock-Token");
        h->value.data = ngx_pcalloc(r->pool, 256);//ngx_pstrdup(r->pool, &token_value);
        h->value.len = ngx_sprintf(h->value.data, "%uD", key) - h->value.data;
        return NGX_OK;
    }
    return NGX_DONE;
}

ngx_uint_t ngx_http_slock_unlock(ngx_http_request_t *r)
{
    ngx_str_t *str_key = &r->unparsed_uri;
    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);
    ngx_uint_t i;
    ngx_int_t rc;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d]", __FUNCTION__, __LINE__);

    ipc_alert_t alert = {
        .cmd = NGX_HTTP_SLOCK_IPC_DEL,
        .key = key
    };

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] before send, cmd: %uD, key: %uD",
            __FUNCTION__, __LINE__, alert.cmd, alert.key);

    /** Check token **/
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;

    for (i = 0;  ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                return NGX_ERROR;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }
        if (header[i].key.len == 11 &&
                ngx_strncasecmp(header[i].key.data, (u_char*)"Slock-Token", 11) == 0) {
            ngx_uint_t token = ngx_atoi(header[i].value.data, header[i].value.len);
            /** token doesn't equal **/
            if (key != token) {
                return NGX_ERROR;
            }
            break;
        }
    }

    if ((rc = ngx_http_slock_shm_del(key)) == NGX_OK) {
        ngx_http_slock_ipc_alert(&alert);
    } else if (rc == NGX_ERROR) {
        return NGX_HTTP_NOT_FOUND;
    }

    return NGX_OK;
}

ngx_int_t ngx_http_slock_lock_init_worker(ngx_cycle_t *cycle)
{
    ngx_rbtree_init(&slock_tree, &slock_sentinel, ngx_rbtree_insert_value);
    return NGX_OK;
}
