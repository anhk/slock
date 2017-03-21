

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

typedef void (*slock_item_process)(ngx_http_request_t *r, void *priv);

/**
 * 在本地worker中查找该key，返回key的header
 **/
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


/** 从一个header中查找r **/
static slock_item_t *slock_rbtree_item_find(slock_head_t *head,
        ngx_http_request_t *r)
{
    ngx_queue_t *q;
    for (q = ngx_queue_head(&head->queue);
            q != ngx_queue_sentinel(&head->queue);
            q = ngx_queue_next(q)) {
        slock_item_t *item = container_of(q, slock_item_t, qnode);
        if (item->r == r) {
            return item;
        }
    }
    /** TODO: **/
    return NULL;
}


/**
 * 将一个请求挂到某key的下边
 * 如果该key没有header，则创建一个header
 **/
static ngx_int_t slock_rbtree_add(ngx_uint_t key, ngx_http_request_t *r)
{
    slock_head_t *head;
    slock_item_t *item;
    ngx_log_t *log = r->connection->log;

    if ((head = slock_rbtree_find(key)) == NULL) {
        /** 创建一个header **/
        if ((head = ngx_calloc(sizeof(slock_head_t), log)) == NULL) {
            return NGX_ERROR;
        }
        ngx_queue_init(&head->queue);
        head->rbnode.key = key;
        ngx_rbtree_insert(&slock_tree, &head->rbnode);
    }

    /** 下挂到header的下边 **/
    if ((item = ngx_calloc(sizeof(slock_item_t), log)) == NULL) {
        return NGX_ERROR;
    }
    item->r = r;
    ngx_queue_insert_tail(&head->queue, &item->qnode);

    return NGX_OK;
}


__attribute__((unused))
static ngx_int_t slock_rbtree_entry(ngx_uint_t key,
        slock_item_process process, void *priv)
{
    slock_head_t *head;
    ngx_queue_t *q, *next;

    /** 从本地进程的rbtree中查找key **/
    if ((head = slock_rbtree_find(key)) == NULL) {
        return NGX_ERROR;
    }

    for (q = ngx_queue_head(&head->queue);
            q != ngx_queue_sentinel(&head->queue);) {
        slock_item_t *item = container_of(q, slock_item_t, qnode);
        next = ngx_queue_next(q);

        process(item->r, priv);
        q = next;
    }

    return NGX_OK;
}

/**
 * 从一个key下，摘除一个请求
 * 一般发生在等待中的请求 client abort
 **/
static ngx_int_t slock_rbtree_delete(ngx_uint_t key, ngx_http_request_t *r)
{
    slock_head_t *head;
    slock_item_t *item;

    /** 从本地进程的rbtree中查找key **/
    if ((head = slock_rbtree_find(key)) == NULL) {
        return NGX_ERROR;
    }

    if ((item = slock_rbtree_item_find(head, r)) == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_remove(&item->qnode); /** 从队列中摘链 **/
    ngx_free(item);

    /** 扫描该key下边的等待请求队列，找到需要操作的request  **/
#if 0
    for (q = ngx_queue_head(&head->queue);
            q != ngx_queue_sentinel(&head->queue);) {
        slock_item_t *item = container_of(q, slock_item_t, qnode);
        next = ngx_queue_next(q);

        /** 如果r==NULL，则删除该key的所有等待队列 **/
        if (r == NULL || item->r == r) { /** THIS IT IS **/
            ngx_queue_remove(q); /** 从队列中摘链 **/
            if (code > 0) {
                if (code == NGX_HTTP_OK) {
                    //r = item->r;
                    item->r->headers_out.status = code;
                    item->r->headers_out.content_length_n = 0;
                    item->r->header_only = 1;
                    rc = ngx_http_send_header(item->r);
                    if (rc == NGX_ERROR) {
                        code = rc; /** return rc **/
                    } else {
                        item->r->keepalive = 1;
                    }
                }

                ngx_http_finalize_request(item->r, code);
            }
            ngx_free(item);
        }
        q = next;
    }
#endif

    /** 如果该key的等待队列为空，则删除该key **/
    if (ngx_queue_empty(&head->queue)) {
        ngx_rbtree_delete(&slock_tree, &head->rbnode);
        ngx_free(head);
    }
    return NGX_OK;
}


static ngx_int_t slock_rbtree_destroy(ngx_uint_t key,
        slock_item_process process)
{
    slock_head_t *head;
    slock_item_t *item;
    ngx_queue_t *q;

    /** 从本地进程的rbtree中查找key **/
    if ((head = slock_rbtree_find(key)) == NULL) {
        return NGX_ERROR;
    }

    while (!ngx_queue_empty(&head->queue)) {
        q = ngx_queue_head(&head->queue);
        ngx_queue_remove(q);
        item = container_of(q, slock_item_t, qnode);

        process(item->r, NULL);
        ngx_free(item);
    }

    /** 如果该key的等待队列为空，则删除该key **/
    if (ngx_queue_empty(&head->queue)) {
        ngx_rbtree_delete(&slock_tree, &head->rbnode);
        ngx_free(head);
    }

#if 0
    for (q = ngx_queue_head(&head->queue);
            q != ngx_queue_sentinel(&head->queue);) {
        slock_item_t *item = container_of(q, slock_item_t, qnode);
        next = ngx_queue_next(q);

        slock_item_process(item, priv);
        q = next;
    }
#endif

    return NGX_OK;
}


static void ngx_http_send_timeout(ngx_http_request_t *r, void *priv)
{
    ngx_http_finalize_request(r, NGX_HTTP_GATEWAY_TIME_OUT);
}

static void ngx_http_send_ok(ngx_http_request_t *r, void *priv)
{
    ngx_int_t rc;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;
    rc = ngx_http_send_header(r);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
        return;
    } else {
        r->keepalive = 1;
    }
    ngx_http_finalize_request(r, NGX_HTTP_OK);
}

    __attribute__((unused))
static void ngx_http_send_data(ngx_http_request_t *r, void *priv)
{
    ipc_alert_t *alert = priv;
//    ngx_connection_t *c = r->connection;
    ngx_int_t rc;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] send data to %p, fd=%d",
            __FUNCTION__, __LINE__, r, r->connection->fd);

    if (!r->header_sent) {
        r->headers_out.status = NGX_HTTP_OK;
        rc = ngx_http_send_header(r);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

    {
        ngx_chain_t out;
        ngx_buf_t *b;
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        out.buf = b;
        out.next = NULL;

        b->flush = 1;
        b->pos = alert->data;
        b->last = alert->data + alert->datalen;
        b->memory = 1;
        b->last_buf = 0;

        rc = ngx_http_output_filter(r, &out);
        if (rc == NGX_ERROR) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }

#if 0
    rc = write(c->fd, alert->data, alert->datalen);
    if (rc < 0) {
        ngx_http_finalize_request(r, rc);
        return;
    }
    if (rc != alert->datalen) {
        /** TODO: **/
    }
#endif
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
    ngx_http_slock_shm_del(key);
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
        //slock_rbtree_delete(alert->key, NULL, NGX_HTTP_GATEWAY_TIME_OUT);
        slock_rbtree_destroy(alert->key, ngx_http_send_timeout);
    } else if (alert->cmd == NGX_HTTP_SLOCK_IPC_DEL) { /** 锁的持有者主动释放 **/
        //slock_rbtree_delete(alert->key, NULL, NGX_HTTP_OK);
        slock_rbtree_destroy(alert->key, ngx_http_send_ok);
    } else if (alert->cmd == NGX_HTTP_SLOCK_IPC_DATA) { /** 锁的持有者发布数据 **/
        ngx_str_t str = {
            .len = alert->datalen,
            .data = alert->data,
        };
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d] %V",
                __FUNCTION__, __LINE__, &str);

        slock_rbtree_entry(alert->key, ngx_http_send_data, alert);
    }
}

/**
 * 客户端断连
 * 有外部调用者来执行 ngx_http_finalize_request
 **/
void ngx_http_slock_lock_collapse(ngx_http_request_t *r)
{
    /** 只有subscriber会断，摘链即可 **/
    ngx_str_t *str_key = &r->unparsed_uri;
    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] uri: %V",
            __FUNCTION__, __LINE__, &r->unparsed_uri);

    slock_rbtree_delete(key, r);
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
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] request %p suspend. fd=%d",
            __FUNCTION__, __LINE__, r, r->connection->fd);
    return NGX_DONE;
}


static ngx_int_t slock_check_req_token(ngx_http_request_t *r, ngx_uint_t key)
{
    /** Check token **/
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;
    ngx_uint_t i;

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

    return NGX_OK;
}

ngx_uint_t ngx_http_slock_unlock(ngx_http_request_t *r)
{
    ngx_str_t *str_key = &r->unparsed_uri;
    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);
    //ngx_uint_t i;
    ngx_int_t rc;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d]", __FUNCTION__, __LINE__);

    ipc_alert_t alert = {
        .cmd = NGX_HTTP_SLOCK_IPC_DEL,
        .key = key
    };

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] before send, cmd: %uD, key: %uD",
            __FUNCTION__, __LINE__, alert.cmd, alert.key);

    if (slock_check_req_token(r, key) != NGX_OK) {
        return NGX_HTTP_UNAUTHORIZED;
    }

    if ((rc = ngx_http_slock_shm_del(key)) == NGX_OK) {
        ngx_http_slock_ipc_alert(&alert);
    } else if (rc == NGX_ERROR) {
        return NGX_HTTP_NOT_FOUND;
    }

    return NGX_OK;
}

/**
 * 发布数据
 **/
void ngx_http_slock_publisher(ngx_http_request_t *r)
{
    ngx_str_t *str_key = &r->unparsed_uri;
    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d]",
            __FUNCTION__, __LINE__);

    /** 检查token的合法性 **/
    if (slock_check_req_token(r, key) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
        return;
    }

    /** 检查token是否存在 **/
    if (ngx_http_slock_shm_check_and_reorder(key) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        return;
    }

    /** Get Request Body **/
    {
#if 0
        ngx_chain_t *cl;
        size_t len;
        u_char *p, *buf;
#endif

        size_t pread;

        pread = r->header_in->last - r->header_in->pos;

        if (pread == 0) {
            /** 没有预读数据，从socket读入 **/
            ngx_connection_t *c = r->connection;
            ipc_alert_t alert = {
                .cmd = NGX_HTTP_SLOCK_IPC_DATA,
                .key = key
            };

            alert.datalen = read(c->fd, alert.data, IPC_DATALEN);
            //rc = (rc == IPC_DATALEN) ? IPC_DATALEN - 1 : rc;

            if (alert.datalen == -1 && ngx_socket_errno == NGX_EAGAIN) {
                return;
            } else if (alert.datalen <= 0) { /** check client abort **/
                c->read->eof = 1;
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] close.",
                        __FUNCTION__, __LINE__);
                ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
                return;
            }

            ngx_str_t str = {
                .len = alert.datalen,
                .data = alert.data,
            };
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] %V",
                    __FUNCTION__, __LINE__, &str);
            ngx_http_slock_ipc_alert(&alert);
            return;
        }

        ngx_str_t str = {
            .len = pread,
            .data = r->header_in->pos,
        };
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] %V",
                __FUNCTION__, __LINE__, &str);

        ipc_alert_t alert = {
            .cmd = NGX_HTTP_SLOCK_IPC_DATA,
            .key = key
        };

        alert.datalen = pread > IPC_DATALEN ? IPC_DATALEN : pread;
        ngx_memcpy(alert.data, r->header_in->pos, pread);
        ngx_http_slock_ipc_alert(&alert);

        r->header_in->pos = r->header_in->last;
    }

#if 0

    ipc_alert_t alert = {
        .cmd = NGX_HTTP_SLOCK_IPC_DATA,
        .key = key
    };
#endif

    //rc = read(c->fd, alert.data, IPC_DATALEN);
    //rc = (rc == IPC_DATALEN) ? IPC_DATALEN - 1 : rc;
    //alert.data[rc] = 0;

    //ngx_http_slock_ipc_alert(&alert);
}

ngx_int_t ngx_http_slock_lock_init_worker(ngx_cycle_t *cycle)
{
    ngx_rbtree_init(&slock_tree, &slock_sentinel, ngx_rbtree_insert_value);
    return NGX_OK;
}

