

#include "ngx_http_slock_lock.h"
#include "ngx_http_slock_ipc.h"
#include "ngx_http_slock_shm.h"


/**
 * 由ipc模块调用，回调函数
 * 收到通知，断连或释放锁
 **/
void ngx_http_slock_lock_notify(ipc_alert_t *alert)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d] cmd: %uD, key: %uD",
            __FUNCTION__, __LINE__, alert->cmd, alert->key);
}

/**
 * 客户端断连
 **/
void ngx_http_slock_lock_collapse(ngx_http_request_t *r)
{
    /** 只有subscriber会断，摘链即可 **/
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[%s:%d] uri: %V",
            __FUNCTION__, __LINE__, &r->unparsed_uri);
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
    }
    return rc;
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
    ngx_table_elt_t *header= part->elts;

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

