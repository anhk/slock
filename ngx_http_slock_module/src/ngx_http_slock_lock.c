

#include "ngx_http_slock_lock.h"
#include "ngx_http_slock_ipc.h"
#include "ngx_http_slock_shm.h"


void ngx_http_slock_lock_notify(ipc_alert_t *alert)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "[%s:%d] cmd: %d, key: %d",
            __FUNCTION__, __LINE__, alert->cmd, alert->key);
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
    }
    return rc;
}

ngx_uint_t ngx_http_slock_unlock(ngx_http_request_t *r)
{
    ngx_str_t *str_key = &r->unparsed_uri;
    ngx_uint_t key = ngx_crc32_long(str_key->data, str_key->len);

    ipc_alert_t alert = {
        .cmd = NGX_HTTP_SLOCK_IPC_DEL,
        .key = key
    };
    ngx_http_slock_shm_del(key);
    ngx_http_slock_ipc_alert(&alert);

    return NGX_OK;
}


