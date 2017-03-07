

#include "ngx_http_slock_lock.h"
#include "ngx_http_slock_shm.h"

ngx_uint_t ngx_http_slock_lock(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uri: %V", &r->unparsed_uri);
    ngx_http_slock_shm_add(&r->unparsed_uri);
    return NGX_OK;
}

ngx_uint_t ngx_http_slock_unlock(ngx_http_request_t *r)
{
    return NGX_OK;
}
