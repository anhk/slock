
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_uint_t ngx_http_slock_lock(ngx_http_request_t *r);
ngx_uint_t ngx_http_slock_unlock(ngx_http_request_t *r);
