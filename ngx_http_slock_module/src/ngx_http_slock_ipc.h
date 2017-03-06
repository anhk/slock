
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_slock_ipc_init(ngx_cycle_t *cycle, ngx_int_t workers);
ngx_int_t ngx_http_slock_ipc_init_worker(ngx_cycle_t *cycle);

ngx_int_t ngx_http_slock_ipc_alert(ngx_log_t *log);
