
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_slock_ipc.h"

#pragma once

void ngx_http_slock_lock_notify(ipc_alert_t *alert);
ngx_uint_t ngx_http_slock_lock(ngx_http_request_t *r);
ngx_uint_t ngx_http_slock_trylock(ngx_http_request_t *r);
ngx_uint_t ngx_http_slock_unlock(ngx_http_request_t *r);
void ngx_http_slock_publisher(ngx_http_request_t *r);
void ngx_http_slock_lock_collapse(ngx_http_request_t *r);

ngx_int_t ngx_http_slock_lock_timeout(ngx_uint_t key);
ngx_int_t ngx_http_slock_lock_init_worker(ngx_cycle_t *cycle);
