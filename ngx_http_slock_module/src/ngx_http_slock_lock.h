
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_slock_ipc.h"

#pragma once

void ngx_http_slock_lock_notify(ipc_alert_t *alert);
ngx_uint_t ngx_http_slock_lock(ngx_http_request_t *r);
ngx_uint_t ngx_http_slock_unlock(ngx_http_request_t *r);
void ngx_http_slock_lock_collapse(ngx_http_request_t *r);
