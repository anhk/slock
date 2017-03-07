
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#pragma once

ngx_int_t ngx_http_slock_shm_init(ngx_conf_t *cf);
ngx_int_t ngx_http_slock_shm_add(ngx_str_t *key);
ngx_int_t ngx_http_slock_shm_del(ngx_str_t *key);


