
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#pragma once

ngx_int_t ngx_http_slock_shm_init(ngx_conf_t *cf);
ngx_int_t ngx_http_slock_shm_add(ngx_uint_t key);
ngx_int_t ngx_http_slock_shm_del(ngx_uint_t key);

ngx_int_t ngx_http_slock_shm_check_and_reorder(ngx_uint_t key);

typedef ngx_int_t (*shm_timeout_rb)(ngx_uint_t key);

ngx_int_t ngx_http_slock_shm_init_worker(ngx_cycle_t *cycle,
        shm_timeout_rb callback);

