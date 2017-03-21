
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#pragma once


enum { /** COMMAND **/
    NGX_HTTP_SLOCK_IPC_DEL = 1, /** 锁被正常释放 **/
    NGX_HTTP_SLOCK_IPC_BAD,     /** 锁的持有者连接断掉，异常情况 **/
    NGX_HTTP_SLOCK_IPC_DATA,    /** 发布数据 **/
};


#define IPC_DATALEN 52

typedef struct {
    ngx_uint_t cmd;
    ngx_uint_t key;
    ngx_int_t datalen;
    u_char data[IPC_DATALEN];
} ipc_alert_t;

typedef void (*ipc_callback_t)(ipc_alert_t *alert);

ngx_int_t ngx_http_slock_ipc_init(ngx_cycle_t *cycle, ngx_int_t workers);
ngx_int_t ngx_http_slock_ipc_init_worker(ngx_cycle_t *cycle, ipc_callback_t callback);

ngx_int_t ngx_http_slock_ipc_alert(ipc_alert_t *alert);
