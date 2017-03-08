
#pragma once

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t ngx_http_slock_module;


#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})



