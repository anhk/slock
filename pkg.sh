#!/bin/bash

CURDIR=$(pwd)
DESTDIR=/usr/local/slock
BUILDROOT=$(pwd)/buildroot/

build_what=modules

if [ $# = 1 -a "$1" = "all" ]; then
    build_what=
fi


NGINX_VERSION=1.10.3
NGINX=nginx-${NGINX_VERSION}.tar.gz

rm -fr $BUILDROOT/*

tar zxf $NGINX -C $BUILDROOT/
cp -af ngx_http_slock_module $BUILDROOT

cd $BUILDROOT/nginx-release-${NGINX_VERSION}/

./auto/configure --prefix=${DESTDIR} \
    --without-http_charset_module \
    --without-http_gzip_module \
    --without-http_ssi_module \
    --without-http_userid_module \
    --without-http_access_module \
    --without-http_auth_basic_module \
    --without-http_autoindex_module \
    --without-http_geo_module \
    --without-http_map_module \
    --without-http_split_clients_module \
    --without-http_referer_module \
    --without-http_rewrite_module \
    --without-http_proxy_module \
    --without-http_fastcgi_module \
    --without-http_uwsgi_module \
    --without-http_scgi_module \
    --without-http_memcached_module \
    --without-http_limit_conn_module \
    --without-http_limit_req_module \
    --without-http_empty_gif_module \
    --without-http_browser_module \
    --without-http_upstream_hash_module \
    --without-http_upstream_ip_hash_module \
    --without-http_upstream_least_conn_module \
    --without-http_upstream_keepalive_module \
    --without-http_upstream_zone_module \
    --without-pcre \
    --without-http-cache \
    --add-dynamic-module=../ngx_http_slock_module/ || exit -1

make -j 2 $build_what || exit -1
install -d ${DESTDIR}/{logs,conf,sbin,modules}

${DESTDIR}/sbin/nginx -s stop
if [ "$build_what" = "" ]; then
    install -m0755 objs/nginx ${DESTDIR}/sbin/nginx
fi
install -m0755 objs/ngx_http_slock_module.so ${DESTDIR}/modules
cd ${CURDIR}
install -m0644 nginx.conf  ${DESTDIR}/conf/nginx.conf
${DESTDIR}/sbin/nginx


