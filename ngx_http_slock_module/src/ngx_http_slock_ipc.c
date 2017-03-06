
#include "ngx_http_slock_ipc.h"

#include <ngx_channel.h>

/**  worker processes of the world, unite.  **/
ngx_socket_t ngx_http_slock_socketpairs[NGX_MAX_PROCESSES][2];

/** 此函数在init_module时调用，属于master进程 **/
ngx_int_t ngx_http_slock_ipc_init(ngx_cycle_t *cycle, ngx_int_t workers)
{
    int         i, s = 0, on = 1;
    ngx_int_t   last_expected_process = ngx_last_process;

    /*
     * here's the deal: we have no control over fork()ing, nginx's internal
     * socketpairs are unusable for our purposes (as of nginx 0.8 -- check the
     * code to see why), and the module initialization callbacks occur before
     * any workers are spawned. Rather than futzing around with existing
     * socketpairs, we populate our own socketpairs array.
     * Trouble is, ngx_spawn_process() creates them one-by-one, and we need to
     * do it all at once. So we must guess all the workers' ngx_process_slots in
     * advance. Meaning the spawning logic must be copied to the T.
     */

    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[%s:%d] workers: %d", __FUNCTION__, __LINE__, workers);

    for (i = 0; i < NGX_MAX_PROCESSES; i ++) {
        if (i >= workers) {
            ngx_http_slock_socketpairs[i][0] = NGX_INVALID_FILE;
            ngx_http_slock_socketpairs[i][1] = NGX_INVALID_FILE;
            continue;
        }

        while (s < last_expected_process && ngx_processes[s].pid != NGX_INVALID_FILE) {
            // find empty existing slot
            s++;
        }

        // copypaste from os/unix/ngx_process.c (ngx_spawn_process)
        ngx_socket_t    *socks = ngx_http_slock_socketpairs[s];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    "socketpair() failed on socketpair while initializing slock module");
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[%s:%d] init %d <%d:%d>",
                __FUNCTION__, __LINE__, s, ngx_http_slock_socketpairs[s][0],
                ngx_http_slock_socketpairs[s][1]);

        if (ngx_nonblocking(socks[0]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    ngx_nonblocking_n " failed on socketpair while initializing slock module");
            ngx_close_channel(socks, cycle->log);
            return NGX_ERROR;
        }
        if (ngx_nonblocking(socks[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    ngx_nonblocking_n " failed on socketpair while initializing slock module");
            ngx_close_channel(socks, cycle->log);
            return NGX_ERROR;
        }
        if (ioctl(socks[0], FIOASYNC, &on) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    "ioctl(FIOASYNC) failed on socketpair while initializing slock module");
            ngx_close_channel(socks, cycle->log);
            return NGX_ERROR;
        }
        if (fcntl(socks[0], F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    "fcntl(F_SETOWN) failed on socketpair while initializing slock module");
            ngx_close_channel(socks, cycle->log);
            return NGX_ERROR;
        }
        if (fcntl(socks[0], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    "fcntl(FD_CLOEXEC) failed on socketpair while initializing slock module");
            ngx_close_channel(socks, cycle->log);
            return NGX_ERROR;
        }
        if (fcntl(socks[1], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    "fcntl(FD_CLOEXEC) failed while initializing slock module");
            ngx_close_channel(socks, cycle->log);
            return NGX_ERROR;
        }

        s++; // NEXT!!
    }

    return NGX_OK;
}


static void ngx_http_slock_channel_handler(ngx_event_t *ev)
{
    // copypaste from os/unix/ngx_process_cycle.c (ngx_channel_handler)
    ngx_int_t           n;
    ngx_channel_t       ch;
    ngx_connection_t   *c;

    ngx_log_error(NGX_LOG_ERR, ev->log, 0, "[%s:%d]", __FUNCTION__, __LINE__);

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }
    c = ev->data;

    while (1) {
        n = ngx_read_channel(c->fd, &ch, sizeof(ch), ev->log);
        if (n == NGX_ERROR) {
            if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
                ngx_del_conn(c, 0);
            }
            ngx_close_connection(c);
            return;
        }

        if ((ngx_event_flags & NGX_USE_EVENTPORT_EVENT) && (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR)) {
            return;
        }

        if (n == NGX_AGAIN) {
            return;
        }

        ngx_log_error(NGX_LOG_ERR, ev->log, 0, "%d %d %d %d", ch.command, ch.pid, ch.slot, ch.fd);

#if 0
        if (ch.command == NGX_CMD_HTTP_PUSH_STREAM_CHECK_MESSAGES.command) {
            ngx_http_push_stream_process_worker_message();
        } else if (ch.command == NGX_CMD_HTTP_PUSH_STREAM_CENSUS_SUBSCRIBERS.command) {
            ngx_http_push_stream_census_worker_subscribers();
        } else if (ch.command == NGX_CMD_HTTP_PUSH_STREAM_DELETE_CHANNEL.command) {
            ngx_http_push_stream_delete_worker_channel();
        } else if (ch.command == NGX_CMD_HTTP_PUSH_STREAM_CLEANUP_SHUTTING_DOWN.command) {
            ngx_http_push_stream_cleanup_shutting_down_worker();
        }
#endif
    }
}



/** 此函数在init_worker时，由各个子进程调用 **/
ngx_int_t ngx_http_slock_ipc_init_worker(ngx_cycle_t *cycle)
{
    /** 非worker进程，直接退出 **/
    if ((ngx_process != NGX_PROCESS_SINGLE) && (ngx_process != NGX_PROCESS_WORKER)) {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "[%s:%d], who am i: %d", __FUNCTION__, __LINE__, ngx_process_slot);

    /** 将管道加载到epoll中侦听 **/
    if (ngx_add_channel_event(cycle,
                ngx_http_slock_socketpairs[ngx_process_slot][1],
                NGX_READ_EVENT, ngx_http_slock_channel_handler) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                "failed to register channel handler while initializing slock module worker");
        return NGX_ERROR;
    }
    return NGX_OK;
}



ngx_int_t ngx_http_slock_ipc_alert(ngx_log_t *log)
{
    ngx_int_t slot;
    ngx_channel_t command = {51, 0, 0, -1};

    ngx_log_error(NGX_LOG_ERR, log, 0, "[%s:%d]", __FUNCTION__, __LINE__);

    for (slot = 0; slot < NGX_MAX_PROCESSES; slot ++) {
        if (ngx_http_slock_socketpairs[slot][0] == NGX_INVALID_FILE) {
            continue;
        }
        ngx_log_error(NGX_LOG_ERR, log, 0, "[%s:%d] ngx_process[slot]: %d", __FUNCTION__, __LINE__, ngx_processes[slot].pid);
        ngx_log_error(NGX_LOG_ERR, log, 0, "[%s:%d] <%d> sendmsg to %d", __FUNCTION__, __LINE__,
                slot, ngx_http_slock_socketpairs[slot][0]);
        ngx_write_channel(ngx_http_slock_socketpairs[slot][0], &command, sizeof(ngx_channel_t), log);
    }
    return NGX_OK;
}

