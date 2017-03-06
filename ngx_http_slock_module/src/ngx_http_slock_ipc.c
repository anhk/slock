
#include "ngx_http_slock_ipc.h"

#define IPC_DATA_SIZE 56

typedef struct {
    char data[IPC_DATA_SIZE];
} ipc_alert_t;

/** worker processes of the world, unite. **/
ngx_socket_t ngx_http_slock_socketpairs[NGX_MAX_PROCESSES][2];

/** 此函数在init_module时调用，属于master进程 **/
ngx_int_t ngx_http_slock_ipc_init(ngx_cycle_t *cycle, ngx_int_t workers)
{
    int i, s = 0;
    ngx_int_t last_expected_process = ngx_last_process;

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

    for (i = 0; i < NGX_MAX_PROCESSES; i ++) {
        ngx_socket_t *socks = ngx_http_slock_socketpairs[s];
        if (i >= workers) {
            socks[0] = NGX_INVALID_FILE;
            socks[1] = NGX_INVALID_FILE;
            continue;
        }

        while (s < last_expected_process && ngx_processes[s].pid != NGX_INVALID_FILE) {
            s++; // find empty existing slot
        }

        // copypaste from os/unix/ngx_process.c (ngx_spawn_process)
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    "socketpair() failed on socketpair while initializing slock module");
            return NGX_ERROR;
        }

        if (ngx_nonblocking(socks[0]) == -1 || ngx_nonblocking(socks[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                    ngx_nonblocking_n " failed on socketpair while initializing slock module");
            close(socks[0]);
            close(socks[1]);
            return NGX_ERROR;
        }
        s++; // NEXT!!
    }

    return NGX_OK;
}


static void ngx_http_slock_ipc_reader(ngx_event_t *ev)
{
    ngx_int_t rc;
    ipc_alert_t alert;
    ngx_connection_t *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }
    c = ev->data;

    while (1) {
        if ((rc = read(c->fd, &alert, sizeof(ipc_alert_t))) != sizeof(ipc_alert_t)) {
            if (rc == -1 && ngx_errno == NGX_EAGAIN) {
                return;
            }
            ngx_log_error(NGX_LOG_ERR, ev->log, 0, "read error.");
            return;
        }

        ngx_log_error(NGX_LOG_ERR, ev->log, 0, "%s", alert.data);
    }
}



/** 此函数在init_worker时，由各个子进程调用 **/
ngx_int_t ngx_http_slock_ipc_init_worker(ngx_cycle_t *cycle)
{
    ngx_connection_t *c;
    ngx_socket_t *socks = ngx_http_slock_socketpairs[ngx_process_slot];
    /** 非worker进程，直接退出 **/
    if ((ngx_process != NGX_PROCESS_SINGLE) && (ngx_process != NGX_PROCESS_WORKER)) {
        return NGX_OK;
    }

    /** 将管道加载到epoll中侦听, socks[1] for read, socks[0] for write **/
    if ((c = ngx_get_connection(socks[1], cycle->log)) == NULL) {
        return NGX_ERROR;
    }
    c->data = NULL;
    c->read->handler = ngx_http_slock_ipc_reader;
    c->read->log = cycle->log;
    c->write->handler = NULL;

    ngx_add_event(c->read, NGX_READ_EVENT, 0);

    return NGX_OK;
}



ngx_int_t ngx_http_slock_ipc_alert(ngx_log_t *log)
{
    ngx_int_t slot;
    ngx_int_t rc;
    ipc_alert_t alert = {"Hello World!"};

    for (slot = 0; slot < NGX_MAX_PROCESSES; slot ++) {
        ngx_socket_t *socks = ngx_http_slock_socketpairs[slot];
        if (socks[0] == NGX_INVALID_FILE) {
            continue;
        }
        if ((rc = write(socks[0], &alert, sizeof(ipc_alert_t))) != sizeof(ipc_alert_t)) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "write error.");
        }
    }
    return NGX_OK;
}

