#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <net/sock.h>

struct http_server_param {
    struct socket *listen_socket;
};

struct httpd_service {
    bool is_stopped;
    char *dir_path;
    struct list_head head;
};
extern struct httpd_service daemon_list;

enum {
    TRACE_cthread_err = 1,  // number of create thread failed
    TRACE_kmalloc_err,      // number of fail kmalloc
    TRACE_recvmsg,          // number of recvmsg
    TRACE_sendmsg,          // number of sendmsg
    TRACE_send_err,         // number of send request failed
    TRACE_recv_err,         // number of recv request failed
};

struct runtime_state {
    atomic_t cthread_err, kmalloc_err;
    atomic_t recvmsg, sendmsg;
    atomic_t send_err, recv_err;
};
extern struct runtime_state states;

#define TRACE(ops)                      \
    do {                                \
        if (TRACE_##ops)                \
            atomic_add(1, &states.ops); \
    } while (0)

extern int http_server_daemon(void *arg);
#endif
