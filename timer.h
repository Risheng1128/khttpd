#ifndef TIMER_H
#define TIMER_H

#include "http_server.h"

#define TIMEOUT_DEFAULT 8000 /* ms */

typedef int (*timer_callback)(struct socket *, enum sock_shutdown_cmd);
typedef struct {
    size_t key;
    size_t pos;
    timer_callback callback;
    struct socket *socket;
} timer_node_t;

void http_timer_init(void);
int http_find_timer(void);
void handle_expired_timers(void);
bool http_add_timer(struct http_request *req,
                    size_t timeout,
                    timer_callback cb);
void http_timer_update(timer_node_t *node, size_t timeout);
void http_free_timer(void);

#endif