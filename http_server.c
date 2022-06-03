#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256

extern struct workqueue_struct *khttpd_wq;

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir_context;
    struct list_head node;
    struct work_struct khttpd_work;
};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            TRACE(send_err);
            break;
        }
        done += length;
    }
    return done;
}

// callback for 'iterate_dir', trace entry.
static int tracedir(struct dir_context *dir_context,
                    const char *name,
                    int namelen,
                    loff_t offset,
                    u64 ino,
                    unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[SEND_BUFFER_SIZE] = {0};

        snprintf(buf, SEND_BUFFER_SIZE,
                 "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", name, name);
        http_server_send(request->socket, buf, strlen(buf));
    }
    return 0;
}

static bool handle_directory(struct http_request *request)
{
    struct file *fp;
    char buf[SEND_BUFFER_SIZE] = {0};

    request->dir_context.actor = tracedir;
    if (request->method != HTTP_GET) {
        snprintf(buf, SEND_BUFFER_SIZE,
                 "HTTP/1.1 501 Not Implemented\r\n%s%s%s%s",
                 "Content-Type: text/plain\r\n", "Content-Length: 19\r\n",
                 "Connection: Close\r\n", "501 Not Implemented\r\n");
        http_server_send(request->socket, buf, strlen(buf));
        return false;
    }

    snprintf(buf, SEND_BUFFER_SIZE, "HTTP/1.1 200 OK\r\n%s%s%s",
             "Connection: Keep-Alive\r\n", "Content-Type: text/html\r\n",
             "Keep-Alive: timeout=5, max=1000\r\n\r\n");
    http_server_send(request->socket, buf, strlen(buf));


    snprintf(buf, SEND_BUFFER_SIZE, "%s%s%s%s", "<html><head><style>\r\n",
             "body{font-family: monospace; font-size: 15px;}\r\n",
             "td {padding: 1.5px 6px;}\r\n",
             "</style></head><body><table>\r\n");
    http_server_send(request->socket, buf, strlen(buf));

    fp = filp_open("/home/benson/khttpd/", O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(fp)) {
        pr_info("Open file failed");
        return false;
    }

    iterate_dir(fp, &request->dir_context);
    snprintf(buf, SEND_BUFFER_SIZE, "</table></body></html>\r\n");
    http_server_send(request->socket, buf, strlen(buf));
    filp_close(fp, NULL);
    return true;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    int ret = handle_directory(request);
    if (ret > 0)
        TRACE(sendmsg);
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void free_work(void)
{
    struct http_request *l, *tar;
    /* cppcheck-suppress uninitvar */

    list_for_each_entry_safe (tar, l, &daemon_list.head, node) {
        kernel_sock_shutdown(tar->socket, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->socket);
        kfree(tar);
    }
}

static void http_server_worker(struct work_struct *work)
{
    struct http_request *worker =
        container_of(work, struct http_request, khttpd_work);
    char *buf;
    struct http_parser parser;
    // callback function setting
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

rekmalloc:
    buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        TRACE(kmalloc_err);
        goto rekmalloc;
    }

    // set the initial parameter of parser
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &worker->socket;

    // check the thread should be stop or not
    while (!daemon_list.is_stopped) {
        // receive data
        int ret = http_server_recv(worker->socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                TRACE(recv_err);
            break;
        } else
            TRACE(recvmsg);

        // parse the data received
        http_parser_execute(&parser, &setting, buf, ret);
        if (worker->complete && !http_should_keep_alive(&parser))
            break;

        memset(buf, 0, ret);
    }
    kernel_sock_shutdown(worker->socket, SHUT_RDWR);
    kfree(buf);
}

static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work;

    // allocate the size of struct http_request
    if (!(work = kmalloc(sizeof(struct http_request), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    // initialize the work which calls the function http_server_worker
    INIT_WORK(&work->khttpd_work, http_server_worker);

    list_add(&work->node, &daemon_list.head);

    return &work->khttpd_work;
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct work_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;

    // regist the signals
    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon_list.head);

    // check the thread should be stop or not
    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            // check there is any signal occurred or not
            if (signal_pending(current))
                break;
            TRACE(accept_err);
            continue;
        }

        worker = create_work(socket);
        if (IS_ERR(worker)) {
            TRACE(cthread_err);
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }

        // start server workqueue
        queue_work(khttpd_wq, worker);
    }
    daemon_list.is_stopped = true;
    free_work();
    return 0;
}