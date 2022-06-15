#include "timer.h"
#include <linux/time64.h>

#define TIMER_INFINITE (-1)
#define PQ_DEFAULT_SIZE 50

typedef int (*prio_queue_comparator)(void *pi, void *pj);
typedef struct {
    void **priv;
    size_t nalloc;  // number of items in queue
    size_t size;
    prio_queue_comparator comp;
} prio_queue_t;

static bool prio_queue_init(prio_queue_t *ptr,
                            prio_queue_comparator comp,
                            int size)
{
    ptr->priv = kmalloc(sizeof(void *) * (size + 1), GFP_KERNEL);
    if (!ptr->priv) {
        pr_err("init: kmalloc failed");
        return false;
    }

    ptr->nalloc = 0;
    ptr->size = size + 1;
    ptr->comp = comp;
    return true;
}

static void prio_queue_free(prio_queue_t *ptr)
{
    kfree(ptr->priv);
}

static inline bool prio_queue_is_empty(prio_queue_t *ptr)
{
    return !ptr->nalloc;
}

// return minimun member in queue
static inline void *prio_queue_min(prio_queue_t *ptr)
{
    return prio_queue_is_empty(ptr) ? NULL : ptr->priv[1];
}

static bool prio_queue_resize(prio_queue_t *ptr, size_t new_size)
{
    void **new_ptr;

    if (new_size <= ptr->nalloc) {
        pr_err("resize: new_size to small");
        return false;
    }

    new_ptr = kmalloc(sizeof(void *) * new_size, GFP_KERNEL);
    if (!new_ptr) {
        pr_err("resize: malloc failed");
        return false;
    }

    memcpy(new_ptr, ptr->priv, sizeof(void *) * (ptr->nalloc + 1));
    kfree(ptr->priv);
    ptr->priv = new_ptr;
    return true;
}

static inline void prio_queue_swap(prio_queue_t *ptr, size_t i, size_t j)
{
    void *tmp = ptr->priv[i];
    ptr->priv[i] = ptr->priv[j];
    ptr->priv[j] = tmp;
}

static inline void prio_queue_swim(prio_queue_t *ptr, size_t k)
{
    while (k > 1 && ptr->comp(ptr->priv[k], ptr->priv[k >> 1])) {
        prio_queue_swap(ptr, k, k >> 1);
        k >>= 1;
    }
}

static size_t prio_queue_sink(prio_queue_t *ptr, size_t k)
{
    while ((k << 1) <= ptr->nalloc) {
        size_t j = k << 1;
        if (j < ptr->nalloc && ptr->comp(ptr->priv[j + 1], ptr->priv[j]))
            j++;
        if (!ptr->comp(ptr->priv[j], ptr->priv[k]))
            break;
        prio_queue_swap(ptr, j, k);
        k = j;
    }
    return k;
}

/* remove the item with minimum key value from the heap */
static bool prio_queue_delmin(prio_queue_t *ptr)
{
    if (prio_queue_is_empty(ptr))
        return true;
    prio_queue_swap(ptr, 1, ptr->nalloc);
    ptr->nalloc--;
    prio_queue_sink(ptr, 1);
    if (ptr->nalloc > 0 && ptr->nalloc <= ((ptr->size - 1) >> 2)) {
        if (!prio_queue_resize(ptr, ptr->size >> 1))
            return false;
    }
    return true;
}

/* add a new item to the heap */
static bool prio_queue_insert(prio_queue_t *ptr, void *item)
{
    // queue is full
    if (ptr->nalloc + 1 == ptr->size) {
        if (!prio_queue_resize(ptr, ptr->size << 1))
            return false;
    }
    ptr->priv[++ptr->nalloc] = item;
    prio_queue_swim(ptr, ptr->nalloc);

    return true;
}

static int timer_comp(void *ti, void *tj)
{
    return ((timer_node_t *) ti)->key < ((timer_node_t *) tj)->key ? 1 : 0;
}

static prio_queue_t timer;
static size_t current_msec;

static void http_time_update(void)
{
    struct timespec64 tv;
    ktime_get_ts64(&tv);  // get current time
    current_msec = tv.tv_sec * 1000 + tv.tv_nsec / 1000000;
}

void http_timer_init(void)
{
    if (!prio_queue_init(&timer, timer_comp, PQ_DEFAULT_SIZE))
        return;
    http_time_update();
}

void handle_expired_timers(void)
{
    while (!prio_queue_is_empty(&timer)) {
        timer_node_t *node;

        http_time_update();
        node = prio_queue_min(&timer);

        if (node->key > current_msec)
            return;

        if (node->callback)
            node->callback(node->socket, SHUT_RDWR);

        prio_queue_delmin(&timer);
        kfree(node);
    }
}

bool http_add_timer(struct http_request *req, size_t timeout, timer_callback cb)
{
    timer_node_t *node = kmalloc(sizeof(timer_node_t), GFP_KERNEL);
    if (!node)
        return false;

    http_time_update();
    req->timer_item = node;
    node->key = current_msec + timeout;
    node->callback = cb;
    node->socket = req->socket;

    prio_queue_insert(&timer, node);
    return true;
}

void http_free_timer(void)
{
    int i;
    for (i = 0; i < timer.nalloc; i++)
        kfree(timer.priv[i]);
    prio_queue_free(&timer);
}
