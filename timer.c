#include "timer.h"
#include <linux/time64.h>

#define TIMER_INFINITE (-1)
#define PQ_DEFAULT_SIZE 500000

typedef int (*prio_queue_comparator)(void *pi, void *pj);
typedef struct {
    void **priv;
    atomic_t nalloc;  // number of items in queue
    atomic_t size;
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

    atomic_set(&ptr->nalloc, 0);
    atomic_set(&ptr->size, size + 1);
    ptr->comp = comp;
    return true;
}

static void prio_queue_free(prio_queue_t *ptr)
{
    kfree(ptr->priv);
}

static inline bool prio_queue_is_empty(prio_queue_t *ptr)
{
    return !atomic_read(&ptr->nalloc);
}

// return minimun member in queue
static inline void *prio_queue_min(prio_queue_t *ptr)
{
    return prio_queue_is_empty(ptr) ? NULL : ptr->priv[1];
}

// static bool prio_queue_resize(prio_queue_t *ptr, size_t new_size)
// {
//     void **new_ptr;

//     if (new_size <= ptr->nalloc) {
//         pr_err("resize: new_size to small");
//         return false;
//     }

//     new_ptr = kmalloc(sizeof(void *) * new_size, GFP_KERNEL);
//     if (!new_ptr) {
//         pr_err("resize: malloc failed");
//         return false;
//     }

//     memcpy(new_ptr, ptr->priv, sizeof(void *) * (ptr->nalloc + 1));
//     kfree(ptr->priv);
//     ptr->priv = new_ptr;
//     return true;
// }

static inline void prio_queue_swap(prio_queue_t *ptr, size_t i, size_t j)
{
    void *tmp = ptr->priv[i];
    ptr->priv[i] = ptr->priv[j];
    ptr->priv[j] = tmp;
}

static size_t prio_queue_sink(prio_queue_t *ptr, size_t k)
{
    size_t nalloc = atomic_read(&ptr->nalloc);

    while ((k << 1) <= nalloc) {
        size_t j = k << 1;
        if (j < nalloc && ptr->comp(ptr->priv[j + 1], ptr->priv[j]))
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
    size_t nalloc;
    timer_node_t *node;

    do {
        if (prio_queue_is_empty(ptr))
            return true;

        nalloc = atomic_read(&ptr->nalloc);
        prio_queue_swap(ptr, 1, nalloc);

        if (nalloc == atomic_read(&ptr->nalloc)) {
            node = ptr->priv[nalloc--];
            break;
        }
        // change again
        prio_queue_swap(ptr, 1, nalloc);
    } while (1);

    atomic_set(&ptr->nalloc, nalloc);
    prio_queue_sink(ptr, 1);

    if (node->callback)
        node->callback(node->socket, SHUT_RDWR);

    kfree(node);
    return true;
}

static inline bool prio_queue_cmpxchg(timer_node_t **var,
                                      long long *old,
                                      long long neu)
{
    bool ret;
    union u64 {
        struct {
            int low, high;
        } s;
        long long ui;
    } cmp = {.ui = *old}, with = {.ui = neu};

    /**
     * 1. cmp.s.hi:cmp.s.lo compare with *var
     * 2. if equall, set ZF and copy with.s.hi:with.s.lo to *var
     * 3. if not equall， clear ZF and copy *var to cmp.s.hi:cmp.s.lo
     */
    __asm__ __volatile__("lock cmpxchg8b %1\n\tsetz %0"
                         : "=q"(ret), "+m"(*var), "+d"(cmp.s.high),
                           "+a"(cmp.s.low)
                         : "c"(with.s.high), "b"(with.s.low)
                         : "cc", "memory");
    if (!ret)
        *old = cmp.ui;
    return ret;
}

/* add a new item to the heap */
static bool prio_queue_insert(prio_queue_t *ptr, void *item)
{
    timer_node_t **slot;  // get the address we want to store item
    size_t old_nalloc, old_size;
    long long old;

restart:
    old_nalloc = atomic_read(&ptr->nalloc);
    old_size = atomic_read(&ptr->nalloc);

    // get the address want to store
    slot = (timer_node_t **) &ptr->priv[old_nalloc + 1];
    old = (long long) *slot;

    do {
        if (old_nalloc != atomic_read(&ptr->nalloc))
            goto restart;
    } while (!prio_queue_cmpxchg(slot, &old, (long long) item));

    atomic_inc(&ptr->nalloc);
    return true;
}

static int timer_comp(void *ti, void *tj)
{
    return ((timer_node_t *) ti)->key < ((timer_node_t *) tj)->key ? 1 : 0;
}

static prio_queue_t timer;
static atomic_t current_msec;

static void current_time_update(void)
{
    struct timespec64 tv;
    ktime_get_ts64(&tv);  // get current time
    atomic_set(&current_msec, tv.tv_sec * 1000 + tv.tv_nsec / 1000000);
}

void http_timer_init(void)
{
    if (!prio_queue_init(&timer, timer_comp, PQ_DEFAULT_SIZE))
        return;
    current_time_update();
}

void handle_expired_timers(void)
{
    while (!prio_queue_is_empty(&timer)) {
        timer_node_t *node;

        current_time_update();
        node = prio_queue_min(&timer);

        if (node->key > atomic_read(&current_msec))
            return;

        prio_queue_delmin(&timer);
    }
}

bool http_add_timer(struct http_request *req, size_t timeout, timer_callback cb)
{
    timer_node_t *node = kmalloc(sizeof(timer_node_t), GFP_KERNEL);

    if (!node)
        return false;

    current_time_update();
    req->timer_item = node;
    node->key = atomic_read(&current_msec) + timeout;
    node->pos = atomic_read(&timer.nalloc) + 1;
    node->callback = cb;
    node->socket = req->socket;

    prio_queue_insert(&timer, node);
    return true;
}

void http_timer_update(timer_node_t *node, size_t timeout)
{
    current_time_update();
    node->key = atomic_read(&current_msec) + timeout;
    // update new position
    node->pos = prio_queue_sink(&timer, node->pos);
}

void http_free_timer(void)
{
    int i;
    size_t nalloc = atomic_read(&timer.nalloc);
    for (i = 1; i < nalloc + 1; i++)
        kfree(timer.priv[i]);
    prio_queue_free(&timer);
}
