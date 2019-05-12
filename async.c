#include "async.h"
#include "vm.h"
#include <linux/slab.h>

struct workqueue_struct *async_wq;

int async_init(void) {
    async_wq = alloc_workqueue("async_wq", 0, 0);
    if(!async_wq) return -ENOMEM;
    return 0;
}

void async_cleanup(void) {
    destroy_workqueue(async_wq);
}

struct task_event_notifier * new_task_event_notifier(void) {
    struct task_event_notifier *ret;

    ret = kmalloc(sizeof(struct task_event_notifier), GFP_KERNEL);
    if(!ret) return NULL;

    atomic_set(&ret->refcount, 1);
    sema_init(&ret->sem, 0);
    INIT_LIST_HEAD(&ret->events);
    mutex_init(&ret->mu);

    return ret;
}

static struct task_event * __raw_read_event(struct task_event_notifier *x) {
    struct task_event *ev;

    BUG_ON(x->events.prev == &x->events);

    ev = container_of(x->events.prev, struct task_event, entry);
    list_del(x->events.prev);

    return ev;
}

void get_task_event_notifier(struct task_event_notifier *x) {
    atomic_inc(&x->refcount);
}
EXPORT_SYMBOL(get_task_event_notifier);

void put_task_event_notifier(struct task_event_notifier *x) {
    struct task_event *ev;

    if(atomic_dec_return(&x->refcount) == 0) {
        // No need to lock because we already have unique access to `x` here.
        while(down_trylock(&x->sem) == 0) {
            ev = __raw_read_event(x);
            if(ev->release_on_error) ev->release_on_error(ev);
        }
        kfree(x);
    }
}
EXPORT_SYMBOL(put_task_event_notifier);

void async_start_task(struct work_struct *work) {
    queue_work(async_wq, work);
}
EXPORT_SYMBOL(async_start_task);

void async_notify_event(struct task_event_notifier *x, struct task_event *ev) {
    mutex_lock(&x->mu);
    list_add(&ev->entry, &x->events);
    mutex_unlock(&x->mu);
    up(&x->sem);
}
EXPORT_SYMBOL(async_notify_event);

struct task_event * async_listen_event_interruptible(struct task_event_notifier *x) {
    struct task_event *ev;

    if(down_interruptible(&x->sem) < 0) return NULL;
    mutex_lock(&x->mu);
    ev = __raw_read_event(x);
    mutex_unlock(&x->mu);
    return ev;
}
EXPORT_SYMBOL(async_listen_event_interruptible);
