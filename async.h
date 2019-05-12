#pragma once

#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>

#define ASYNC_READ 1
#define ASYNC_WRITE 2

struct execution_engine;

struct task_event_notifier {
    atomic_t refcount;
    struct semaphore sem;
    struct list_head events;
    struct mutex mu;
};

struct task_event {
    struct list_head entry;
    void (*release_on_error)(struct task_event *ev);
};

struct async_task {
    struct work_struct work; // must be the first field
    void *private_data;
};

struct async_io_rw_task {
    struct work_struct work; 

    int operation; // ASYNC_*
    struct file *file;
    size_t buf_len;
    uint8_t *buf;

    uint32_t private_data;
};

struct task_event_notifier * new_task_event_notifier(void);
void get_task_event_notifier(struct task_event_notifier *x);
void put_task_event_notifier(struct task_event_notifier *x);
void async_start_task(struct work_struct *work);
void async_notify_event(struct task_event_notifier *x, struct task_event *ev);
struct task_event * async_listen_event_interruptible(struct task_event_notifier *x);
