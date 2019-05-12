#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include "../kapi.h"
#include "../vm.h"
#include "def.h"
#include "../async.h"

int async_init(void);
void async_destroy(void);

struct import_resolver *resolver;

#define ID_NAME(id) #id
#define GEN_POLYFILL_0(id) \
    int id(struct vmctx *ctx) { \
        printk(KERN_INFO "Polyfill(0) called: %s\n", ID_NAME(id)); \
        return 1; \
    }
#define GEN_POLYFILL_1(id) \
    int id(struct vmctx *ctx, uint32_t a) { \
        printk(KERN_INFO "Polyfill(1) called: %s %u\n", ID_NAME(id), a); \
        return 1; \
    }
#define GEN_POLYFILL_2(id) \
    int id(struct vmctx *ctx, uint32_t a, uint32_t b) { \
        printk(KERN_INFO "Polyfill(2) called: %s %u %u\n", ID_NAME(id), a, b); \
        return 1; \
    }
#define GEN_POLYFILL_3(id) \
    int id(struct vmctx *ctx, uint32_t a, uint32_t b, uint32_t c) { \
        printk(KERN_INFO "Polyfill(3) called: %s %u %u %u\n", ID_NAME(id), a, b, c); \
        return 1; \
    }
#define GEN_POLYFILL_4(id) \
    int id(struct vmctx *ctx, uint32_t a, uint32_t b, uint32_t c, uint32_t d) { \
        printk(KERN_INFO "Polyfill(4) called: %s %u %u %u %u\n", ID_NAME(id), a, b, c, d); \
        return 1; \
    }

int __wasi_fd_prestat_get(
    struct vmctx *ctx,
    __wasi_fd_t fd,
    wasm_pointer_t _out
) {
    struct execution_engine *ee = (void *) ctx;
    struct file *f;
    __wasi_prestat_t *out;

    //printk(KERN_INFO "fd_prestat_get\n");
    out = (void *) vmctx_get_memory_slice(ctx, _out, sizeof(__wasi_prestat_t));
    if(!out) {
        return __WASI_EFAULT;
    }

    f = ee_get_file(ee, fd);
    if(!f) {
        return __WASI_EBADF;
    }

    out->u.dir.pr_name_len = 4;
    return __WASI_ESUCCESS;
}

int __wasi_fd_prestat_dir_name(
    struct vmctx *ctx,
    __wasi_fd_t fd,
    wasm_pointer_t path,
    uint32_t path_len
) {
    uint8_t *path_p;

    printk(KERN_INFO "fd_prestat_dir_name called on context %px, fd = %d\n", ctx, (int) fd);

    if(path_len != 4) {
        return __WASI_EINVAL;
    }

    path_p = vmctx_get_memory_slice(ctx, path, path_len);
    if(!path_p) return __WASI_EFAULT;

    path_p[0] = 'W';
    path_p[1] = 'A';
    path_p[2] = 'S';
    path_p[3] = 'M';
    return __WASI_ESUCCESS;
}

int __wasi_proc_exit(
    struct vmctx *ctx,
    __wasi_exitcode_t rval
) {
    do_exit(rval);
}

int __wasi_environ_get(
    struct vmctx *ctx,
    wasm_pointer_t environ,
    wasm_pointer_t environ_buf
) {
    return __WASI_ESUCCESS;
}

int __wasi_environ_sizes_get(
    struct vmctx *ctx,
    wasm_pointer_t environ_count,
    wasm_pointer_t environ_buf_size
) {
    uint32_t *x;

    x = (void *) vmctx_get_memory_slice(ctx, environ_count, sizeof(uint32_t));
    if(!x) return __WASI_EFAULT;
    *x = 0;

    x = (void *) vmctx_get_memory_slice(ctx, environ_buf_size, sizeof(uint32_t));
    if(!x) return __WASI_EFAULT;
    *x = 0;
    return __WASI_ESUCCESS;
}

int __wasi_args_get(
    struct vmctx *ctx,
    wasm_pointer_t argv,
    wasm_pointer_t argv_buf
) {
    wasm_pointer_t *pointer_vec;
    char *argv_buf_p;

    pointer_vec = (void *) vmctx_get_memory_slice(ctx, argv, sizeof(wasm_pointer_t) * 1);
    if(!pointer_vec) return __WASI_EFAULT;

    pointer_vec[0] = argv_buf;

    argv_buf_p = (void *) vmctx_get_memory_slice(ctx, argv_buf, 5);
    if(!argv_buf_p) return __WASI_EFAULT;
    argv_buf_p[0] = 'W';
    argv_buf_p[1] = 'A';
    argv_buf_p[2] = 'S';
    argv_buf_p[3] = 'M';
    argv_buf_p[4] = 0;

    return __WASI_ESUCCESS;
}

int __wasi_args_sizes_get(
    struct vmctx *ctx,
    wasm_pointer_t argc,
    wasm_pointer_t argv_buf_size
) {
    uint32_t *x;

    x = (void *) vmctx_get_memory_slice(ctx, argc, sizeof(uint32_t));
    if(!x) return __WASI_EFAULT;
    *x = 1;

    x = (void *) vmctx_get_memory_slice(ctx, argv_buf_size, sizeof(uint32_t));
    if(!x) return __WASI_EFAULT;
    *x = 5;
    return __WASI_ESUCCESS;
}

int __wasi_fd_close(struct vmctx *ctx, __wasi_fd_t fd) {
    struct execution_engine *ee = (void *) ctx;
    if(ee_deregister_file(ee, fd) < 0) return __WASI_EBADF;
    return __WASI_ESUCCESS;
}

static inline loff_t file_pos_read(struct file *file)
{
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos)
{
	file->f_pos = pos;
}

int __wasi_fd_write(
    struct vmctx *ctx,
    __wasi_fd_t fd,
    wasm_pointer_t iovs,
    uint32_t iovs_len,
    wasm_pointer_t nwritten
) {
    struct execution_engine *ee = (void *) ctx;
    int ret;
    uint32_t i;
    __wasi_ciovec_t *iov;
    uint8_t *buf;
    loff_t pos;
    struct file *f;
    uint32_t *nwritten_p;

    nwritten_p = (void *) vmctx_get_memory_slice(ctx, nwritten, sizeof(uint32_t));
    if(!nwritten_p) {
        return __WASI_EFAULT;
    }
    *nwritten_p = 0;

    f = ee_get_file(ee, fd);
    if(!f) {
        return __WASI_EBADF;
    }

    for(i = 0; i < iovs_len; i++) {
        iov = (void *) vmctx_get_memory_slice(ctx, iovs + sizeof(__wasi_ciovec_t) * i, sizeof(__wasi_ciovec_t));
        if(!iov) {
            return __WASI_EFAULT;
        }
        buf = (void *) vmctx_get_memory_slice(ctx, iov->buf, iov->buf_len);
        if(!buf) {
            return __WASI_EFAULT;
        }
        pos = file_pos_read(f);
        ret = kernel_write(f, buf, iov->buf_len, &pos);
        if(ret < 0) {
            return __WASI_EPIPE;
        }
        *nwritten_p += ret;
        file_pos_write(f, pos);
    }

    return 0;
}

int __wasi_fd_read(
    struct vmctx *ctx,
    __wasi_fd_t fd,
    wasm_pointer_t iovs,
    uint32_t iovs_len,
    wasm_pointer_t nread
) {
    struct execution_engine *ee = (void *) ctx;
    int ret;
    uint32_t i;
    __wasi_ciovec_t *iov;
    uint8_t *buf;
    loff_t pos;
    struct file *f;
    uint32_t *nread_p;

    nread_p = (void *) vmctx_get_memory_slice(ctx, nread, sizeof(uint32_t));
    if(!nread_p) {
        return __WASI_EFAULT;
    }
    *nread_p = 0;

    f = ee_get_file(ee, fd);
    if(!f) {
        return __WASI_EBADF;
    }

    for(i = 0; i < iovs_len; i++) {
        iov = (void *) vmctx_get_memory_slice(ctx, iovs + sizeof(__wasi_ciovec_t) * i, sizeof(__wasi_ciovec_t));
        if(!iov) {
            return __WASI_EFAULT;
        }
        buf = (void *) vmctx_get_memory_slice(ctx, iov->buf, iov->buf_len);
        if(!buf) {
            return __WASI_EFAULT;
        }
        pos = file_pos_read(f);
        ret = kernel_read(f, buf, iov->buf_len, &pos);
        if(ret < 0) {
            return __WASI_EPIPE;
        }
        *nread_p += ret;
        file_pos_write(f, pos);
    }

    return 0;
}

int __wasi_random_get(
    struct vmctx *ctx,
    wasm_pointer_t buf,
    uint32_t buf_len
) {
    return __WASI_ESUCCESS;
}

int __wasi_path_open(
    struct vmctx *ctx,
    __wasi_fd_t dirfd,
    __wasi_fd_t dirflags,
    wasm_pointer_t path,
    uint32_t path_len,
    __wasi_oflags_t o_flags,
    __wasi_rights_t fs_rights_base,
    __wasi_rights_t fs_rights_inheriting,
    __wasi_fdflags_t fs_flags,
    wasm_pointer_t fd_out
) {
    uint8_t *path_p;

    path_p = vmctx_get_memory_slice(ctx, path, path_len);
    if(!path_p) return __WASI_EFAULT;

    printk(KERN_INFO "path_open dirfd=%d path=%.*s\n", (int) dirfd, path_len, (char *) path_p);
    return __WASI_EINVAL;
}

#define WORK_TYPE_READ 1
#define WORK_TYPE_WRITE 2

struct wasi_work {
    struct work_struct work_s;
    struct task_event task_ev;

    struct task_event_notifier *notifier;
    int result;
    uint32_t private_data;

    int work_type;
    union {
        struct {
            struct file *file;
            uint8_t *buf;
            uint32_t buf_len;
        } work_read, work_write;
    } inner_work;
};

int __wasi_async_sys_poll(
    struct vmctx *ctx,
    wasm_pointer_t result_out,
    wasm_pointer_t private_data_out
) {
    struct task_event *ev;
    struct wasi_work *work;
    struct execution_engine *ee = (void *) ctx;
    int *result_p = (void *) vmctx_get_memory_slice(ctx, result_out, sizeof(int));
    uint32_t *private_data_p = (void *) vmctx_get_memory_slice(ctx, private_data_out, sizeof(uint32_t));

    if(!result_p || !private_data_p) {
        return __WASI_EFAULT;
    }

    ev = async_listen_event_interruptible(ee->notifier);
    if(!ev) {
        return __WASI_EINTR;
    }

    work = container_of(ev, struct wasi_work, task_ev);
    *result_p = work->result;
    *private_data_p = work->private_data;
    kfree(work);
    return __WASI_ESUCCESS;
}

static void wasi_work_release_on_error(struct task_event *ev) {
    struct wasi_work *work = container_of(ev, struct wasi_work, task_ev);
    kfree(work);
}

static void async_read_handler(struct work_struct *ws) {
    struct wasi_work *work = container_of(ws, struct wasi_work, work_s);
    struct file *file = work->inner_work.work_read.file;
    struct task_event_notifier *notifier;
    loff_t pos;

    pos = file_pos_read(file);
    work->result = kernel_read(
        file,
        work->inner_work.work_read.buf,
        work->inner_work.work_read.buf_len,
        &pos
    );
    if(work->result > 0) {
        file_pos_write(file, pos);
    }

    INIT_LIST_HEAD(&work->task_ev.entry);
    work->task_ev.release_on_error = wasi_work_release_on_error;

    notifier = work->notifier;
    work->notifier = NULL;

    async_notify_event(notifier, &work->task_ev);

    put_task_event_notifier(notifier);
    fput(file);
}

int __wasi_async_fd_read_async(
    struct vmctx *ctx,
    __wasi_fd_t fd,
    wasm_pointer_t buf,
    uint32_t buf_len,
    uint32_t private_data
) {
    struct execution_engine *ee = (void *) ctx;
    struct wasi_work *work;
    uint8_t *buf_p;
    struct file *file;

    buf_p = vmctx_get_memory_slice(ctx, buf, buf_len);
    if(!buf_p) return __WASI_EFAULT;

    file = ee_get_file(ee, fd);
    if(!file) return __WASI_EBADF;

    work = kmalloc(sizeof(struct wasi_work), GFP_KERNEL);
    if(!work) return __WASI_ENOMEM;

    work->notifier = ee->notifier;
    get_task_event_notifier(work->notifier);

    atomic_long_inc(&file->f_count);

    work->result = -1;
    work->private_data = private_data;
    work->work_type = WORK_TYPE_READ;
    work->inner_work.work_read.file = file;
    work->inner_work.work_read.buf = buf_p;
    work->inner_work.work_read.buf_len = buf_len;

    INIT_WORK(&work->work_s, async_read_handler);
    async_start_task(&work->work_s);

    return 0;
}

GEN_POLYFILL_2(_fd_fdstat_get);

int do_resolve(struct import_resolver_instance *self, const char *name, struct import_info *out) {
    if(strcmp(name, "wasi_unstable##fd_prestat_get") == 0) {
        out->fn = __wasi_fd_prestat_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_prestat_dir_name") == 0) {
        out->fn = __wasi_fd_prestat_dir_name;
        out->param_count = 3;
        return 0;
    } else if(strcmp(name, "wasi_unstable##environ_sizes_get") == 0) {
        out->fn = __wasi_environ_sizes_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##environ_get") == 0) {
        out->fn = __wasi_environ_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##args_sizes_get") == 0) {
        out->fn = __wasi_args_sizes_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##args_get") == 0) {
        out->fn = __wasi_args_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##random_get") == 0) {
        out->fn = __wasi_random_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_write") == 0) {
        out->fn = __wasi_fd_write;
        out->param_count = 4;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_read") == 0) {
        out->fn = __wasi_fd_read;
        out->param_count = 4;
        return 0;
    } else if(strcmp(name, "wasi_unstable##proc_exit") == 0) {
        out->fn = __wasi_proc_exit;
        out->param_count = 1;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_fdstat_get") == 0) {
        out->fn = _fd_fdstat_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_close") == 0) {
        out->fn = __wasi_fd_close;
        out->param_count = 1;
        return 0;
    } else if(strcmp(name, "wasi_unstable##path_open") == 0) {
        out->fn = __wasi_path_open;
        out->param_count = 9;
        return 0;
    } else if(strcmp(name, "wasi_async##fd_read_async") == 0) {
        out->fn = __wasi_async_fd_read_async;
        out->param_count = 4;
        return 0;
    } else if(strcmp(name, "wasi_async##sys_poll") == 0) {
        out->fn = __wasi_async_sys_poll;
        out->param_count = 2;
        return 0;
    } else {
        return -EINVAL;
    }
}

int get_instance(struct execution_engine *ee, struct import_resolver *self, struct import_resolver_instance *out) {
    out->resolve = do_resolve;
    return 0;
}

int __init init_module(void) {
    struct import_resolver tmp = {
        .get_instance = get_instance
    };
    resolver = kwasm_resolver_register(&tmp);
    if(IS_ERR(resolver)) {
        return PTR_ERR(resolver);
    }
    return 0;
}

void __exit cleanup_module(void) {
    kwasm_resolver_deregister(resolver);
}

MODULE_LICENSE("GPL");
