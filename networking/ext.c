#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/nsproxy.h>
#include <linux/kallsyms.h>
#include <uapi/linux/eventpoll.h>
#include "../kapi.h"
#include "../vm.h"

typedef uint32_t wasm_pointer_t;

struct import_resolver *resolver;

struct __timespec {
	uint64_t       tv_sec;                 /* seconds */
	long long               tv_nsec;                /* nanoseconds */
};

struct __itimerspec {
	struct __timespec it_interval;    /* timer period */
	struct __timespec it_value;       /* timer expiration */
};

extern int sys_close(unsigned int fd);

static int (*_sys_epoll_create)(int size);
static int (*_sys_epoll_ctl)(int epfd, int op, int fd, struct epoll_event *event);
static int (*_sys_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);
static int (*_sys_fcntl)(unsigned int fd, unsigned int cmd, unsigned long arg);
static int (*_sys_accept4)(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags);
static int (*_sys_sendto)(int fd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len);
static int (*_sys_recvfrom)(int fd, void *ubuf, size_t size, unsigned int flasgs, struct sockaddr *addr, int *addr_len);
static int (*_sys_timerfd_create)(int clockid, int flags);
static int (*_sys_timerfd_settime)(int ufd, int flags, const struct __itimerspec *utmr, struct __itimerspec *otmr);
static int (*_sys_eventfd2)(unsigned int count, int flags);

int __net_socket(
    struct vmctx *ctx,
    int family,
    int type,
    int proto
) {
    struct socket *sock;
    struct file *f;
    int err, fd;

    if((err = sock_create_kern(
        current->nsproxy->net_ns,
        family,
        type,
        proto,
        &sock
    )) < 0) {
        return err;
    }

    fd = get_unused_fd_flags(O_RDWR);
    if(fd < 0) {
        return fd;
    }

    f = sock_alloc_file(sock, O_RDWR, NULL);
    if(IS_ERR(f)) {
        put_unused_fd(fd);
        sock_release(sock);
        return PTR_ERR(f);
    }

    fd_install(fd, f);
    return fd;
}

int __net_bind(
    struct vmctx *ctx,
    int fd,
    wasm_pointer_t sockaddr,
    uint32_t sockaddr_len
) {
    int err;
    struct file *file;
    struct socket *sock;
    struct sockaddr *sa;

    file = fget(fd);
    if(!file) {
        return -EBADF;
    }

    sock = sock_from_file(file, &err);
    if(!sock) {
        fput(file);
        return -ENOTSOCK;
    }

    if(sockaddr) {
        sa = (void *) vmctx_get_memory_slice(ctx, sockaddr, sockaddr_len);
        if(!sa) {
            fput(file);
            return -EFAULT;
        }
    } else {
        if(sockaddr_len != 0) {
            fput(file);
            return -EINVAL;
        }
        sa = NULL;
    }

    err = sock->ops->bind(sock, sa, sockaddr_len);
    fput(file);
    return err;
}

int __net_listen(
    struct vmctx *ctx,
    int fd,
    int backlog
) {
    int err;
    struct file *file;
    struct socket *sock;

    file = fget(fd);
    if(!file) {
        return -EBADF;
    }

    sock = sock_from_file(file, &err);
    if(!sock) {
        fput(file);
        return -ENOTSOCK;
    }

    err = sock->ops->listen(sock, backlog);
    fput(file);
    return err;
}

int __net_accept4(
    struct vmctx *ctx,
    int fd,
    wasm_pointer_t sockaddr,
    wasm_pointer_t sockaddr_len_vptr,
    uint32_t flags
) {
    int ret;
    struct sockaddr *sa = NULL;
    int *sockaddr_len_p = NULL;
    mm_segment_t old_fs;

    if(sockaddr) {
        sockaddr_len_p = (void *) vmctx_get_memory_slice(ctx, sockaddr_len_vptr, sizeof(int));
        if(!sockaddr_len_p) {
            return -EFAULT;
        }

        sa = (void *) vmctx_get_memory_slice(ctx, sockaddr, *sockaddr_len_p);
        if(!sa) {
            return -EFAULT;
        }
    }

    old_fs = get_fs();
	set_fs(KERNEL_DS);
    ret = _sys_accept4(fd, sa, sockaddr_len_p, flags);
    set_fs(old_fs);

    return ret;
}

int __net_sendto(
    struct vmctx *ctx,
    int fd,
    wasm_pointer_t buf,
    uint32_t len,
    uint32_t flags,
    wasm_pointer_t addr,
    int addr_len
) {
    int ret;
    mm_segment_t old_fs;
    struct sockaddr *sa = NULL;
    uint8_t *buf_p = vmctx_get_memory_slice(ctx, buf, len);
    if(!buf_p) return -EFAULT;

    if(addr) {
        sa = (void *) vmctx_get_memory_slice(ctx, addr, addr_len);
        if(!sa) return -EFAULT;
    }

    old_fs = get_fs();
	set_fs(KERNEL_DS);
    ret = _sys_sendto(fd, buf_p, len, flags, sa, addr_len);
    set_fs(old_fs);

    return ret;
}

int __net_recvfrom(
    struct vmctx *ctx,
    int fd,
    wasm_pointer_t buf,
    uint32_t len,
    uint32_t flags,
    wasm_pointer_t addr,
    wasm_pointer_t addr_len_vptr
) {
    int ret;
    mm_segment_t old_fs;
    struct sockaddr *sa = NULL;
    int *addr_len_p = NULL;
    uint8_t *buf_p = vmctx_get_memory_slice(ctx, buf, len);

    if(!buf_p) return -EFAULT;

    if(addr) {
        addr_len_p = (void *) vmctx_get_memory_slice(ctx, addr_len_vptr, sizeof(int));
        if(!addr_len_p) return -EFAULT;

        sa = (void *) vmctx_get_memory_slice(ctx, addr, *addr_len_p);
        if(!sa) return -EFAULT;
    }

    old_fs = get_fs();
	set_fs(KERNEL_DS);
    ret = _sys_recvfrom(fd, buf_p, len, flags, sa, addr_len_p);
    set_fs(old_fs);

    return ret;
}

int __net_eventfd_sem(
    struct vmctx *ctx,
    uint32_t initial
) {
    const int EFD_SEMAPHORE = 1;
    return _sys_eventfd2(initial, EFD_SEMAPHORE);
}

int __net_epoll_create(struct vmctx *ctx) {
    return _sys_epoll_create(42);
}
int __net_epoll_ctl(
    struct vmctx *ctx,
    int epfd,
    int op,
    int fd,
    wasm_pointer_t _event
) {
    struct epoll_event *event = NULL;
    mm_segment_t old_fs;
    int ret;

    if(_event) {
        event = (void *) vmctx_get_memory_slice(ctx, _event, sizeof(struct epoll_event));
        if(!event) return -EFAULT;
    }

    old_fs = get_fs();
	set_fs(KERNEL_DS);
    ret = _sys_epoll_ctl(epfd, op, fd, event);
    set_fs(old_fs);

    return ret;
}
int __net_epoll_wait(
    struct vmctx *ctx,
    int epfd,
    wasm_pointer_t _events,
    int maxevents,
    int timeout
) {
    int ret;
    struct epoll_event *events;
    mm_segment_t old_fs;
    events = (void *) vmctx_get_memory_slice(
        ctx,
        _events,
        (unsigned long) sizeof(struct epoll_event) * (unsigned long) (unsigned int) maxevents
    );
    if(!events) return -EFAULT;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
    ret = _sys_epoll_wait(epfd, events, maxevents, timeout);
	set_fs(old_fs);

	return ret;
}

int __net_fcntl(
    struct vmctx *ctx,
    int fd,
    int cmd,
    uint32_t arg
) {
    switch(cmd) {
        case F_GETFL:
        case F_SETFL:
            break;

        default:
            return -EPERM;
    }

    return _sys_fcntl(fd, cmd, arg);
}

int do_resolve(struct import_resolver_instance *self, const char *name, struct import_info *out) {
    if(strcmp(name, "net##_socket") == 0) {
        out->fn = __net_socket;
        out->param_count = 3;
        return 0;
    } else if(strcmp(name, "net##_bind") == 0) {
        out->fn = __net_bind;
        out->param_count = 3;
        return 0;
    } else if(strcmp(name, "net##_listen") == 0) {
        out->fn = __net_listen;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "net##_accept4") == 0) {
        out->fn = __net_accept4;
        out->param_count = 4;
        return 0;
    } else if(strcmp(name, "net##_sendto") == 0) {
        out->fn = __net_sendto;
        out->param_count = 6;
        return 0;
    } else if(strcmp(name, "net##_recvfrom") == 0) {
        out->fn = __net_recvfrom;
        out->param_count = 6;
        return 0;
    } else if(strcmp(name, "net##_eventfd_sem") == 0) {
        out->fn = __net_eventfd_sem;
        out->param_count = 1;
        return 0;
    } else if(strcmp(name, "net##_epoll_create") == 0) {
        out->fn = __net_epoll_create;
        out->param_count = 0;
        return 0;
    } else if(strcmp(name, "net##_epoll_ctl") == 0) {
        out->fn = __net_epoll_ctl;
        out->param_count = 4;
        return 0;
    } else if(strcmp(name, "net##_epoll_wait") == 0) {
        out->fn = __net_epoll_wait;
        out->param_count = 4;
        return 0;
    } else if(strcmp(name, "net##_fcntl") == 0) {
        out->fn = __net_fcntl;
        out->param_count = 3;
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

    _sys_epoll_create = (void *) kallsyms_lookup_name("sys_epoll_create");
    _sys_epoll_ctl = (void *) kallsyms_lookup_name("sys_epoll_ctl");
    _sys_epoll_wait = (void *) kallsyms_lookup_name("sys_epoll_wait");
    _sys_fcntl = (void *) kallsyms_lookup_name("sys_fcntl");
    _sys_accept4 = (void *) kallsyms_lookup_name("sys_accept4");
    _sys_sendto = (void *) kallsyms_lookup_name("sys_sendto");
    _sys_recvfrom = (void *) kallsyms_lookup_name("sys_recvfrom");
    _sys_timerfd_create = (void *) kallsyms_lookup_name("sys_timerfd_create");
    _sys_timerfd_settime = (void *) kallsyms_lookup_name("sys_timerfd_settime");
    _sys_eventfd2 = (void *) kallsyms_lookup_name("sys_eventfd2");

    if(
        !_sys_epoll_create ||
        !_sys_epoll_ctl ||
        !_sys_epoll_wait ||
        !_sys_fcntl ||
        !_sys_accept4 ||
        !_sys_sendto ||
        !_sys_recvfrom ||
        !_sys_timerfd_create ||
        !_sys_timerfd_settime ||
        !_sys_eventfd2
    ) {
        printk(KERN_INFO "Unable to find some internal symbols.\n");
        return -EINVAL;
    }

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
