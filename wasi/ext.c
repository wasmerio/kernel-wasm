#include <linux/module.h>
#include "../kapi.h"
#include "../vm.h"

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

GEN_POLYFILL_2(_fd_prestat_get);
GEN_POLYFILL_3(_fd_prestat_dir_name);
GEN_POLYFILL_2(_environ_sizes_get);
GEN_POLYFILL_2(_environ_get);
GEN_POLYFILL_2(_args_sizes_get);
GEN_POLYFILL_2(_args_get);
GEN_POLYFILL_2(_random_get);
GEN_POLYFILL_4(_fd_write);
GEN_POLYFILL_4(_fd_read);
GEN_POLYFILL_1(_proc_exit);
GEN_POLYFILL_2(_fd_fdstat_get);

int do_resolve(struct import_resolver_instance *self, const char *name, struct import_info *out) {
    if(strcmp(name, "wasi_unstable##fd_prestat_get") == 0) {
        out->fn = _fd_prestat_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_prestat_dir_name") == 0) {
        out->fn = _fd_prestat_dir_name;
        out->param_count = 3;
        return 0;
    } else if(strcmp(name, "wasi_unstable##environ_sizes_get") == 0) {
        out->fn = _environ_sizes_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##environ_get") == 0) {
        out->fn = _environ_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##args_sizes_get") == 0) {
        out->fn = _args_sizes_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##args_get") == 0) {
        out->fn = _args_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##random_get") == 0) {
        out->fn = _random_get;
        out->param_count = 2;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_write") == 0) {
        out->fn = _fd_write;
        out->param_count = 4;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_read") == 0) {
        out->fn = _fd_read;
        out->param_count = 4;
        return 0;
    } else if(strcmp(name, "wasi_unstable##proc_exit") == 0) {
        out->fn = _proc_exit;
        out->param_count = 1;
        return 0;
    } else if(strcmp(name, "wasi_unstable##fd_fdstat_get") == 0) {
        out->fn = _fd_fdstat_get;
        out->param_count = 2;
        return 0;
    } else {
        return -EINVAL;
    }
}

int get_instance(struct import_resolver *self, struct import_resolver_instance *out) {
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
