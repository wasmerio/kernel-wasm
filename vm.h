#pragma once

#include "request.h"
#include <linux/set_memory.h>

#define MAX_CODE_SIZE (1048576 * 8)
#define MAX_MEMORY_SIZE (1048576 * 16)
#define MAX_GLOBAL_COUNT 128

struct local_memory;
struct local_table;
struct imported_func;

struct vmctx {
    struct local_memory **memories;
    struct local_table **tables;
    uint64_t **globals;
    void **imported_memories;
    void **imported_tables;
    void **imported_globals;
    struct imported_func *imported_funcs;
    uint32_t *dynamic_sigindices;
};

struct local_memory {
    uint8_t *base;
    size_t bound;
    void *unused;
};
struct local_table {
    void *unused;
};
struct imported_func {
    void *func;
    struct vmctx *ctx;
};

struct execution_engine {
    struct vmctx ctx;
    struct local_memory local_memory_backing;
    struct local_memory *local_memory_ptr_backing;
    struct local_table local_table_backing;
    struct local_table *local_table_ptr_backing;
    uint64_t *local_global_backing;
    uint64_t **local_global_ptr_backing;
    uint8_t *code_backing;
    uint8_t *code;
    uint32_t code_len;
};

static inline unsigned long round_up_to_page_size(unsigned long x) {
    return (x + 4095ul) & (~4095ul);
}

int init_execution_engine(const struct run_code_request *request, struct execution_engine *ee) {
    unsigned long num_pages;
    int err;
    int i;

    if(
        request->code_len == 0 ||
        request->code_len > MAX_CODE_SIZE ||
        request->memory_len > MAX_MEMORY_SIZE ||
        request->global_count > MAX_GLOBAL_COUNT
    ) {
        return -EINVAL;
    }

    memset(ee, 0, sizeof(struct execution_engine));

    // Initialize backing code storage.
    ee->code_backing = kmalloc(request->code_len + 8192, GFP_KERNEL);
    if(ee->code_backing == NULL || IS_ERR(ee->code_backing)) {
        return -ENOMEM;
    }

    // Align to page boundary.
    ee->code = (uint8_t *) round_up_to_page_size((unsigned long) ee->code_backing);
    if(copy_from_user(ee->code, request->code, request->code_len)) {
        err = -EFAULT;
        goto fail_code_backing;
    }

    ee->code_len = request->code_len;

    // Set execution permission.
    num_pages = round_up_to_page_size(request->code_len) / 4096;
    if(set_memory_x((unsigned long) ee->code, num_pages)) {
        err = -EFAULT;
        goto fail_code_backing;
    }

    if(request->memory && request->memory_len) {
        ee->local_memory_ptr_backing = &ee->local_memory_backing;
        ee->local_memory_backing.base = kmalloc(request->memory_len, GFP_KERNEL);
        if(ee->local_memory_backing.base == NULL || IS_ERR(ee->local_memory_backing.base)) {
            err = -ENOMEM;
            goto fail_memory_nx;
        }
        if(copy_from_user(ee->local_memory_backing.base, request->memory, request->memory_len)) {
            err = -EFAULT;
            goto fail_memory_backing;
        }
        ee->local_memory_backing.bound = request->memory_len;
        ee->ctx.memories = &ee->local_memory_ptr_backing;
    }
    if(request->globals && request->global_count) {
        ee->local_global_ptr_backing = kmalloc(sizeof(uint64_t *) * request->global_count, GFP_KERNEL);
        if(ee->local_global_ptr_backing == NULL || IS_ERR(ee->local_global_ptr_backing)) {
            err = -ENOMEM;
            goto fail_memory_backing;
        }
        ee->local_global_backing = kmalloc(sizeof(uint64_t) * request->global_count, GFP_KERNEL);
        if(ee->local_global_backing == NULL || IS_ERR(ee->local_global_backing)) {
            err = -ENOMEM;
            goto fail_global_ptr_backing;
        }
        if(copy_from_user(ee->local_global_backing, request->globals, sizeof(uint64_t) * request->global_count)) {
            err = -EFAULT;
            goto fail_global_backing;
        }
        for(i = 0; i < request->global_count; i++) {
            ee->local_global_ptr_backing[i] = &ee->local_global_backing[i];
        }
        ee->ctx.globals = ee->local_global_ptr_backing;
    }

    return 0;

    fail_global_backing:
    kfree(ee->local_global_backing);

    fail_global_ptr_backing:
    kfree(ee->local_global_ptr_backing);

    fail_memory_backing:
    kfree(ee->local_memory_backing.base);

    fail_memory_nx:
    set_memory_nx((unsigned long) ee->code, num_pages);

    fail_code_backing:
    kfree(ee->code_backing);

    return err;
}

void destroy_execution_engine(struct execution_engine *ee) {
    int num_pages;

    num_pages = round_up_to_page_size(ee->code_len) / 4096;

    kfree(ee->local_global_backing);
    kfree(ee->local_global_ptr_backing);
    kfree(ee->local_memory_backing.base);
    set_memory_nx((unsigned long) ee->code, num_pages);
    kfree(ee->code_backing);
}

uint64_t ee_call0(struct execution_engine *ee, uint32_t offset) {
    typedef uint64_t(*func)(struct vmctx *);
    func f = (func) (ee->code + offset);
    return f(&ee->ctx);
}
