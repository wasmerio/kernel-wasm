#pragma once

#include "request.h"
#include <linux/set_memory.h>

#define MAX_CODE_SIZE (1048576 * 8)
#define MAX_MEMORY_SIZE (1048576 * 16)
#define MAX_GLOBAL_COUNT 128
#define MAX_IMPORT_COUNT 128
#define MAX_DYNAMIC_SIGINDICE_COUNT 8192
#define MAX_TABLE_COUNT 1024

struct local_memory;
struct local_table;
struct imported_func;
struct vm_intrinsics;

struct vmctx {
    struct local_memory **memories;
    struct local_table **tables;
    uint64_t **globals;
    void **imported_memories;
    void **imported_tables;
    void **imported_globals;
    struct imported_func *imported_funcs;
    uint32_t *dynamic_sigindices;
    struct vm_intrinsics *intrinsics;
};

struct vm_intrinsics {
    void *memory_grow;
    void *memory_size;
};

struct local_memory {
    uint8_t *base;
    size_t bound;
    void *unused;
};

struct anyfunc {
    void *func;
    struct vmctx *ctx;
    uint32_t sig_id;
};
struct local_table {
    struct anyfunc *base;
    size_t count;
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
    struct vm_intrinsics intrinsics_backing;
    uint64_t *local_global_backing;
    uint64_t **local_global_ptr_backing;
    uint8_t *code_backing;
    uint8_t *code;
    uint32_t code_len;
};

static inline unsigned long round_up_to_page_size(unsigned long x) {
    return (x + 4095ul) & (~4095ul);
}

static uint8_t *vmctx_get_memory_slice(struct vmctx *ctx, uint32_t offset, uint32_t len) {
    struct local_memory *mem;
    unsigned long begin, end, real_end;

    if(ctx->memories == NULL) return NULL;
    mem = *ctx->memories;

    begin = (unsigned long) mem->base + (unsigned long) offset;
    end = begin + (unsigned long) len;
    real_end = (unsigned long) mem->base + (unsigned long) mem->bound;
    if(end < begin || begin < (unsigned long) mem->base || begin >= real_end || end > real_end) {
        return NULL;
    }
    return (uint8_t *) begin;
}

static int _wasm_import_env_print_str(struct vmctx *ctx, uint32_t offset, uint32_t len) {
    uint8_t *slice;
    slice = vmctx_get_memory_slice(ctx, offset, len);
    if(!slice) {
        return -1;
    }
    printk(KERN_INFO "wasm: %.*s\n", len, (char *) slice);
    return 0;
}

static int resolve_import(const char *name, struct vmctx *ctx, struct imported_func *out) {
    if(strcmp(name, "env##print_str") == 0) {
        out->func = _wasm_import_env_print_str;
        out->ctx = ctx;
        return 0;
    } else {
        return -EINVAL;
    }
}


/*pub memory_grow: unsafe extern "C" fn(
        ctx: &mut Ctx,
        memory_index: usize,
        delta: Pages,
    ) -> i32,
    pub memory_size: unsafe extern "C" fn(
        ctx: &Ctx,
        memory_index: usize,
    ) -> Pages,*/

static int32_t wasm_memory_grow(struct vmctx *ctx, size_t memory_index, uint32_t pages) {
    uint8_t *new_memory;
    unsigned long old_size;

    if(ctx->memories) {
        old_size = (*ctx->memories)->bound;
        new_memory = krealloc((*ctx->memories)->base, (*ctx->memories)->bound + (unsigned long) pages * 65536, GFP_KERNEL);
        if(!new_memory) {
            return -1;
        }
        (*ctx->memories)->base = new_memory;
        (*ctx->memories)->bound += (unsigned long) pages * 65536;
        return old_size / 65536;
    } else {
        return -1;
    }
}

static int32_t wasm_memory_size(struct vmctx *ctx, size_t memory_index) {
    if(ctx->memories) return (*ctx->memories)->bound / 65536;
    else return 0;
}

int init_execution_engine(const struct run_code_request *request, struct execution_engine *ee) {
    unsigned long num_pages;
    int err;
    int i;
    struct import_request import_req;
    struct table_entry_request table_entry_req;

    if(
        request->code_len == 0 ||
        request->code_len > MAX_CODE_SIZE ||
        request->memory_len > MAX_MEMORY_SIZE ||
        request->global_count > MAX_GLOBAL_COUNT ||
        request->imported_func_count > MAX_IMPORT_COUNT ||
        request->dynamic_sigindice_count > MAX_DYNAMIC_SIGINDICE_COUNT ||
        request->table_count > MAX_TABLE_COUNT
    ) {
        return -EINVAL;
    }

    memset(ee, 0, sizeof(struct execution_engine));

    // Initialize backing code storage.
    ee->code_backing = kmalloc(request->code_len + 8192, GFP_KERNEL);
    if(ee->code_backing == NULL) {
        return -ENOMEM;
    }

    // Align to page boundary.
    ee->code = (uint8_t *) round_up_to_page_size((unsigned long) ee->code_backing);
    if(copy_from_user(ee->code, request->code, request->code_len)) {
        err = -EFAULT;
        goto fail_before_set_code_x;
    }

    ee->code_len = request->code_len;

    // Set execution permission.
    num_pages = round_up_to_page_size(request->code_len) / 4096;
    if(set_memory_x((unsigned long) ee->code, num_pages)) {
        err = -EFAULT;
        goto fail_before_set_code_x;
    }

    if(request->memory && request->memory_len) {
        ee->local_memory_ptr_backing = &ee->local_memory_backing;
        ee->local_memory_backing.base = kmalloc(request->memory_len, GFP_KERNEL);
        if(ee->local_memory_backing.base == NULL) {
            err = -ENOMEM;
            goto fail;
        }
        if(copy_from_user(ee->local_memory_backing.base, request->memory, request->memory_len)) {
            err = -EFAULT;
            goto fail;
        }
        ee->local_memory_backing.bound = request->memory_len;
        ee->ctx.memories = &ee->local_memory_ptr_backing;
    }
    if(request->globals && request->global_count) {
        ee->local_global_ptr_backing = kmalloc(sizeof(uint64_t *) * request->global_count, GFP_KERNEL);
        if(ee->local_global_ptr_backing == NULL) {
            err = -ENOMEM;
            goto fail;
        }
        ee->local_global_backing = kmalloc(sizeof(uint64_t) * request->global_count, GFP_KERNEL);
        if(ee->local_global_backing == NULL) {
            err = -ENOMEM;
            goto fail;
        }
        if(copy_from_user(ee->local_global_backing, request->globals, sizeof(uint64_t) * request->global_count)) {
            err = -EFAULT;
            goto fail;
        }
        for(i = 0; i < request->global_count; i++) {
            ee->local_global_ptr_backing[i] = &ee->local_global_backing[i];
        }
        ee->ctx.globals = ee->local_global_ptr_backing;
    }
    if(request->imported_funcs && request->imported_func_count) {
        ee->ctx.imported_funcs = kmalloc(sizeof(struct imported_func) * request->imported_func_count, GFP_KERNEL);
        if(ee->ctx.imported_funcs == NULL) {
            err = -ENOMEM;
            goto fail;
        }
        for(i = 0; i < request->imported_func_count; i++) {
            if(copy_from_user(&import_req, &request->imported_funcs[i], sizeof(struct import_request))) {
                err = -EFAULT;
                goto fail;
            }
            import_req.name[sizeof(import_req.name) - 1] = 0;
            if((err = resolve_import(import_req.name, &ee->ctx, &ee->ctx.imported_funcs[i])) < 0) {
                printk(KERN_INFO "Failed to resolve import %s\n", import_req.name);
                err = -EINVAL;
                goto fail;
            }
        }
    }
    if(request->dynamic_sigindices && request->dynamic_sigindice_count) {
        ee->ctx.dynamic_sigindices = kmalloc(sizeof(uint32_t) * request->dynamic_sigindice_count, GFP_KERNEL);
        if(ee->ctx.dynamic_sigindices == NULL) {
            err = -ENOMEM;
            goto fail;
        }
        if(copy_from_user(
            ee->ctx.dynamic_sigindices,
            request->dynamic_sigindices,
            sizeof(uint32_t) * request->dynamic_sigindice_count
        )) {
            err = -EFAULT;
            goto fail;
        }
    }
    if(request->table && request->table_count) {
        ee->local_table_ptr_backing = &ee->local_table_backing;

        ee->local_table_backing.base = kmalloc(sizeof(struct anyfunc) * request->table_count, GFP_KERNEL);
        if(ee->local_table_backing.base == NULL) {
            err = -ENOMEM;
            goto fail;
        }

        ee->local_table_backing.count = request->table_count;

        for(i = 0; i < request->table_count; i++) {
            if(copy_from_user(&table_entry_req, &request->table[i], sizeof(struct table_entry_request))) {
                err = -EFAULT;
                goto fail;
            }
            if(table_entry_req.offset == (unsigned long) (-1L)) {
                ee->local_table_backing.base[i].func = NULL;
            } else {
                ee->local_table_backing.base[i].func =
                    (void *) ((unsigned long) ee->code + table_entry_req.offset);
            }
            ee->local_table_backing.base[i].ctx = &ee->ctx;
            ee->local_table_backing.base[i].sig_id = table_entry_req.sig_id;
        }
        ee->ctx.tables = &ee->local_table_ptr_backing;
    }

    ee->ctx.intrinsics = &ee->intrinsics_backing;
    ee->intrinsics_backing.memory_grow = wasm_memory_grow;
    ee->intrinsics_backing.memory_size = wasm_memory_size;

    return 0;

    fail:
    kfree(ee->local_table_backing.base);
    kfree(ee->ctx.dynamic_sigindices);
    kfree(ee->ctx.imported_funcs);
    kfree(ee->local_global_backing);
    kfree(ee->local_global_ptr_backing);
    kfree(ee->local_memory_backing.base);
    set_memory_nx((unsigned long) ee->code, num_pages);

    fail_before_set_code_x:
    kfree(ee->code_backing);

    return err;
}

void destroy_execution_engine(struct execution_engine *ee) {
    int num_pages;

    num_pages = round_up_to_page_size(ee->code_len) / 4096;

    kfree(ee->local_table_backing.base);
    kfree(ee->ctx.dynamic_sigindices);
    kfree(ee->ctx.imported_funcs);
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
