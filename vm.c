#include "vm.h"

static int (*_set_memory_ro)(unsigned long addr, int numpages);
static int (*_set_memory_rw)(unsigned long addr, int numpages);

int vm_init(void) {
    _set_memory_ro = (void *) kallsyms_lookup_name("set_memory_ro");
    _set_memory_rw = (void *) kallsyms_lookup_name("set_memory_rw");
    if(!_set_memory_ro || !_set_memory_rw) {
        printk(KERN_ALERT "unable to get address for set_memory_ro/rw\n");
        return -EINVAL;
    }
    return 0;
}

void vm_cleanup(void) {

}

static int resolve_import(const char *name, uint32_t param_count, struct execution_engine *ee, struct imported_func *out) {
    out->func = module_resolver_resolve_import(&ee->resolver, name, param_count);
    if(out->func == NULL) {
        return -EINVAL;
    } else {
        out->ctx = &ee->ctx;
        printk(KERN_INFO "Resolve: %s -> %px\n", name, out->func);
        return 0;
    }
}

static int32_t wasm_memory_grow(struct vmctx *ctx, size_t memory_index, uint32_t pages) {
    uint8_t *new_memory;
    unsigned long old_size, delta;

    if(ctx->memories) {
        old_size = (*ctx->memories)->bound;
        delta = (unsigned long) pages * 65536;
        new_memory = vmalloc(old_size + delta);
        if(!new_memory) {
            return -1;
        }
        memcpy(new_memory, (*ctx->memories)->base, old_size);
        memset(new_memory + old_size, 0, delta);
        vfree((*ctx->memories)->base);
        (*ctx->memories)->base = new_memory;
        (*ctx->memories)->bound += delta;
        return old_size / 65536;
    } else {
        return -1;
    }
}

static int32_t wasm_memory_size(struct vmctx *ctx, size_t memory_index) {
    if(ctx->memories) return (*ctx->memories)->bound / 65536;
    else return 0;
}

int init_execution_engine(const struct load_code_request *request, struct execution_engine *ee) {
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

    err = get_module_resolver(&ee->resolver);
    if(err) {
        return err;
    }

    // Initialize code storage.
    ee->code = __vmalloc(round_up_to_page_size(request->code_len), GFP_KERNEL, PAGE_KERNEL_EXEC);
    if(ee->code == NULL) {
        err = -ENOMEM;
        goto fail;
    }
    if((((unsigned long) ee->code) & 4095) != 0) {
        printk(KERN_INFO "Executable memory not aligned to page boundary\n");
        err = -EINVAL;
        goto fail;
    }
    if(copy_from_user(ee->code, request->code, request->code_len)) {
        err = -EFAULT;
        goto fail;
    }

    ee->code_len = request->code_len;

    if(request->memory && request->memory_len) {
        ee->local_memory_ptr_backing = &ee->local_memory_backing;
        ee->local_memory_backing.base = vmalloc(request->memory_len);
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
        ee->local_global_ptr_backing = vmalloc(sizeof(uint64_t *) * request->global_count);
        if(ee->local_global_ptr_backing == NULL) {
            err = -ENOMEM;
            goto fail;
        }
        ee->local_global_backing = vmalloc(sizeof(uint64_t) * request->global_count);
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
        ee->ctx.imported_funcs = vmalloc(sizeof(struct imported_func) * request->imported_func_count);
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
            if((err = resolve_import(import_req.name, import_req.param_count, ee, &ee->ctx.imported_funcs[i])) < 0) {
                printk(KERN_INFO "Failed to resolve import %s\n", import_req.name);
                err = -EINVAL;
                goto fail;
            }
        }
    }
    if(request->dynamic_sigindices && request->dynamic_sigindice_count) {
        ee->ctx.dynamic_sigindices = vmalloc(sizeof(uint32_t) * request->dynamic_sigindice_count);
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

        ee->local_table_backing.base = vmalloc(sizeof(struct anyfunc) * request->table_count);
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

    ee->stack_backing = vmalloc(STACK_SIZE);
    if(!ee->stack_backing) {
        err = -ENOMEM;
        goto fail;
    }
    ee->stack_begin = (void *) round_up_to_page_size((unsigned long) ee->stack_backing);
    ee->stack_end = (void *) (((unsigned long) ee->stack_backing + STACK_SIZE) & (~0xful)); // 16-byte alignment

    // FIXME: Accessing the stack guard triggers a triple fault.
    _set_memory_ro((unsigned long) ee->stack_begin, STACK_GUARD_SIZE / 4096);
    ee->ctx.stack_lower_bound = (uint8_t *) ((unsigned long) ee->stack_begin + STACK_GUARD_SIZE + 8192);
 
    return 0;

    fail:
    vfree(ee->stack_backing);
    vfree(ee->local_table_backing.base);
    vfree(ee->ctx.dynamic_sigindices);
    vfree(ee->ctx.imported_funcs);
    vfree(ee->local_global_backing);
    vfree(ee->local_global_ptr_backing);
    vfree(ee->local_memory_backing.base);
    vfree(ee->code);

    release_module_resolver(&ee->resolver);

    return err;
}

void destroy_execution_engine(struct execution_engine *ee) {
    int i;

    _set_memory_rw((unsigned long) ee->stack_begin, STACK_GUARD_SIZE / 4096);

    vfree(ee->stack_backing);
    vfree(ee->local_table_backing.base);
    vfree(ee->ctx.dynamic_sigindices);
    vfree(ee->ctx.imported_funcs);
    vfree(ee->local_global_backing);
    vfree(ee->local_global_ptr_backing);
    vfree(ee->local_memory_backing.base);
    vfree(ee->code);

    release_module_resolver(&ee->resolver);

    for(i = 0; i < ee->file_count; i++) {
        if(ee->files[i].f) {
            fput(ee->files[i].f);
        }
    }
    kfree(ee->files);
}

uint64_t ee_call0(struct execution_engine *ee, uint32_t offset) {
    typedef uint64_t(*func)(struct vmctx *);
    func f = (func) (ee->code + offset);
    return f(&ee->ctx);
}

struct file * ee_get_file(struct execution_engine *ee, int fd) {
    if(fd >= ee->file_count || !ee->files[fd].f) {
        return NULL;
    }
    return ee->files[fd].f;
}
EXPORT_SYMBOL(ee_get_file);

int ee_deregister_file(struct execution_engine *ee, int fd) {
    if(fd >= ee->file_count || !ee->files[fd].f) {
        return -EINVAL;
    }
    fput(ee->files[fd].f);
    ee->files[fd].f = NULL;
    return 0;
}
EXPORT_SYMBOL(ee_deregister_file);

int ee_take_and_register_file(struct execution_engine *ee, struct file *f) {
    int i, new_cap;
    struct file_entry *tmp;

    for(i = 0; i < ee->file_count; i++) {
        if(!ee->files[i].f) {
            ee->files[i].f = f;
            return i;
        }
    }

    if(ee->file_count == ee->file_cap) {
        new_cap = ee->file_cap * 2 + 1;
        tmp = krealloc(ee->files, sizeof(struct file_entry) * new_cap, GFP_KERNEL);
        if(!tmp) {
            return -ENOMEM;
        }
        ee->files = tmp;
        ee->file_cap = new_cap;
    }

    ee->files[ee->file_count].f = f;
    ee->file_count++;
    return ee->file_count - 1;
}
EXPORT_SYMBOL(ee_take_and_register_file);