#include "vm.h"
#include <linux/delay.h>

static int (*_set_memory_ro)(unsigned long addr, int numpages);
static int (*_set_memory_rw)(unsigned long addr, int numpages);
static int (*_map_kernel_range_noflush)(unsigned long addr, unsigned long size,
			    pgprot_t prot, struct page **pages);
static void (*_put_files_struct)(struct files_struct *files);
static int (*_unshare_files)(struct files_struct **displaced);

int vm_unshare_executor_files(void) {
    struct files_struct *displaced = NULL;
    int ret;
    
    ret = _unshare_files(&displaced);
    if(ret < 0) {
        return ret;
    }
    if(displaced) _put_files_struct(displaced);
    return 0;
}

int vm_init(void) {
    _set_memory_ro = (void *) kallsyms_lookup_name("set_memory_ro");
    _set_memory_rw = (void *) kallsyms_lookup_name("set_memory_rw");
    _map_kernel_range_noflush = (void *) kallsyms_lookup_name("map_kernel_range_noflush");
    _unshare_files = (void *) kallsyms_lookup_name("unshare_files");
    _put_files_struct = (void *) kallsyms_lookup_name("put_files_struct");
    if(!_set_memory_ro || !_set_memory_rw || !_map_kernel_range_noflush || !_unshare_files || !_put_files_struct) {
        printk(KERN_ALERT "unable to get address for internal symbol(s)\n");
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
        out->ctx_indirect = &ee->ctx_indirect;
        //printk(KERN_INFO "Resolve: %s -> %px\n", name, out->func);
        return 0;
    }
}

static int32_t wasm_memory_grow(struct vmctx *ctx, size_t memory_index, uint32_t pages) {
    unsigned long old_size, delta;
    int new_os_page_count;
    int i, j;
    struct execution_engine *ee = (void *) ctx;

    if(ctx->memory_base) {
        old_size = ctx->memory_bound;
        if(pages == 0) return old_size / 65536;

        delta = (unsigned long) pages * 65536;
        if(old_size + delta > STATIC_MEMORY_AVAILABLE) {
            printk(KERN_INFO "Rejected memory grow request (#1)\n");
            return -1;
        }

        new_os_page_count = ((unsigned long) (old_size + delta) / PAGE_SIZE);
        for(i = ee->memory_page_count; i < new_os_page_count; i++) {
            ee->memory_pages[i] = alloc_page(GFP_KERNEL);
            if(!ee->memory_pages[i]) {
                for(j = ee->memory_page_count; j < i; j++) {
                    __free_page(ee->memory_pages[j]);
                    ee->memory_pages[j] = NULL;
                }
                printk(KERN_INFO "Rejected memory grow request (#2)\n");
                return -1;
            }
        }

        if(_map_kernel_range_noflush(
            (unsigned long) ee->static_memory_vm->addr + old_size,
            delta,
            PAGE_KERNEL,
            &ee->memory_pages[ee->memory_page_count]
        ) != delta / PAGE_SIZE) {
            printk(KERN_INFO "FIXME: something might not be handled properly here (map_kernel_range_noflush failure)\n");
            return -1;
        }
        flush_cache_vmap(
            (unsigned long) ee->static_memory_vm->addr + old_size,
            (unsigned long) ee->static_memory_vm->addr + old_size + delta
        );

        ee->memory_page_count = new_os_page_count;

        ctx->memory_bound += delta;
        return old_size / 65536;
    } else {
        return -1;
    }
}

static int32_t wasm_memory_size(struct vmctx *ctx, size_t memory_index) {
    if(ctx->memory_base) return ctx->memory_bound / 65536;
    else return 0;
}

int init_execution_engine(const struct load_code_request *request, struct execution_engine *ee) {
    int err;
    int i;
    struct import_request import_req;
    struct table_entry_request table_entry_req;
    int pages_allocated_without_mapping = 0;

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

    err = get_module_resolver(ee, &ee->resolver);
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
        ee->static_memory_vm = __get_vm_area(STATIC_MEMORY_SIZE, VM_MAP, VMALLOC_START, VMALLOC_END);
        if(!ee->static_memory_vm) {
            err = -ENOMEM;
            goto fail;
        }

        ee->memory_page_count = (request->memory_len / PAGE_SIZE);
        ee->memory_pages = vzalloc(sizeof(struct page *) * (STATIC_MEMORY_AVAILABLE / PAGE_SIZE));
        if(!ee->memory_pages) {
            err = -ENOMEM;
            goto fail;
        }
        for(i = 0; i < ee->memory_page_count; i++) {
            ee->memory_pages[i] = alloc_page(GFP_KERNEL);
            if(!ee->memory_pages[i]) {
                ee->memory_page_count = i;
                pages_allocated_without_mapping = 1;
                err = -ENOMEM;
                goto fail;
            }
        }
        if(_map_kernel_range_noflush(
            (unsigned long) ee->static_memory_vm->addr,
            request->memory_len,
            PAGE_KERNEL,
            ee->memory_pages
        ) != ee->memory_page_count) {
            printk(KERN_INFO "FIXME: something might not be handled properly here (map_kernel_range_noflush failure)\n");
            err = -ENOMEM;
            goto fail;
        }
        flush_cache_vmap(
            (unsigned long) ee->static_memory_vm->addr,
            (unsigned long) ee->static_memory_vm->addr + request->memory_len
        );
        ee->ctx.memory_base = ee->static_memory_vm->addr;
        if(copy_from_user(ee->ctx.memory_base, request->memory, request->memory_len)) {
            err = -EFAULT;
            goto fail;
        }
        ee->ctx.memory_bound = request->memory_len;
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
    ee->ctx_indirect = &ee->ctx;

    // FIXME: Accessing the stack guard triggers a triple fault.
    _set_memory_ro((unsigned long) ee->stack_begin, STACK_GUARD_SIZE / 4096);
    ee->ctx.stack_lower_bound = (uint8_t *) ((unsigned long) ee->stack_begin + STACK_GUARD_SIZE + 8192);
 
    return 0;

    fail:

    if(ee->memory_pages) {
        if(!pages_allocated_without_mapping) {
            unmap_kernel_range(
                (unsigned long) ee->static_memory_vm->addr,
                ee->memory_page_count * PAGE_SIZE
            );
        }
        for(i = 0; i < ee->memory_page_count; i++) {
            __free_page(ee->memory_pages[i]);
        }
        vfree(ee->memory_pages);
    }
    if(ee->static_memory_vm) free_vm_area(ee->static_memory_vm);
    vfree(ee->stack_backing);
    vfree(ee->local_table_backing.base);
    vfree(ee->ctx.dynamic_sigindices);
    vfree(ee->ctx.imported_funcs);
    vfree(ee->local_global_backing);
    vfree(ee->local_global_ptr_backing);
    vfree(ee->code);

    release_module_resolver(&ee->resolver);

    return err;
}

void destroy_execution_engine(struct execution_engine *ee) {
    int i;

    _set_memory_rw((unsigned long) ee->stack_begin, STACK_GUARD_SIZE / 4096);

    if(ee->memory_pages) {
        unmap_kernel_range(
            (unsigned long) ee->static_memory_vm->addr,
            ee->memory_page_count * PAGE_SIZE
        );
        for(i = 0; i < ee->memory_page_count; i++) {
            __free_page(ee->memory_pages[i]);
        }
        vfree(ee->memory_pages);
    }
    if(ee->static_memory_vm) free_vm_area(ee->static_memory_vm);
    vfree(ee->stack_backing);
    vfree(ee->local_table_backing.base);
    vfree(ee->ctx.dynamic_sigindices);
    vfree(ee->ctx.imported_funcs);
    vfree(ee->local_global_backing);
    vfree(ee->local_global_ptr_backing);
    vfree(ee->code);

    release_module_resolver(&ee->resolver);
}

uint64_t ee_call0(struct execution_engine *ee, uint32_t offset) {
    typedef uint64_t(*func)(struct vmctx *);
    func f = (func) (ee->code + offset);
    return f(&ee->ctx);
}
