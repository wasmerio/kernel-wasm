#pragma once

#include "request.h"
#include <linux/set_memory.h>
#include <linux/sched/mm.h>

#define MAX_CODE_SIZE (1048576 * 8)
#define MAX_MEMORY_SIZE (1048576 * 16)
#define MAX_GLOBAL_COUNT 128
#define MAX_IMPORT_COUNT 128
#define MAX_DYNAMIC_SIGINDICE_COUNT 8192
#define MAX_TABLE_COUNT 1024
#define STACK_SIZE (2 * 1048576)
#define STACK_GUARD_SIZE 8192

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
    uint8_t *code;
    uint32_t code_len;
    uint8_t *stack_begin;
    uint8_t *stack_end;
    uint8_t *stack_backing;
    struct mm_struct *mm;
};

// We are assuming that no concurrent access to a session would ever happen - is this true?
struct privileged_session {
    int ready;
    struct execution_engine ee;
};

void init_privileged_session(struct privileged_session *sess) {
    sess->ready = 0;
}

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

/*
static void make_ro(struct mm_struct *mm, unsigned long begin, unsigned long end) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    unsigned long addr = begin;

    while(addr < end) {
        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd)) {
            addr += PAGE_SIZE;
            continue;
        }
        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d)) {
            addr += PAGE_SIZE;
            continue;
        }
        pud = pud_offset(p4d, addr);
        if (pud_none(*pud)) {
            addr += PAGE_SIZE;
            continue;
        }
        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd)) {
            addr += PAGE_SIZE;
            continue;
        }
        pte = pte_offset_map(pmd, addr);
        if (pte_present(*pte)){
            *pte = pte_wrprotect(*pte);         
        }
        addr += PAGE_SIZE;
    }
}

static void make_rw(struct mm_struct *mm, unsigned long begin, unsigned long end) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    unsigned long addr = begin;

    while(addr < end) {
        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd)) {
            addr += PAGE_SIZE;
            continue;
        }
        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d)) {
            addr += PAGE_SIZE;
            continue;
        }
        pud = pud_offset(p4d, addr);
        if (pud_none(*pud)) {
            addr += PAGE_SIZE;
            continue;
        }
        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd)) {
            addr += PAGE_SIZE;
            continue;
        }
        pte = pte_offset_map(pmd, addr);
        if (pte_present(*pte)){
            *pte = pte_mkwrite(*pte);         
        }
        addr += PAGE_SIZE;
    }
}
*/

void ee_make_code_nx(struct execution_engine *ee) {
    set_memory_nx((unsigned long) ee->code, round_up_to_page_size(ee->code_len) / 4096);
}

void ee_make_code_x(struct execution_engine *ee) {
    set_memory_x((unsigned long) ee->code, round_up_to_page_size(ee->code_len) / 4096);
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
            if((err = resolve_import(import_req.name, &ee->ctx, &ee->ctx.imported_funcs[i])) < 0) {
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

    ee->mm = current->mm;
    mmgrab(ee->mm);
    //make_ro(ee->mm, (unsigned long) ee->stack_begin, (unsigned long) ee->stack_begin + STACK_GUARD_SIZE); // stack guard

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

    return err;
}

void destroy_execution_engine(struct execution_engine *ee) {
    //make_rw(ee->mm, (unsigned long) ee->stack_begin, (unsigned long) ee->stack_begin + STACK_GUARD_SIZE);
    mmdrop(ee->mm);

    vfree(ee->stack_backing);
    vfree(ee->local_table_backing.base);
    vfree(ee->ctx.dynamic_sigindices);
    vfree(ee->ctx.imported_funcs);
    vfree(ee->local_global_backing);
    vfree(ee->local_global_ptr_backing);
    vfree(ee->local_memory_backing.base);
    vfree(ee->code);
}

uint64_t ee_call0(struct execution_engine *ee, uint32_t offset) {
    typedef uint64_t(*func)(struct vmctx *);
    func f = (func) (ee->code + offset);
    return f(&ee->ctx);
}
