#pragma once

#include "request.h"
#include <linux/set_memory.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/preempt.h>
#include <asm/cacheflush.h>
#include "kapi.h"

#define MAX_CODE_SIZE (1048576 * 8)
#define MAX_MEMORY_SIZE (1048576 * 16)
#define MAX_GLOBAL_COUNT 128
#define MAX_IMPORT_COUNT 128
#define MAX_DYNAMIC_SIGINDICE_COUNT 8192
#define MAX_TABLE_COUNT 1024
#define STACK_SIZE (2 * 1048576)
#define STACK_GUARD_SIZE 8192
#define STATIC_MEMORY_SIZE (6144ul * 1048576ul)
#define STATIC_MEMORY_AVAILABLE (1024ul * 1048576ul)

struct local_memory;
struct local_table;
struct imported_func;
struct vm_intrinsics;

struct vmctx {
    struct local_memory **_memories;
    struct local_table **tables;
    uint64_t **globals;
    void **_imported_memories;
    void **imported_tables;
    void **imported_globals;
    struct imported_func *imported_funcs;
    uint32_t *dynamic_sigindices;
    struct vm_intrinsics *intrinsics;
    uint8_t *stack_lower_bound;
    uint8_t *memory_base;
    size_t memory_bound;
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

    // Corresponds to `FuncCtx` in Wasmer, but only has one (the first) field which is used in generated code.
    struct vmctx **ctx_indirect;
};

struct execution_engine {
    struct vmctx ctx;
    struct local_table local_table_backing;
    struct local_table *local_table_ptr_backing;
    struct vm_intrinsics intrinsics_backing;
    struct module_resolver resolver;
    uint64_t *local_global_backing;
    uint64_t **local_global_ptr_backing;
    uint8_t *code;
    uint32_t code_len;
    uint8_t *stack_begin;
    uint8_t *stack_end;
    uint8_t *stack_backing;
    struct vmctx *ctx_indirect;

    struct vm_struct *static_memory_vm;
    struct page **memory_pages;
    int memory_page_count;

    struct preempt_notifier preempt_notifier;
    uint64_t preempt_in_count, preempt_out_count;
};

// We are assuming that no concurrent access to a session would ever happen - is this true?
struct privileged_session {
    int ready;
    struct execution_engine ee;
};

static inline void init_privileged_session(struct privileged_session *sess) {
    sess->ready = 0;
}

static inline unsigned long round_up_to_page_size(unsigned long x) {
    return (x + 4095ul) & (~4095ul);
}

static inline uint8_t *vmctx_get_memory_slice(struct vmctx *ctx, uint32_t offset, uint32_t len) {
    unsigned long begin, end, real_end;

    begin = (unsigned long) ctx->memory_base + (unsigned long) offset;
    end = begin + (unsigned long) len;
    real_end = (unsigned long) ctx->memory_base + (unsigned long) ctx->memory_bound;
    if(end < begin || begin < (unsigned long) ctx->memory_base || begin >= real_end || end > real_end) {
        return NULL;
    }
    return (uint8_t *) begin;
}

static inline void ee_make_code_nx(struct execution_engine *ee) {
    set_memory_nx((unsigned long) ee->code, round_up_to_page_size(ee->code_len) / 4096);
}

static inline void ee_make_code_x(struct execution_engine *ee) {
    set_memory_x((unsigned long) ee->code, round_up_to_page_size(ee->code_len) / 4096);
}

int vm_unshare_executor_files(void);
int init_execution_engine(const struct load_code_request *request, struct execution_engine *ee);
void destroy_execution_engine(struct execution_engine *ee);
uint64_t ee_call0(struct execution_engine *ee, uint32_t offset);
