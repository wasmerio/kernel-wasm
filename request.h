#pragma once

#include <linux/module.h>

struct import_request {
    char name[64];
    uint32_t param_count;
};

struct table_entry_request {
    unsigned long offset;
    uint32_t sig_id;
};

struct load_code_request {
    uint8_t __user *code;
    uint32_t code_len;
    uint8_t __user *memory;
    uint32_t memory_len;
    uint32_t memory_max;
    struct table_entry_request __user *table;
    uint32_t table_count;
    uint64_t __user *globals;
    uint32_t global_count;
    struct import_request __user *imported_funcs;
    uint32_t imported_func_count;
    uint32_t __user *dynamic_sigindices;
    uint32_t dynamic_sigindice_count;
};

struct run_code_result {
    uint32_t success;
    uint64_t retval;
};

struct run_code_request {
    uint32_t entry_offset;
    uint64_t __user *params;
    uint32_t param_count;
    struct run_code_result __user *result;
};

struct read_memory_request {
    uint8_t __user *out;
    uint32_t offset;
    uint32_t len;
};

struct write_memory_request {
    const uint8_t __user *in;
    uint32_t offset;
    uint32_t len;
};
