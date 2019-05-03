#pragma once

#include <linux/module.h>

struct run_code_request {
    uint8_t __user *code;
    uint32_t code_len;
    uint8_t __user *memory;
    uint32_t memory_len;
    uint32_t memory_max;
    uint32_t __user *table;
    uint32_t table_count;
    uint64_t __user *globals;
    uint32_t global_count;
};
