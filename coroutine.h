#pragma once

asm(
    "co_switch:\n"
    "push %rbx\n"
    "push %rbp\n"
    "push %r12\n"
    "push %r13\n"
    "push %r14\n"
    "push %r15\n"
    "mov (%rdi), %rax\n"
    "mov %rsp, (%rdi)\n"
    "mov %rax, %rsp\n"
    "pop %r15\n"
    "pop %r14\n"
    "pop %r13\n"
    "pop %r12\n"
    "pop %rbp\n"
    "pop %rbx\n"
    "ret\n"

    "pre_call_entry:\n"
    "pop %rax\n" // entry
    "pop %rdi\n" // co
    "call *%rax\n"
    "ud2\n"
);

void co_switch(void **stack);
void pre_call_entry(void);

struct Coroutine;

typedef void (*CoEntry)(struct Coroutine *co);

struct Coroutine {
    void *stack;
    CoEntry entry;
    int terminated;
    void *private_data;
};

void call_entry(struct Coroutine *co) {
    co_switch(&co->stack);
    co->entry(co);
    co->terminated = 1;
    co_switch(&co->stack);
}

void start_coroutine(struct Coroutine *co) {
    void **stack = (void **) co->stack;

    *(--stack) = co;
    *(--stack) = call_entry; // 16-byte aligned

    *(--stack) = pre_call_entry;

    *(--stack) = 0;
    *(--stack) = 0;
    *(--stack) = 0;
    *(--stack) = 0;
    *(--stack) = 0;
    *(--stack) = 0;

    co->stack = (void *) stack;

    co_switch(&co->stack);

}
