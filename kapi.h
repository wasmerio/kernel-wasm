#pragma once

struct execution_engine;

struct import_info {
    void *fn;
    int param_count;
};

struct import_resolver_instance {
    int (*resolve)(struct import_resolver_instance *self, const char *name, struct import_info *info_out);
    void (*release)(struct import_resolver_instance *self);
    void *private_data;
};

struct module_resolver {
    struct import_resolver_instance *resolvers;
    int resolver_count;
};

struct import_resolver {
    int (*get_instance)(struct execution_engine *ee, struct import_resolver *self, struct import_resolver_instance *out);
    void *private_data;
};

struct import_resolver * kwasm_resolver_register(struct import_resolver *resolver);
void kwasm_resolver_deregister(struct import_resolver *resolver);

int get_module_resolver(struct execution_engine *ee, struct module_resolver *out);
void release_module_resolver(struct module_resolver *in);
void * module_resolver_resolve_import(struct module_resolver *r, const char *name, int param_count);
