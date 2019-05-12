#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "kapi.h"

struct resolver_entry {
    struct import_resolver inner;
    struct list_head list;
};

struct registry {
    struct mutex mu;
    struct list_head resolvers;
    int resolver_count;
};

static struct registry global_registry;

int init_global_registry(void) {
    mutex_init(&global_registry.mu);
    INIT_LIST_HEAD(&global_registry.resolvers);
    global_registry.resolver_count = 0;
    return 0;
}

void destroy_global_registry(void) {
    struct list_head *x;
    struct resolver_entry *last = NULL;
    list_for_each(x, &global_registry.resolvers) {
        kfree(last);
        last = container_of(x, struct resolver_entry, list);
    }
    kfree(last);
}

struct import_resolver * kwasm_resolver_register(struct import_resolver *resolver) {
    struct resolver_entry *entry;
    
    entry = kmalloc(sizeof(struct resolver_entry), GFP_KERNEL);
    if(!entry) return ERR_PTR(-ENOMEM);

    memcpy(&entry->inner, resolver, sizeof(struct import_resolver));

    mutex_lock(&global_registry.mu);
    list_add(&entry->list, &global_registry.resolvers);
    global_registry.resolver_count++;
    resolver = &entry->inner;
    mutex_unlock(&global_registry.mu);

    return resolver;
}
EXPORT_SYMBOL(kwasm_resolver_register);

void kwasm_resolver_deregister(struct import_resolver *resolver) {
    struct resolver_entry *entry;

    mutex_lock(&global_registry.mu);
    entry = container_of(resolver, struct resolver_entry, inner);
    list_del(&entry->list);
    kfree(entry);
    global_registry.resolver_count--;
    mutex_unlock(&global_registry.mu);
}
EXPORT_SYMBOL(kwasm_resolver_deregister);

int get_module_resolver(struct execution_engine *ee, struct module_resolver *out) {
    int i;
    int err;
    struct resolver_entry *entry;
    struct list_head *x;

    mutex_lock(&global_registry.mu);
    out->resolvers = kmalloc(sizeof(struct import_resolver_instance) * global_registry.resolver_count, GFP_KERNEL);
    if(!out->resolvers) {
        mutex_unlock(&global_registry.mu);
        return -ENOMEM;
    }

    i = 0;
    list_for_each(x, &global_registry.resolvers) {
        entry = container_of(x, struct resolver_entry, list);
        memset(&out->resolvers[i], 0, sizeof(out->resolvers[i]));
        err = entry->inner.get_instance(ee, &entry->inner, &out->resolvers[i]);
        if(err) {
            kfree(out->resolvers);
            out->resolvers = NULL;
            mutex_unlock(&global_registry.mu);
            return err;
        }
        i++;
    }
    out->resolver_count = global_registry.resolver_count;

    mutex_unlock(&global_registry.mu);
    return 0;
}

void release_module_resolver(struct module_resolver *in) {
    int i;

    for(i = 0; i < in->resolver_count; i++) {
        if(in->resolvers[i].release) in->resolvers[i].release(&in->resolvers[i]);
    }
    kfree(in->resolvers);
}

void * module_resolver_resolve_import(struct module_resolver *r, const char *name, int param_count) {
    int i, err;
    struct import_info info;

    for(i = 0; i < r->resolver_count; i++) {
        if(r->resolvers[i].resolve) {
            err = r->resolvers[i].resolve(&r->resolvers[i], name, &info);
            if(err == 0) {
                if(info.param_count == param_count) {
                    return info.fn;
                } else {
                    return NULL;
                }
            }
        }
    }
    return NULL;
}