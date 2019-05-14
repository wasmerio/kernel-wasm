#include <linux/module.h>

int uapi_init(void);
void uapi_cleanup(void);

int init_global_registry(void);
void destroy_global_registry(void);

int vm_init(void);
void vm_cleanup(void);

int __init init_module(void) {
    if(uapi_init() != 0) {
        return -EINVAL;
    }
    if(init_global_registry() != 0) {
        uapi_cleanup();
        return -EINVAL;
    }
    if(vm_init() != 0) {
        destroy_global_registry();
        uapi_cleanup();
        return -EINVAL;
    }
    printk(KERN_INFO "linux-ext-wasm: Module loaded\n");
    return 0;
}

void __exit cleanup_module(void) {
    vm_cleanup();
    destroy_global_registry();
    uapi_cleanup();
    printk(KERN_INFO "linux-ext-wasm: Module unloaded\n");
}

MODULE_LICENSE("GPL");
