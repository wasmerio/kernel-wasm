#include <linux/module.h>

extern int uapi_init(void);
void uapi_cleanup(void);

int __init init_module(void) {
    if(uapi_init() != 0) {
        return -EINVAL;
    }
    printk(KERN_INFO "linux-ext-wasm: Module loaded\n");
    return 0;
}

void __exit cleanup_module(void) {
    uapi_cleanup();
    printk(KERN_INFO "linux-ext-wasm: Module unloaded\n");
}

MODULE_LICENSE("GPL");
