#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <linux/kthread.h>
#include <asm/fpu/api.h>
#include <asm/fpu/internal.h>

#include "vm.h"
#include "request.h"
#include "coroutine.h"

#define WASM_LOAD_CODE 0x1001
#define WASM_RUN_CODE 0x1002
#define WASM_READ_MEMORY 0x1003
#define WASM_WRITE_MEMORY 0x1004

const char *CLASS_NAME = "wasm";
const char *DEVICE_NAME = "wasmctl";

static int major_number;
static struct class *dev_class = NULL;
static struct device *dev_handle = NULL;
static int uapi_initialized = 0;

int uapi_init(void);
void uapi_cleanup(void);
static int wd_open(struct inode *, struct file *);
static int wd_release(struct inode *, struct file *);
static ssize_t wd_read(struct file *, char *, size_t, loff_t *);
static ssize_t wd_write(struct file *, const char *, size_t, loff_t *);
static ssize_t wd_ioctl(struct file *, unsigned int cmd, unsigned long arg);

static struct file_operations wasm_ops = {
    .open = wd_open,
    .read = wd_read,
    .write = wd_write,
    .release = wd_release,
    .unlocked_ioctl = wd_ioctl
};

int uapi_init(void) {
    major_number = register_chrdev(0, DEVICE_NAME, &wasm_ops);
    if(major_number < 0) {
        printk(KERN_ALERT "linux-ext-wasm: Device registration failed\n");
        return major_number;
    }

    dev_class = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(dev_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "linux-ext-wasm: Device class creation failed\n");
        return PTR_ERR(dev_class);
    }

    dev_handle = device_create(
        dev_class,
        NULL,
        MKDEV(major_number, 0),
        NULL,
        DEVICE_NAME
    );
    if(IS_ERR(dev_handle)) {
        class_destroy(dev_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "linux-ext-wasm: Device creation failed\n");
        return PTR_ERR(dev_handle);
    }

    printk(KERN_INFO "linux-ext-wasm: uapi initialized\n");
    uapi_initialized = 1;

    return 0;
}

void uapi_cleanup(void) {
    if(!uapi_initialized) return;

    // TODO: Is it possible that we still have open handles
    // to the UAPI device at this point?
    device_destroy(dev_class, MKDEV(major_number, 0));
    class_unregister(dev_class);
    class_destroy(dev_class);
    unregister_chrdev(major_number, DEVICE_NAME);
}

static int wd_open(struct inode *_inode, struct file *f) {
    struct privileged_session *sess;

    sess = kmalloc(sizeof(struct privileged_session), GFP_KERNEL);
    if(!sess) return -ENOMEM;

    init_privileged_session(sess);
    f->private_data = sess;
    return 0;
}

static int wd_release(struct inode *_inode, struct file *f) {
    struct privileged_session *sess = f->private_data;

    if(sess->ready) {
        printk(KERN_INFO "Released execution engine %px\n", &sess->ee);
        destroy_execution_engine(&sess->ee);
    }

    kfree(sess);

    return 0;
}

static ssize_t wd_read(struct file *_file, char *_data, size_t _len, loff_t *_offset) {
    return 0;
}

static ssize_t wd_write(struct file *_file, const char *data, size_t len, loff_t *offset) {
    return -EINVAL;
}

static ssize_t handle_wasm_load_code(struct file *f, void *arg) {
    int err;
    struct load_code_request req;
    struct privileged_session *sess = f->private_data;

    if(sess->ready) {
        err = -EINVAL;
        goto fail;
    }

    if(copy_from_user(&req, arg, sizeof(struct load_code_request))) {
        err = -EFAULT;
        goto fail;
    }
    if((err = init_execution_engine(&req, &sess->ee)) < 0) {
        goto fail;
    }
    printk(KERN_INFO
        "Initialized execution engine %px, "
        "code = %px, global_backing = %px, global_ptr_backing = %px, code_size = %u, memory_size = %lu, "
        "static_memory_addr = %px\n",
        &sess->ee,
        sess->ee.code,
        sess->ee.local_global_backing,
        sess->ee.local_global_ptr_backing,
        sess->ee.code_len,
        sess->ee.ctx.memory_bound,
        sess->ee.static_memory_vm ? sess->ee.static_memory_vm->addr : NULL
    );

    sess->ready = 1;
    return 0;

    fail:
    return err;
}

struct code_runner_task {
    struct semaphore exec_start, finalizer_start, finalizer_end;
    struct execution_engine *ee;
    struct run_code_request *req;
    uint64_t ret;
    int finalize_ret;
    struct task_struct *runner_ts;
    int finalizer_should_not_run;

    struct file *stdin, *stdout, *stderr;
};

static void code_runner_sched_in(struct preempt_notifier *notifier, int cpu) {
    struct execution_engine *ee = container_of(notifier, struct execution_engine, preempt_notifier);
    ee->preempt_in_count++;
}

static void code_runner_sched_out(struct preempt_notifier *notifier, struct task_struct *next) {
    struct execution_engine *ee = container_of(notifier, struct execution_engine, preempt_notifier);
    ee->preempt_out_count++;
}

static struct preempt_ops code_runner_preempt_ops = {
    .sched_in = code_runner_sched_in,
    .sched_out = code_runner_sched_out,
};

void code_runner_inner(struct Coroutine *co) {
    int fd;

    struct code_runner_task *task = co->private_data;
    up(&task->exec_start);

    if(vm_unshare_executor_files() < 0) {
        printk(KERN_INFO "Unable to unshare files\n");
        fput(task->stderr);
        fput(task->stdout);
        fput(task->stdin);
        return;
    }

    fd = get_unused_fd_flags(O_RDWR);
    if(fd < 0) {
        printk(KERN_INFO "Unable to get fd for stdin\n");
        fput(task->stderr);
        fput(task->stdout);
        fput(task->stdin);
        return;
    }
    fd_install(fd, task->stdin);
    printk(KERN_INFO "stdin = %d\n", fd);

    fd = get_unused_fd_flags(O_RDWR);
    if(fd < 0) {
        printk(KERN_INFO "Unable to get fd for stdout\n");
        fput(task->stderr);
        fput(task->stdout);
        return;
    }
    fd_install(fd, task->stdout);
    printk(KERN_INFO "stdout = %d\n", fd);

    fd = get_unused_fd_flags(O_RDWR);
    if(fd < 0) {
        printk(KERN_INFO "Unable to get fd for stderr\n");
        fput(task->stderr);
        return;
    }
    fd_install(fd, task->stderr);
    printk(KERN_INFO "stderr = %d\n", fd);

    kernel_fpu_begin();

    preempt_notifier_init(&task->ee->preempt_notifier, &code_runner_preempt_ops);
    preempt_notifier_register(&task->ee->preempt_notifier);

    preempt_enable();

    if(task->req->param_count != 0) {
        printk(KERN_INFO "invalid param count\n");
    } else {
        allow_signal(SIGKILL);
        task->ret = ee_call0(task->ee, task->req->entry_offset);
    }
}

static int code_runner(void *data) {
    struct code_runner_task *task = data;
    struct Coroutine co = {
        .stack = task->ee->stack_end,
        .entry = code_runner_inner,
        .terminated = 0,
        .private_data = task,
    };
    //printk(KERN_INFO "stack: %px-%px\n", task->ee->stack_begin, task->ee->stack_end);
    start_coroutine(&co);
    while(!co.terminated) {
        co_switch(&co.stack);
    }
    return 0;
}

static int task_finalizer(void *data) {
    struct code_runner_task *task = data;
    down(&task->finalizer_start);
    if(task->finalizer_should_not_run) {
        return 0;
    }

    task->finalize_ret = kthread_stop(task->runner_ts);
    up(&task->finalizer_end);
    return 0;
}

static ssize_t handle_wasm_read_memory(struct file *f, void *arg) {
    struct privileged_session *sess = f->private_data;
    struct read_memory_request req;
    uint8_t *slice;

    if(copy_from_user(&req, arg, sizeof(struct read_memory_request))) {
        return -EFAULT;
    }
    if(!sess->ready) {
        return -EINVAL;
    }

    slice = vmctx_get_memory_slice(&sess->ee.ctx, req.offset, req.len);
    if(!slice) {
        return -EINVAL;
    }
    if(copy_to_user(req.out, slice, req.len)) {
        return -EFAULT;
    }
    return 0;
}

static ssize_t handle_wasm_write_memory(struct file *f, void *arg) {
    struct privileged_session *sess = f->private_data;
    struct write_memory_request req;
    uint8_t *slice;

    if(copy_from_user(&req, arg, sizeof(struct write_memory_request))) {
        return -EFAULT;
    }
    if(!sess->ready) {
        return -EINVAL;
    }

    slice = vmctx_get_memory_slice(&sess->ee.ctx, req.offset, req.len);
    if(!slice) {
        return -EINVAL;
    }
    if(copy_from_user(slice, req.in, req.len)) {
        return -EFAULT;
    }
    return 0;
}

static ssize_t handle_wasm_run_code(struct file *f, void *arg) {
    int ret;
    int made_nx = 0;
    struct run_code_request req;
    struct code_runner_task task;
    struct privileged_session *sess = f->private_data;
    struct task_struct *runner_ts, *finalizer_ts;
    struct run_code_result result;

    if(copy_from_user(&req, arg, sizeof(struct run_code_request))) {
        return -EFAULT;
    }

    if(!sess->ready) {
        return -EINVAL;
    }

    memset(&task, 0, sizeof(struct code_runner_task));

    task.ee = &sess->ee;
    task.req = &req;

    task.stdin = fget_raw(0);
    if(IS_ERR(task.stdin)) {
        return PTR_ERR(task.stdin);
    }

    task.stdout = fget_raw(1);
    if(IS_ERR(task.stdout)) {
        fput(task.stdin);
        return PTR_ERR(task.stdout);
    }

    task.stderr = fget_raw(2);
    if(IS_ERR(task.stderr)) {
        fput(task.stdout);
        fput(task.stdin);
        return PTR_ERR(task.stderr);
    }
    sema_init(&task.exec_start, 0);
    sema_init(&task.finalizer_start, 0);
    sema_init(&task.finalizer_end, 0);

    finalizer_ts = kthread_run(task_finalizer, &task, "task_finalizer");
    if(!finalizer_ts || IS_ERR(finalizer_ts)) {
        fput(task.stderr);
        fput(task.stdout);
        fput(task.stdin);
        printk(KERN_INFO "Unable to start task finalizer\n");
        return -EINVAL;
    }

    runner_ts = kthread_create(code_runner, &task, "code_runner");
    if(!runner_ts || IS_ERR(runner_ts)) {
        task.finalizer_should_not_run = 1;
        up(&task.finalizer_start);
        fput(task.stderr);
        fput(task.stdout);
        fput(task.stdin);
        printk(KERN_INFO "Unable to start code runner\n");
        return -EINVAL;
    }
    get_task_struct(runner_ts);
    task.runner_ts = runner_ts;

    preempt_notifier_inc();
    wake_up_process(runner_ts);

    down(&task.exec_start); // wait for execution start
    up(&task.finalizer_start);

    while(down_interruptible(&task.finalizer_end) < 0) {
        // interrupted by signal
        ee_make_code_nx(&sess->ee); // trigger a page fault
        made_nx = 1;
        kill_pid(task_pid(runner_ts), SIGKILL, 0);
    }
    ret = task.finalize_ret;
    if(ret != 0) {
        printk(KERN_INFO "bad result from runner thread: %d\n", ret);
        result.success = 0;
        result.retval = 0;
    } else {
        //printk(KERN_INFO "result = %llu\n", task.ret);
        result.success = 1;
        result.retval = task.ret;
    }

    put_task_struct(runner_ts);
    if(made_nx) {
        ee_make_code_x(&sess->ee);
    }

    preempt_notifier_dec();
    printk(KERN_INFO "preempt_in = %llu, preempt_out = %llu\n", sess->ee.preempt_in_count, sess->ee.preempt_out_count);

    if(copy_to_user(
        req.result,
        &result,
        sizeof(struct run_code_result))
    ) {
        return -EFAULT;
    }
    return 0;
}

#define DISPATCH_CMD(cmd, f) case cmd: return (f)(file, (void *) arg);

static ssize_t wd_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch(cmd) {
        DISPATCH_CMD(WASM_LOAD_CODE, handle_wasm_load_code)
        DISPATCH_CMD(WASM_RUN_CODE, handle_wasm_run_code)
        DISPATCH_CMD(WASM_READ_MEMORY, handle_wasm_read_memory)
        DISPATCH_CMD(WASM_WRITE_MEMORY, handle_wasm_write_memory)
        default:
            return -EINVAL;
    }

    return -EINVAL;
}
