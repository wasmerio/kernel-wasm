# kernel-wasm

This is an in-kernel runtime for WebAssembly, based on Wasmer.

## History

I wrote [Cervus](https://github.com/cervus-v/cervus), another WebAssembly "usermode" subsystem running in Linux kernel, about one year ago. At that time we didn't yet have WASI or "production-ready" non-Web runtimes, though the Cervus project has proved that the idea is possible and of great potential.

Now the WASM ecosystem is growing, and it's time to build a complete in-kernel WASM runtime for real applications.

## Features

- [x] WASI support (incomplete; work in progress)
- [x] Asynchronous networking extension with `epoll` support
- [x] Modular host API provider interface
- [x] Fully sandboxed execution environment with software fault isolation
- [ ] Device drivers in WASM
- [ ] "eBPF" in WASM

## Why run WebAssembly in the kernel?

Performance and flexibility.

Since WASM is a virtual ISA protected by a virtual machine, we don't need to rely on external hardware and software checks to ensure safety. Running WASM in the kernel avoids most of the overhead introduced by those checks, e.g. system call (context switching) and `copy_{from,to}_user`, therefore improving performance.

Also, having low-level control means that we can implement a lot of features that were heavy or impossible in userspace, like virtual memory tricks and handling of intensive kernel events (like network packet filtering).

## Build and run

Check and ensure:

- Your system is running Linux kernel 4.15 or higher.
- Your kernel has preemption enabled. Attempting to run WASM user code without kernel preemption will freeze your system.
- Kernel headers are installed and the building environment is properly set up.

Then just run `make` in the root directory, and (optionally) `networking` and `wasi`:

```
make
cd networking && make
cd ../wasi && make
cd ..
```

Load the modules using `insmod`:

```
sudo insmod kernel-wasm.ko
sudo insmod wasi/kwasm-wasi.ko
sudo insmod networking/kwasm-networking.ko
```

Select the `kernel` loader and `singlepass` backend when running Wasmer:

```
sudo wasmer run --backend singlepass --disable-cache --loader kernel your_wasm_file.wasm
```

## Security

Running user code in kernel mode is always a dangerous thing. Although special measures are already taken against different kinds of attacks, it's advised that only trusted binaries should be run through this module, in a short term before we fully reviewed the codebase for security.

Currently known security risks and their solutions:

- [x] Stack overflow check (implemented with explicit bound checking in codegen)
- [x] Memory bound check (implemented with 6GB virtual address space)
- [x] Forceful termination (implemented by setting NX on code pages)
- [ ] Floating point (should implement with `kernel_fpu_{begin,end}` and `preempt_notifier`)
