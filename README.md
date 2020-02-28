# kernel-wasm

Safely run WebAssembly in the Linux kernel, with faster-than-native performance.

## Background

I wrote [Cervus](https://github.com/cervus-v/cervus), another WebAssembly "usermode" subsystem running in Linux kernel, about one year ago. At that time we didn't yet have WASI or any "production-ready" non-Web runtimes, though the Cervus project has proved that the idea is possible and of great potential.

Now the WASM ecosystem is growing, and it's time to build a complete in-kernel WASM runtime for real applications.

## Features

- [x] WASI support (incomplete; work in progress)
- [x] Asynchronous networking extension with `epoll` support
- [x] Modular host API provider interface
- [x] Fully sandboxed execution environment with software fault isolation
- [ ] Faster than native (partially achieved)
- [ ] Device drivers in WASM
- [ ] "eBPF" in WASM

## Why run WebAssembly in the kernel?

Performance and flexibility.

Since WASM is a virtual ISA protected by a virtual machine, we don't need to rely on external hardware and software checks to ensure safety. Running WASM in the kernel avoids most of the overhead introduced by those checks, e.g. system call (context switching) and `copy_{from,to}_user`, therefore improving performance.

Also, having low-level control means that we can implement a lot of features that were heavy or impossible in userspace, like virtual memory tricks and handling of intensive kernel events (like network packet filtering).

## Examples and benchmark

There are two examples (`echo-server` and `http-server`) in the `examples` directory of Wasmer main repo, implementing features as their names suggest.

When compiled with the `singlepass` backend (unoptimized direct x86-64 code generation) and benchmarked using `tcpkali`/`wrk`, `echo-server` is ~10% faster (25210 Mbps / 22820 Mbps) than its native equivalent, and `http-server` is ~6% faster (53293 Rps / 50083 Rps). Even higher performance is expected when the other two Wasmer backends with optimizations (Cranelift/LLVM) are updated to support generating code for the kernel.

Those two examples use both WASI (for file abstraction and printing) and the asynchronous networking extension (via the `kwasm-net` crate). Take a look at them to learn how to do high-performance networking in kernel-wasm.

## Build and run

Check and ensure that:

- Your system is running Linux kernel 4.15 or higher.
- Your kernel has preemption enabled. Attempting to run WASM user code without kernel preemption will freeze your system.
- Kernel headers are installed and the building environment is properly set up.

Then just run `make` in the root directory, and (optionally) `networking` and `wasi`:

```
make
```

Install the modules into ``/lib/modules/`uname -r`/extra``

```
make install
```

Load the modules:

```
sudo modprobe kernel-wasm
sudo modprobe kwasm-networking
sudo modprobe kwasm-wasi
```

Run wasmer with the `kernel` loader and `singlepass` backend:

```
sudo wasmer run --backend singlepass --disable-cache --loader kernel your_wasm_file.wasm
```

## Security

Running user code in kernel mode is always a dangerous thing. Although we use many techniques to protect against different kinds of malicious code and attacks, it's advised that only trusted binaries should be run through this module, in a short term before we fully reviewed the codebase for security.

Currently known security risks and their solutions:

- [x] Stack overflow check (implemented with explicit bound checking in codegen)
- [x] Memory bound check (implemented with 6GB virtual address space)
- [x] Forceful termination (implemented by setting NX on code pages)
- [x] Floating point register save/restore (implemented with `kernel_fpu_{begin,end}` and `preempt_notifier`)

## License

GPLv2, as required for linking to the Linux kernel.
