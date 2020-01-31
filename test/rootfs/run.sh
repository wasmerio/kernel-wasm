#!/bin/sh

/bin/busybox insmod /modules/kernel-wasm.ko || exit 1
/bin/busybox insmod /modules/kwasm-wasi.ko || exit 1
/bin/busybox mkdir /sys /dev /proc
/bin/busybox mount -t devtmpfs devtmpfs /dev || exit 1
/bin/busybox mount -t proc proc /proc || exit 1
/bin/busybox mount -t sysfs sysfs /sys || exit 1
/bin/wasmer run --backend singlepass --loader kernel /data/hello_world.wasm
