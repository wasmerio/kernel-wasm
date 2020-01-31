#!/bin/sh

cd $(dirname $0)/.. || exit 1
KERNEL_PATH=$(readlink -f /vmlinuz)

make || exit 1
cp ./*.ko ./test/rootfs/modules || exit 1

cp "$KERNEL_PATH" ./test/boot/vmlinuz || exit 1
cd ./test/rootfs
find . | cpio -H newc -o > ../boot/initrd.img
