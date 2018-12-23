#!/usr/bin

make
musl-gcc -o rootfs/exp -static exp.c
cd rootfs
find . | cpio -H newc -o > ../rootfs.cpio