## Build Environment
Download linux source code and compile.
Then change the KERNELDIR for your kernel installing path in Makefile.
Last download busybox and make a root-fs.

## Some problem(s)
I think the driver can read any file(I was wrong~), but actually, you can't read root's file via the interface of the driver as a normal user.
So I have to check the exploit by myself if anyone solve it~
