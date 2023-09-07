// +build ignore
#include "hello.bpf.h"

// Example: tracing a message on a kprobe
__attribute__((section("kprobe/sys_execve")))
int hello(void *ctx)
{
    bpf_printk("I'm Naman!");
    return 0;
}