This dir contains the hello world program for eBPF.

`hello.bpf.c` contains the kernel side code written in C

`hello.go` contains the User side code written in Go using `libbpfgo` lib

Pre-requisites:

```
sudo apt-get install libbpf-dev make clang llvm libelf-dev
```

Building and running hello

```
make all
sudo ./hello
```

Reference taken from: https://github.com/lizrice/libbpfgo-beginners