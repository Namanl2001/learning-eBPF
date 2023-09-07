package main

import (
	"C"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)
import (
	"os"
	"os/signal"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	b, err := bpf.NewModuleFromFile("hello.bpf.o")
	if err != nil {
		panic(err)
	}
	defer b.Close()

	err = b.BPFLoadObject()
	if err != nil {
		panic(err)
	}

	prog, err := b.GetProgram("hello_bpftrace")
	if err != nil {
		panic(err)
	}

	// _, err = prog.AttachKprobe("__x64_sys_execve")
	_, err = prog.AttachRawTracepoint("sys_enter")
	if err != nil {
		panic(err)
	}

	e := make(chan []byte, 300)
	pb, err := b.InitPerfBuf("events", e, nil, 1024)
	if err != nil {
		panic(err)
	}
	pb.Start()

	mp := make(map[string]int)
	go func() {
		for data := range e {
			command := string(data)
			mp[command]++
		}
	}()

	<-sig
	defer pb.Stop()
	for cmd, cnt := range mp {
		fmt.Printf("%s: %d\n", cmd, cnt)
	}
}
