package main

import (
	"C"

	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
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

	prog, err := b.GetProgram("hello")
	if err != nil {
		panic(err)
	}

	_, err = prog.AttachKprobe("__x64_sys_execve")
	if err != nil {
		panic(err)
	}

	go helpers.TracePipeListen()

	<-sig
	fmt.Println("cleaning up")
}
