package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func doExecveAt(progName string, argv []string, envv []string) error {

	argv0p, err := syscall.BytePtrFromString(progName)
	if err != nil {
		return err
	}

	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}

	envvp, err := syscall.SlicePtrFromStrings(envv)
	if err != nil {
		return err
	}

	_, _, err = syscall.Syscall6(unix.SYS_EXECVEAT,
		uintptr(^uintptr(0)), /* dirfd */
		uintptr(unsafe.Pointer(argv0p)),
		uintptr(unsafe.Pointer(&argvp[0])),
		uintptr(unsafe.Pointer(&envvp[0])),
		0,
		0,
	)

	return err
}

func main() {

	useExecveAt := flag.Bool("use-execveat", false, "use execveat(2) instead of execve(2)")
	flag.Parse()
	fmt.Printf("execveat=%t\n", *useExecveAt)

	progName := os.Args[0]
	var err error
	var count int

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s <nexecs>\n", progName)
		flag.PrintDefaults()
		return
	}
	count, err = strconv.Atoi(args[0])
	if err != nil || count < 0 {
		fmt.Fprintf(os.Stderr, "invalid argument: %s (expecting non-negative integer)\n", os.Args[1])
		os.Exit(1)
	}
	count--
	if count == 0 {
		os.Exit(0)
	}

	envp := []string{"GOMAXPROCS=1"}
	if *useExecveAt {
		argv := []string{progName, "-use-execveat", strconv.Itoa(count)}
		err = doExecveAt(progName, argv, envp)
	} else {
		argv := []string{progName, strconv.Itoa(count)}
		err = syscall.Exec(progName, argv, envp)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "exec failed: %s\n", err)
		os.Exit(1)
	}
}
