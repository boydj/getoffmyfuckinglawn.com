//go:build unix

package main

import "syscall"

// raiseNoFile lifts the soft RLIMIT_NOFILE to the hard limit so thousands
// of sockets can be open at once.
func raiseNoFile() error {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return err
	}
	if r.Cur >= r.Max {
		return nil
	}
	r.Cur = r.Max
	return syscall.Setrlimit(syscall.RLIMIT_NOFILE, &r)
}
