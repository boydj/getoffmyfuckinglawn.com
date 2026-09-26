//go:build !unix

package main

func raiseNoFile() error { return nil }
