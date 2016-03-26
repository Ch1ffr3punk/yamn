package main

import (
	"fmt"
	"testing"
	"time"
)

func TestHttp(t *testing.T) {
	// Start server
	fmt.Println("Starting HTTP Server")
	go server()
	time.Sleep(5)
	client("test.txt")
}
