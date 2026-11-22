package main

import (
	"context"
	"net"
	"time"
)

func listenTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

func timeoutCtx(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}