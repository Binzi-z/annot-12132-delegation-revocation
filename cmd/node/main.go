// Command node 是授权回收协议的本地节点进程。
//
// 两个节点分别启动，各自拥有独立的数据目录与可控队列，通过 HTTP 接收
// 准入查询与事件，通过文件队列接收复制事件。父测试进程以 -child 模式
// 拉起本进程，地址写入 -addr-file，stdin 关闭即退出。
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"revauth/internal/node"
)

func main() {
	var (
		dataDir    = flag.String("data", "", "event log and snapshot directory")
		queueDir   = flag.String("queue", "", "controllable replication queue directory")
		audit      = flag.String("audit", "", "audit JSONL path")
		listen     = flag.String("listen", "127.0.0.1:0", "listen address")
		addrFile   = flag.String("addr-file", "", "write resolved listen address here")
		child      = flag.Bool("child", false, "child process mode (exit on stdin close)")
		fixedClock = flag.Int64("fixed-clock", 0, "use a fixed unix timestamp as node clock (test determinism)")
	)
	flag.Parse()

	if *dataDir == "" {
		log.Fatal("-data is required")
	}
	n, err := node.New(node.Config{
		DataDir:      *dataDir,
		QueueDir:     *queueDir,
		AuditPath:    *audit,
		PollInterval: 15 * time.Millisecond,
		FixedClock:   *fixedClock,
	})
	if err != nil {
		log.Fatalf("node init: %v", err)
	}
	if err := n.Start(*listen, *addrFile); err != nil {
		log.Fatalf("node start: %v", err)
	}
	log.Printf("revauth node listening on %s (data=%s)", n.Addr(), *dataDir)

	if *child {
		awaitStdinClose()
	} else {
		awaitSignal()
	}
	if err := n.Close(); err != nil {
		log.Printf("node close: %v", err)
	}
}

// awaitStdinClose 子进程模式：stdin 被父进程关闭时退出。
func awaitStdinClose() {
	buf := make([]byte, 1)
	for {
		if _, err := os.Stdin.Read(buf); err != nil {
			return
		}
	}
}

func awaitSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
