// Command cc-node runs one protocol node. It is used both interactively and by
// the two-process replay harness.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ccrevoke/internal/scenario"
	"ccrevoke/internal/node"
)

func main() {
	var (
		role   = flag.String("role", "", "organization/role name, e.g. orgA")
		dir    = flag.String("dir", "", "durable store directory")
		listen = flag.String("listen", "127.0.0.1:0", "HTTP listen address")
		seed   = flag.String("seed", scenario.Seed, "shared key seed")
		peers  = flag.String("peers", "", "comma-separated peer orgs")
		ready  = flag.String("ready-file", "", "write the bound address here once serving")
		step   = flag.Int64("tick-step", 1, "logical clock increment per authored event")
		auto   = flag.String("bootstrap", "", "scenario name to seed on first start (optional)")
		verbose = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()
	if *role == "" || *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: cc-node -role orgA -dir ./runtime/A [-listen 127.0.0.1:18081]")
		os.Exit(2)
	}

	var peerList []string
	for _, p := range strings.Split(*peers, ",") {
		if p = strings.TrimSpace(p); p != "" {
			peerList = append(peerList, p)
		}
	}

	n, err := node.Open(node.Config{Org: *role, Dir: *dir, Peers: peerList, Seed: *seed, TickStep: *step})
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	if *auto != "" {
		if err := node.SeedScenario(n, *auto); err != nil {
			log.Fatalf("bootstrap %q: %v", *auto, err)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", n)
	srv := &http.Server{Handler: mux}

	ln, err := listenTCP(*listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if *ready != "" {
		os.WriteFile(*ready, []byte(addr), 0o644)
	}
	if *verbose {
		log.Printf("%s listening on %s (dir %s)", *role, addr, *dir)
	}
	// Always print the bound address as a JSON line so a parent harness can
	// read it from stdout.
	msg, _ := json.Marshal(map[string]string{"org": *role, "addr": addr})
	fmt.Println(string(msg))

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	ctx, cancel := timeoutCtx(2 * time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = n.Close()
}
