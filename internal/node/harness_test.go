// Package node_test 用两个真实本地进程 + 可控文件队列重放协议的最小反例，
// 并验证正常独立路径持续可用、撤销路径无法借旧数据恢复。
package node_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"revauth/internal/model"
	"revauth/internal/testkit"
)

// procNode 一个被父进程拉起的真实节点子进程及其访问端点。
type procNode struct {
	name     string
	baseURL  string
	dataDir  string
	queueDir string
	addrFile string
	cmd      *exec.Cmd
	stdin    io.WriteCloser
}

var (
	buildOnce sync.Once
	binaryPath string
	buildErr   error
)

// buildBinary 只编译一次节点二进制供两个子进程共用。
func buildBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		// 放在测试工作目录下的稳定位置，避免不同 t.TempDir() 之间路径失效。
		dir := filepath.Join(os.TempDir(), "revauth-test-bin")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			buildErr = err
			return
		}
		bin := filepath.Join(dir, "node.exe")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/node")
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build failed: %v\n%s", err, out)
			return
		}
		binaryPath = bin
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binaryPath
}

func startNode(t *testing.T, name, root string) *procNode {
	t.Helper()
	bin := buildBinary(t)
	pn := &procNode{
		name:     name,
		dataDir:  filepath.Join(root, name, "data"),
		queueDir: filepath.Join(root, name, "queue"),
		addrFile: filepath.Join(root, name, "addr.txt"),
	}
	for _, d := range []string{pn.dataDir, pn.queueDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(bin,
		"-child",
		"-data", pn.dataDir,
		"-queue", pn.queueDir,
		"-audit", filepath.Join(root, name, "audit.jsonl"),
		"-listen", "127.0.0.1:0",
		"-addr-file", pn.addrFile,
		// 固定时钟，使测试证书的 1970 年有效期窗口与节点判定时间一致。
		"-fixed-clock", "1000000",
	)
	var err error
	pn.stdin, err = cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node %s: %v", name, err)
	}
	pn.cmd = cmd

	// 等待地址文件与健康检查就绪。
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(pn.addrFile)
		if err == nil && len(bytes.TrimSpace(b)) > 0 {
			pn.baseURL = "http://" + string(bytes.TrimSpace(b))
			if code, err := httpGet(pn.baseURL + "/healthz"); err == nil && code == 200 {
				return pn
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("node %s did not become ready", name)
	return nil
}

func (p *procNode) stop(t *testing.T) {
	t.Helper()
	if p.stdin != nil {
		_ = p.stdin.Close()
	}
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
	}
}

// ---- HTTP 客户端辅助 ----

func httpGet(url string) (int, []byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

func postJSON(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

type admitResp struct {
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"`
	Degraded bool   `json:"degraded"`
}

func (p *procNode) admit(t *testing.T, cert model.AdmissionCertificate, kind model.AccessKind) admitResp {
	t.Helper()
	code, raw := postJSON(t, p.baseURL+"/admit", map[string]any{
		"certificate": cert, "access_kind": kind,
	})
	if code != 200 {
		t.Fatalf("%s admit status %d: %s", p.name, code, raw)
	}
	var d admitResp
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func (p *procNode) postEvent(t *testing.T, kind model.EventKind, issuer model.OrgID, payload any) {
	t.Helper()
	code, raw := postJSON(t, p.baseURL+"/events", map[string]any{
		"kind": kind, "issuer": issuer, "payload": payload,
	})
	if code != 200 {
		t.Fatalf("%s event status %d: %s", p.name, code, raw)
	}
}

func (p *procNode) compact(t *testing.T) {
	t.Helper()
	code, raw := postJSON(t, p.baseURL+"/admin/compact", map[string]any{})
	if code != 200 {
		t.Fatalf("compact status %d: %s", code, raw)
	}
}

func (p *procNode) heartbeat(t *testing.T, iss model.OrgID) {
	t.Helper()
	code, raw := postJSON(t, p.baseURL+"/admin/heartbeat", map[string]any{"issuer": iss})
	if code != 200 {
		t.Fatalf("heartbeat status %d: %s", code, raw)
	}
}

// waitFor 轮询直到断言成立或超时。
func waitFor(t *testing.T, timeout time.Duration, fn func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatal("timeout waiting for: " + msg)
}

// bootstrapEvents 构造两个签发者创始换主与心跳事件（序号从 1 起，按签发者分链）。
func bootstrapEvents(t *testing.T, a, b *testkit.Issuer, now int64) map[model.OrgID][]model.Event {
	t.Helper()
	evs := map[model.OrgID][]model.Event{}
	seq := map[model.OrgID]uint64{}
	mk := func(org model.OrgID, kind model.EventKind, payload any) model.Event {
		seq[org]++
		ev := model.Event{Seq: seq[org], Issuer: org, Kind: kind, EmittedAt: now, Payload: payload}
		ev.Hash = ev.Digest()
		return ev
	}
	evs[testkit.OrgA] = []model.Event{
		mk(testkit.OrgA, model.EvKeyRotated, model.KeyRotatedPayload{NewGeneration: a.Gen, PublicKey: a.Pub}),
		mk(testkit.OrgA, model.EvHeartbeat, model.HeartbeatPayload{}),
	}
	evs[testkit.OrgB] = []model.Event{
		mk(testkit.OrgB, model.EvKeyRotated, model.KeyRotatedPayload{NewGeneration: b.Gen, PublicKey: b.Pub}),
		mk(testkit.OrgB, model.EvHeartbeat, model.HeartbeatPayload{}),
	}
	return evs
}
