// Package node 把判定引擎、可控队列与 HTTP 接口组装为一个可独立运行的本地节点。
//
// 节点后台轮询队列 inbox：按交付序尝试应用事件，
//   - 成功：移入 ack（at-least-once 下重复消息会被引擎幂等拒绝并同样 ack）；
//   - 序号缺口（ErrGap）：保留在 inbox 等待前驱，不阻塞其他签发者的事件；
//   - 哈希链损坏：隔离对应签发者，故障不跨分区扩散。
package node

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"revauth/internal/engine"
	"revauth/internal/eventlog"
	"revauth/internal/model"
	"revauth/internal/queue"
)

// Node 单个本地节点。
type Node struct {
	eng  *engine.Engine
	q    *queue.Queue
	srv  *http.Server
	addr string

	pollInterval time.Duration
	stop         context.CancelFunc
	wg           sync.WaitGroup
}

// Config 节点配置。
type Config struct {
	DataDir      string // 事件日志与快照目录
	QueueDir     string // 可控队列目录（可为空，则仅用 HTTP 注入事件）
	AuditPath    string // 审计 JSONL 路径（可为空）
	PollInterval time.Duration
	FixedClock   int64 // 非零时使用固定时钟（测试确定性时间），否则用墙上时间
}

// New 构造节点（打开引擎与队列，不启动监听）。
func New(cfg Config) (*Node, error) {
	opts := []engine.Option{}
	if cfg.AuditPath != "" {
		w, err := engine.OpenAudit(cfg.AuditPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, engine.WithAudit(w))
	}
	if cfg.FixedClock != 0 {
		fixed := cfg.FixedClock
		opts = append(opts, engine.WithClock(func() int64 { return fixed }))
	}
	eng, err := engine.Open(cfg.DataDir, opts...)
	if err != nil {
		return nil, err
	}
	n := &Node{eng: eng, pollInterval: cfg.PollInterval}
	if n.pollInterval <= 0 {
		n.pollInterval = 20 * time.Millisecond
	}
	if cfg.QueueDir != "" {
		q, err := queue.Open(cfg.QueueDir)
		if err != nil {
			return nil, err
		}
		n.q = q
	}
	n.routes()
	return n, nil
}

// Engine 暴露引擎（测试与控制器直接发事件用）。
func (n *Node) Engine() *engine.Engine { return n.eng }

// Queue 暴露队列（控制器制造滞留/乱序/重复用）。
func (n *Node) Queue() *queue.Queue { return n.q }

func (n *Node) routes() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", n.handleHealth)
	mux.HandleFunc("/admit", n.handleAdmit)
	mux.HandleFunc("/events", n.handleEvents)
	mux.HandleFunc("/admin/compact", n.handleCompact)
	mux.HandleFunc("/admin/heartbeat", n.handleHeartbeat)
	mux.HandleFunc("/admin/state", n.handleState)
	n.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

// Start 绑定监听并启动队列轮询。addrFile 非空时把实际监听地址写入该文件。
func (n *Node) Start(addr, addrFile string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	n.addr = ln.Addr().String()
	if addrFile != "" {
		if err := writeAddrFile(addrFile, n.addr); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.stop = cancel
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.pollLoop(ctx)
	}()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		_ = n.srv.Serve(ln)
	}()
	return nil
}

// Addr 返回实际监听地址。
func (n *Node) Addr() string { return n.addr }

// Close 优雅停止。
func (n *Node) Close() error {
	if n.stop != nil {
		n.stop()
	}
	err := n.srv.Close()
	n.wg.Wait()
	return err
}

func writeAddrFile(path, addr string) error {
	return os.WriteFile(path, []byte(addr), 0o644)
}

// pollLoop 周期消费 inbox。
func (n *Node) pollLoop(ctx context.Context) {
	if n.q == nil {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(n.pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.drainOnce()
		}
	}
}

// drainOnce 执行一轮 inbox 消费，导出以便测试同步触发。
func (n *Node) drainOnce() {
	if n.q == nil {
		return
	}
	names, err := n.q.Poll()
	if err != nil {
		return
	}
	for _, name := range names {
		ev, err := n.q.Read("inbox", name)
		if err != nil {
			continue
		}
		err = n.eng.Ingest(ev)
		switch {
		case err == nil, errors.Is(err, engine.ErrAlreadyApplied):
			_ = n.q.Ack(name) // 新事件或重复投递都确认
		case errors.Is(err, engine.ErrGap):
			// 缺口：保留消息等待前驱，继续尝试后续（可能属于另一签发者）。
			continue
		default:
			// 链损坏等致命错误：引擎已隔离该签发者，移出 inbox 避免忙轮询。
			if errors.Is(err, eventlog.ErrChainBroken) {
				_ = n.q.Ack(name)
			}
		}
	}
}

// ---- HTTP 处理 ----

func (n *Node) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type admitReq struct {
	Certificate model.AdmissionCertificate `json:"certificate"`
	AccessKind  model.AccessKind           `json:"access_kind"`
}

func (n *Node) handleAdmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	var req admitReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d := n.eng.EvaluateAny(req.Certificate, req.AccessKind)
	writeJSON(w, http.StatusOK, d)
}

func (n *Node) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	var ev model.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// HTTP 控制面不维护哈希链，由节点补齐链字段并按水位幂等应用。
	if _, err := n.eng.IngestUnchained(ev.Kind, ev.Issuer, ev.Payload); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"status": "error", "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}

func (n *Node) handleCompact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	snap, err := n.eng.Compact()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshot_hash": snap.Hash(), "bans": len(snap.Bans)})
}

type heartbeatReq struct {
	Issuer model.OrgID `json:"issuer"`
}

func (n *Node) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	var req heartbeatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ev, err := n.eng.Emit(req.Issuer, model.EvHeartbeat, model.HeartbeatPayload{})
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]uint64{"seq": ev.Seq})
}

func (n *Node) handleState(w http.ResponseWriter, r *http.Request) {
	org := model.OrgID(r.URL.Query().Get("issuer"))
	state := map[string]any{
		"bans": n.eng.Bans(),
	}
	if org != "" {
		state["issuer"] = org
		state["watermark"] = n.eng.Watermark(org)
		state["quarantined"] = n.eng.IsQuarantined(org)
	}
	writeJSON(w, http.StatusOK, state)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
