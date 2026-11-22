package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// AuditWriter 将每次访问决策追加为不可变 JSONL 审计记录。
// 每条记录自带原因码、逐边证据、水位与签发者活性，构成可核查依据。
type AuditWriter struct {
	mu sync.Mutex
	f  *os.File
}

// OpenAudit 打开（或创建）审计文件。
func OpenAudit(path string) (*AuditWriter, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &AuditWriter{f: f}, nil
}

// Append 追加一条决策记录并 fsync。
func (w *AuditWriter) Append(d Decision) {
	b, err := json.Marshal(d)
	if err != nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = w.f.Write(append(b, '\n'))
	_ = w.f.Sync()
}

// Close 关闭审计文件。
func (w *AuditWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
