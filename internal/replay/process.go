package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Process manages one real cc-node subprocess.
type Process struct {
	Org   string
	Dir   string
	Addr  string

	cmd  *exec.Cmd
	mu   sync.Mutex
	logf *os.File
}

// NodeBinary locates or builds the cc-node binary. It rebuilds when any Go
// source under the module is newer than the cached binary. The binary is cached
// under the OS temp directory (not the repo) so tests leave no artifacts.
func NodeBinary() (string, error) {
	exe := "cc-node"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	root, err := moduleRoot()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(os.TempDir(), "ccrevoke-bin")
	bin := filepath.Join(cacheDir, exe)
	binInfo, statErr := os.Stat(bin)
	if statErr == nil {
		newer, err := sourcesNewerThan(root, binInfo.ModTime())
		if err == nil && !newer {
			return bin, nil
		}
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/cc-node")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build cc-node: %v\n%s", err, out)
	}
	return bin, nil
}

// sourcesNewerThan reports whether any .go file under root is newer than t.
func sourcesNewerThan(root string, t time.Time) (bool, error) {
	newer := false
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "bin" || base == "runtime" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && info.ModTime().After(t) {
			newer = true
			return filepath.SkipAll
		}
		return nil
	})
	return newer, err
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above working directory")
		}
		dir = parent
	}
}

// Start launches a node process and waits for it to report its bound address.
func Start(org, dir, seed string, tickStep int64, bootstrap string, env []string) (*Process, error) {
	bin, err := NodeBinary()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	logf, err := os.Create(filepath.Join(dir, "node.stderr.log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin,
		"-role", org,
		"-dir", dir,
		"-listen", "127.0.0.1:0",
		"-seed", seed,
		"-tick-step", fmt.Sprintf("%d", tickStep),
		"-bootstrap", bootstrap,
		"-v",
	)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = logf
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logf.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	p := &Process{Org: org, Dir: dir, cmd: cmd, logf: logf}

	// Read the address line from stdout (or fall back to a ready file).
	addrCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var msg struct {
				Addr string `json:"addr"`
			}
			if err := json.Unmarshal([]byte(line), &msg); err == nil && msg.Addr != "" {
				addrCh <- msg.Addr
				return
			}
		}
		addrCh <- ""
	}()

	select {
	case addr := <-addrCh:
		if addr == "" {
			p.Stop()
			return nil, fmt.Errorf("node %s exited before reporting an address (see %s/node.stderr.log)", org, dir)
		}
		p.Addr = addr
	case <-time.After(15 * time.Second):
		p.Stop()
		return nil, fmt.Errorf("node %s did not report an address within 15s", org)
	}

	// Confirm health.
	client := NewClient(org, p.Addr)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := client.Health(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			p.Stop()
			return nil, fmt.Errorf("node %s never became healthy", org)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return p, nil
}

// Stop terminates the process.
func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	_ = p.cmd.Process.Kill()
	err := p.cmd.Wait()
	if p.logf != nil {
		p.logf.Close()
		p.logf = nil
	}
	p.cmd = nil
	return err
}

// Restart stops and starts the process against the same durable directory.
// A new ephemeral port is used.
func (p *Process) Restart(seed string, tickStep int64) error {
	_ = p.Stop()
	np, err := Start(p.Org, p.Dir, seed, tickStep, "", nil)
	if err != nil {
		return err
	}
	p.Addr = np.Addr
	p.cmd = np.cmd
	p.logf = np.logf
	return nil
}

// Client returns a client bound to this process.
func (p *Process) Client() *Client { return NewClient(p.Org, p.Addr) }