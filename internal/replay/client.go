// Package replay drives two real cc-node processes over loopback through a
// controllable queue. Delivery is explicit: the test decides what reaches which
// node, in what order, with drops/duplicates/holds, so a partition is simply
// "stop delivering".
package replay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"ccrevoke/internal/event"
	"ccrevoke/internal/model"
	"ccrevoke/internal/node"
	"ccrevoke/internal/proto"
)

// Client talks to one cc-node process.
type Client struct {
	Org  string
	Addr string
	HTTP *http.Client
}

// NewClient returns a client for a node address.
func NewClient(org, addr string) *Client {
	return &Client{Org: org, Addr: addr, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) url(path string) string { return "http://" + c.Addr + path }

func (c *Client) get(path string, out any) error {
	resp, err := c.HTTP.Get(c.url(path))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, body)
	}
	return json.Unmarshal(body, out)
}

func (c *Client) post(path string, in, out any) error {
	raw, _ := json.Marshal(in)
	resp, err := c.HTTP.Post(c.url(path), "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, body)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// Health checks the node is up.
func (c *Client) Health() error {
	var out map[string]any
	return c.get("/health", &out)
}

// Events returns the node's retained events from an origin after a sequence.
func (c *Client) Events(origin string, after uint64) ([]event.Event, error) {
	var out []event.Event
	err := c.get(fmt.Sprintf("/events?origin=%s&after=%d", origin, after), &out)
	return out, err
}

// Evidence returns the node's durable evidence.
func (c *Client) Evidence() ([]event.EvidenceRecord, error) {
	var out []event.EvidenceRecord
	err := c.get("/evidence", &out)
	return out, err
}

// Ingest delivers one event to the node.
func (c *Client) Ingest(ev event.Event) error {
	return c.post("/ingest", ev, nil)
}

// MergeEvidence delivers evidence to the node.
func (c *Client) MergeEvidence(recs []event.EvidenceRecord) error {
	return c.post("/evidence/merge", recs, nil)
}

// Author asks the node to author an event locally.
func (c *Client) Author(in node.AuthorInput) (event.Event, error) {
	var ev event.Event
	err := c.post("/author", in, &ev)
	return ev, err
}

// Evaluate runs an admission query.
func (c *Client) Evaluate(req model.Request) (model.Decision, *proto.Certificate, error) {
	var out struct {
		Decision    model.Decision     `json:"decision"`
		Explan      string             `json:"explanation"`
		Certificate *proto.Certificate `json:"certificate"`
	}
	if err := c.post("/evaluate", req, &out); err != nil {
		return model.Decision{}, nil, err
	}
	return out.Decision, out.Certificate, nil
}

// Checkpoint asks the node to compact.
func (c *Client) Checkpoint() error { return c.post("/checkpoint", struct{}{}, nil) }

// Clock advances the node's logical clock.
func (c *Client) Clock(delta int64) (int64, error) {
	var out struct {
		Now int64 `json:"now"`
	}
	err := c.post("/clock", map[string]int64{"delta": delta}, &out)
	return out.Now, err
}

// Summary fetches the node diagnostic summary.
func (c *Client) Summary() (map[string]any, error) {
	var out map[string]any
	err := c.get("/state", &out)
	return out, err
}