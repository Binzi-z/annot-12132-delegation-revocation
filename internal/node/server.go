package node

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"ccrevoke/internal/event"
	"ccrevoke/internal/model"
)

// ServeHTTP exposes the node protocol over HTTP. It is deliberately small: the
// harness (not the node) controls delivery, so replication is pull-based.
func (n *Node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "org": n.cfg.Org})
	case r.Method == http.MethodGet && r.URL.Path == "/state":
		writeJSON(w, http.StatusOK, n.summary())
	case r.Method == http.MethodGet && r.URL.Path == "/events":
		origin := r.URL.Query().Get("origin")
		var after uint64
		if s := r.URL.Query().Get("after"); s != "" {
			fmt.Sscanf(s, "%d", &after)
		}
		writeJSON(w, http.StatusOK, n.EventsSince(origin, after))
	case r.Method == http.MethodGet && r.URL.Path == "/evidence":
		writeJSON(w, http.StatusOK, n.Evidence())
	case r.Method == http.MethodGet && r.URL.Path == "/watermarks":
		writeJSON(w, http.StatusOK, n.Watermarks())
	case r.Method == http.MethodPost && r.URL.Path == "/author":
		n.handleAuthor(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/ingest":
		n.handleIngest(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/evidence/merge":
		n.handleEvidenceMerge(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/evaluate":
		n.handleEvaluate(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/checkpoint":
		if err := n.Checkpoint(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case r.Method == http.MethodPost && r.URL.Path == "/clock":
		var body struct {
			Delta int64 `json:"delta"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		now, err := n.AdvanceClock(body.Delta)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"now": now})
	case r.Method == http.MethodPost && r.URL.Path == "/shutdown":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		go n.Close()
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no route " + r.Method + " " + r.URL.Path})
	}
}

func (n *Node) handleAuthor(w http.ResponseWriter, r *http.Request) {
	var in AuthorInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	ev, err := n.Author(in)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (n *Node) handleIngest(w http.ResponseWriter, r *http.Request) {
	var ev event.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := n.Ingest(ev); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "origin": ev.Node, "seq": ev.Seq})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (n *Node) handleEvidenceMerge(w http.ResponseWriter, r *http.Request) {
	var recs []event.EvidenceRecord
	if err := json.NewDecoder(r.Body).Decode(&recs); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := n.MergePeerEvidence(recs); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "evidence": len(recs)})
}

func (n *Node) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req model.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	d, cert := n.Evaluate(req)
	writeJSON(w, http.StatusOK, map[string]any{
		"decision":    d,
		"explanation": d.Explain(),
		"certificate": cert,
	})
}

// Summary is the node diagnostic view.
type Summary struct {
	Org        string                    `json:"org"`
	Clock      int64                     `json:"clock"`
	HeadPos    uint64                    `json:"head_pos"`
	HeadHash   string                    `json:"head_hash"`
	Events     int                       `json:"events"`
	Evidence   int                       `json:"evidence"`
	Bans       int                       `json:"bans"`
	Revoked    int                       `json:"revoked"`
	Watermarks map[string]event.Watermark `json:"watermarks"`
	CurrentGen map[string]int            `json:"current_gen"`
	Quarantine map[string]string         `json:"quarantine"`
	PeerErrors map[string]string         `json:"peer_errors,omitempty"`
	Origins    map[string]uint64         `json:"origins"`
	EvidenceIDs []string                 `json:"evidence_ids"`
}

func (n *Node) summary() Summary {
	n.mu.Lock()
	defer n.mu.Unlock()
	pos, hash := n.st.Head()
	ev := n.st.Evidence()
	s := Summary{
		Org: n.cfg.Org, Clock: n.clock, HeadPos: pos, HeadHash: hash,
		Events: len(n.st.Events()), Evidence: len(ev),
		Bans: len(n.state.Bans), Revoked: len(n.state.Revoked),
		Watermarks: map[string]event.Watermark{}, CurrentGen: map[string]int{},
		Quarantine: map[string]string{}, PeerErrors: n.PeerErrors(),
		Origins: map[string]uint64{},
	}
	for org, w := range n.state.Watermarks {
		s.Watermarks[org] = w
	}
	for org, is := range n.state.Issuers {
		s.CurrentGen[org] = is.CurrentGen
		if is.Quarantined {
			s.Quarantine[org] = is.QuarantineBy
		}
	}
	for org, m := range n.st.OriginMarks() {
		s.Origins[org] = m.Seq
	}
	for _, r := range ev {
		s.EvidenceIDs = append(s.EvidenceIDs, r.EvidenceID)
	}
	sort.Strings(s.EvidenceIDs)
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}