package cidrpolicy

import (
        "context"
        "fmt"
        "sync"

        "github.com/LYH2263/go-cidrpolicy/internal/audit"
        "github.com/LYH2263/go-cidrpolicy/internal/clone"
        "github.com/LYH2263/go-cidrpolicy/internal/metrics"
        "github.com/LYH2263/go-cidrpolicy/internal/persist"
        "github.com/LYH2263/go-cidrpolicy/internal/validate"
)

type Engine struct {
        mu sync.Mutex
        closed bool
        opts Options
        items map[string]*Record
        order []string
        audit *audit.Logger
        metrics metrics.Counters
}

func New(opts Options) (*Engine, error) {
        opts = opts.withDefaults()
        e := &Engine{opts: opts, items: make(map[string]*Record)}
        if opts.AuditPath != "" {
                al, err := audit.Open(opts.AuditPath)
                if err != nil { return nil, err }
                e.audit = al
        }
        return e, nil
}

func (e *Engine) Put(ctx context.Context, id string, payload []byte, meta map[string]string) error {
        if err := ctx.Err(); err != nil { return err }
        if err := validate.NonEmpty("id", id); err != nil {
                return fmt.Errorf("%w: %v", ErrInvalid, err)
        }
        e.mu.Lock(); defer e.mu.Unlock()
        if e.closed { return ErrClosed }
        if _, ok := e.items[id]; !ok { e.order = append(e.order, id) }
        e.items[id] = &Record{ID: id, Payload: clone.Bytes(payload), Meta: clone.StringMap(meta), At: e.opts.Clock.Now()}
        e.metrics.OK()
        if e.audit != nil { _ = e.audit.Log("put", id) }
        return nil
}

func (e *Engine) Get(id string) (*Record, error) {
        e.mu.Lock(); defer e.mu.Unlock()
        if e.closed { return nil, ErrClosed }
        r, ok := e.items[id]
        if !ok { return nil, ErrNotFound }
        return &Record{ID: r.ID, Payload: clone.Bytes(r.Payload), Meta: clone.StringMap(r.Meta), At: r.At}, nil
}

func (e *Engine) List() []*Record {
        e.mu.Lock(); defer e.mu.Unlock()
        out := make([]*Record, 0, len(e.order))
        for _, id := range e.order {
                r := e.items[id]
                out = append(out, &Record{ID: r.ID, Payload: clone.Bytes(r.Payload), Meta: clone.StringMap(r.Meta), At: r.At})
        }
        return out
}

func (e *Engine) Delete(id string) error {
        e.mu.Lock(); defer e.mu.Unlock()
        if e.closed { return ErrClosed }
        if _, ok := e.items[id]; !ok { return ErrNotFound }
        delete(e.items, id)
        for i, x := range e.order {
                if x == id { e.order = append(e.order[:i], e.order[i+1:]...); break }
        }
        return nil
}

func (e *Engine) Snapshot(path string) error {
        e.mu.Lock(); defer e.mu.Unlock()
        type row struct {
                ID string `json:"id"`
                Payload []byte `json:"payload"`
                Meta map[string]string `json:"meta"`
        }
        rows := make([]row, 0, len(e.order))
        for _, id := range e.order {
                r := e.items[id]
                rows = append(rows, row{ID: r.ID, Payload: clone.Bytes(r.Payload), Meta: clone.StringMap(r.Meta)})
        }
        return persist.SaveJSON(path, rows)
}

func (e *Engine) Stats() Stats {
        ok, fail, drop := e.metrics.Snapshot()
        e.mu.Lock(); defer e.mu.Unlock()
        return Stats{OK: ok, Fail: fail, Drop: drop, Size: len(e.items)}
}

func (e *Engine) Close() error {
        e.mu.Lock(); defer e.mu.Unlock()
        if e.closed { return nil }
        e.closed = true
        if e.audit != nil { return e.audit.Close() }
        return nil
}
