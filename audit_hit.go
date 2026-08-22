package cidrpolicy

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type HitLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	buf  []string
}

func OpenHitLog(path string) (*HitLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &HitLog{path: path, f: f}, nil
}

func (h *HitLog) Record(ip, rule string, act Action) error {
	if h == nil || h.f == nil {
		return fmt.Errorf("hitlog closed")
	}
	line := fmt.Sprintf("%s\t%s\t%s\t%d\n", time.Now().UTC().Format(time.RFC3339Nano), ip, rule, act)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf = append(h.buf, line)
	_, err := h.f.WriteString(line)
	return err
}

func (h *HitLog) Flush() error {
	if h == nil || h.f == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.f.Sync()
}

func (h *HitLog) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.f == nil {
		return nil
	}
	err := h.f.Close()
	h.f = nil
	return err
}

func (h *HitLog) Buffer() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.buf))
	copy(out, h.buf)
	return out
}

func (h *HitLog) Rotate(newPath string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Open the new handle first so a failure leaves the current handle
	// (and thus logging) intact.
	f, err := os.OpenFile(newPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	// Close the previous handle so the rotated file is no longer held by
	// this process. On Windows an open write handle lacks FILE_SHARE_DELETE,
	// so leaving it open makes Remove-Item fail with SharingViolation and the
	// rotated directory can never be cleaned up.
	old := h.f
	h.f = f
	h.path = newPath
	if old != nil {
		_ = old.Close()
	}
	return nil
}
