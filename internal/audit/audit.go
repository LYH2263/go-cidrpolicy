package audit
import ("fmt"; "os"; "path/filepath"; "sync"; "time")
type Logger struct { mu sync.Mutex; path string; f *os.File }
func Open(path string) (*Logger, error) {
        if d := filepath.Dir(path); d != "." {
                if err := os.MkdirAll(d, 0o755); err != nil { return nil, err }
        }
        f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
        if err != nil { return nil, err }
        return &Logger{path: path, f: f}, nil
}
func (l *Logger) Log(kind, detail string) error {
        if l == nil || l.f == nil { return fmt.Errorf("audit closed") }
        l.mu.Lock(); defer l.mu.Unlock()
        _, err := fmt.Fprintf(l.f, "%s\t%s\t%s\n", time.Now().UTC().Format(time.RFC3339Nano), kind, detail)
        return err
}
func (l *Logger) Close() error {
        if l == nil { return nil }
        l.mu.Lock(); defer l.mu.Unlock()
        if l.f == nil { return nil }
        err := l.f.Close(); l.f = nil; return err
}
