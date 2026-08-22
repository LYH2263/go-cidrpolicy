package cidrpolicy
import "fmt"
func (e *Engine) Reset() error {
        e.mu.Lock(); defer e.mu.Unlock()
        if e.closed { return ErrClosed }
        e.items = make(map[string]*Record)
        e.order = nil
        return nil
}
func (e *Engine) MustGet(id string) *Record {
        r, err := e.Get(id)
        if err != nil { panic(fmt.Sprintf("%s: %v", id, err)) }
        return r
}
