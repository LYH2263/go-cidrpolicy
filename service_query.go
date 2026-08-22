package cidrpolicy
import "strings"
func (e *Engine) Has(id string) bool {
        _, err := e.Get(id)
        return err == nil
}
func (e *Engine) FindPrefix(prefix string) []*Record {
        out := []*Record{}
        for _, r := range e.List() {
                if strings.HasPrefix(r.ID, prefix) { out = append(out, r) }
        }
        return out
}
