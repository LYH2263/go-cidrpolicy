package cidrpolicy
import "encoding/json"
func (e *Engine) ExportJSON() ([]byte, error) {
        return json.Marshal(e.List())
}
func (e *Engine) Size() int { return e.Stats().Size }
