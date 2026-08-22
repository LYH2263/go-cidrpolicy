package cidrpolicy
import "github.com/LYH2263/go-cidrpolicy/internal/clock"
type Options struct {
        DataDir string
        AuditPath string
        Capacity int
        Clock clock.Clock
}
func (o Options) withDefaults() Options {
        if o.Clock == nil { o.Clock = clock.System{} }
        if o.Capacity <= 0 { o.Capacity = 128 }
        return o
}
