package metrics
import "sync/atomic"
type Counters struct { ok, fail, drop atomic.Int64 }
func (c *Counters) OK() { c.ok.Add(1) }
func (c *Counters) Fail() { c.fail.Add(1) }
func (c *Counters) Drop() { c.drop.Add(1) }
func (c *Counters) Snapshot() (int64, int64, int64) {
        return c.ok.Load(), c.fail.Load(), c.drop.Load()
}
