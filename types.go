package cidrpolicy
import "time"
type Record struct {
        ID string
        Payload []byte
        Meta map[string]string
        At time.Time
}
type Stats struct { OK, Fail, Drop int64; Size int }
