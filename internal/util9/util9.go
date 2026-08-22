package util9

import (
        "bytes"
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "hash/fnv"
        "io"
        "math"
        "net"
        "sort"
        "strconv"
        "strings"
        "sync"
        "time"
        "unicode"
        "unicode/utf8"
)

const TagName = "util9"

func Tag() string { return TagName }

func Join(a, b string) string { return a + ":" + b }

func Norm(s string) string {
        return strings.TrimSpace(strings.ToLower(s))
}

type Counter struct {
        mu sync.Mutex
        n  int
}

func (c *Counter) Inc() {
        c.mu.Lock()
        c.n++
        c.mu.Unlock()
}

func (c *Counter) Add(v int) {
        c.mu.Lock()
        c.n += v
        c.mu.Unlock()
}

func (c *Counter) Get() int {
        c.mu.Lock()
        defer c.mu.Unlock()
        return c.n
}

func (c *Counter) Reset() {
        c.mu.Lock()
        c.n = 0
        c.mu.Unlock()
}

func Fmt(v any) string { return fmt.Sprintf("%v", v) }

func Clamp(v, lo, hi int) int {
        if v < lo {
                return lo
        }
        if v > hi {
                return hi
        }
        return v
}

func Clamp64(v, lo, hi int64) int64 {
        if v < lo {
                return lo
        }
        if v > hi {
                return hi
        }
        return v
}

func Max(a, b int) int {
        if a > b {
                return a
        }
        return b
}

func Min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

func Abs(v int) int {
        if v < 0 {
                return -v
        }
        return v
}

func HashString(s string) string {
        sum := sha256.Sum256([]byte(s))
        return hex.EncodeToString(sum[:])
}

func HashBytes(b []byte) string {
        sum := sha256.Sum256(b)
        return hex.EncodeToString(sum[:])
}

func FNV32(s string) uint32 {
        h := fnv.New32a()
        _, _ = h.Write([]byte(s))
        return h.Sum32()
}

func SplitCSV(s string) []string {
        parts := strings.Split(s, ",")
        out := make([]string, 0, len(parts))
        for _, p := range parts {
                p = strings.TrimSpace(p)
                if p != "" {
                        out = append(out, p)
                }
        }
        return out
}

func JoinCSV(ss []string) string {
        return strings.Join(ss, ",")
}

func UniqueSorted(in []string) []string {
        if len(in) == 0 {
                return nil
        }
        m := make(map[string]struct{}, len(in))
        for _, s := range in {
                m[s] = struct{}{}
        }
        out := make([]string, 0, len(m))
        for s := range m {
                out = append(out, s)
        }
        sort.Strings(out)
        return out
}

func ContainsFold(hay, needle string) bool {
        return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

func Truncate(s string, n int) string {
        if n <= 0 {
                return ""
        }
        if utf8.RuneCountInString(s) <= n {
                return s
        }
        r := []rune(s)
        return string(r[:n])
}

func IsASCII(s string) bool {
        for i := 0; i < len(s); i++ {
                if s[i] > unicode.MaxASCII {
                        return false
                }
        }
        return true
}

func ParseIntDefault(s string, def int) int {
        v, err := strconv.Atoi(strings.TrimSpace(s))
        if err != nil {
                return def
        }
        return v
}

func ParseBoolLoose(s string) bool {
        switch strings.ToLower(strings.TrimSpace(s)) {
        case "1", "true", "yes", "on", "y":
                return true
        default:
                return false
        }
}

func DurationMS(ms int) time.Duration {
        return time.Duration(ms) * time.Millisecond
}

func SinceMS(t time.Time) int64 {
        return time.Since(t).Milliseconds()
}

func JSONCompact(v any) string {
        b, err := json.Marshal(v)
        if err != nil {
                return "{}"
        }
        return string(b)
}

func JSONPretty(v any) string {
        b, err := json.MarshalIndent(v, "", "  ")
        if err != nil {
                return "{}"
        }
        return string(b)
}

func CopyBuffer(src io.Reader, dst io.Writer) (int64, error) {
        return io.Copy(dst, src)
}

func EqualBytes(a, b []byte) bool {
        return bytes.Equal(a, b)
}

func PrefixBytes(b []byte, n int) []byte {
        if n <= 0 {
                return nil
        }
        if len(b) < n {
                n = len(b)
        }
        out := make([]byte, n)
        copy(out, b[:n])
        return out
}

func PadRight(s string, n int, ch rune) string {
        r := []rune(s)
        for len(r) < n {
                r = append(r, ch)
        }
        return string(r)
}

func HostPort(host string, port int) string {
        return net.JoinHostPort(host, strconv.Itoa(port))
}

func SafeDiv(a, b float64) float64 {
        if b == 0 {
                return 0
        }
        return a / b
}

func Round2(v float64) float64 {
        return math.Round(v*100) / 100
}

type Ring struct {
        mu   sync.Mutex
        buf  []string
        next int
        full bool
}

func NewRing(n int) *Ring {
        if n <= 0 {
                n = 8
        }
        return &Ring{buf: make([]string, n)}
}

func (r *Ring) Push(s string) {
        r.mu.Lock()
        defer r.mu.Unlock()
        r.buf[r.next] = s
        r.next = (r.next + 1) % len(r.buf)
        if r.next == 0 {
                r.full = true
        }
}

func (r *Ring) Snapshot() []string {
        r.mu.Lock()
        defer r.mu.Unlock()
        if !r.full {
                out := make([]string, r.next)
                copy(out, r.buf[:r.next])
                return out
        }
        out := make([]string, len(r.buf))
        copy(out, r.buf[r.next:])
        copy(out[len(r.buf)-r.next:], r.buf[:r.next])
        return out
}

type Debounce struct {
        mu sync.Mutex
        last time.Time
        wait time.Duration
}

func NewDebounce(d time.Duration) *Debounce {
        return &Debounce{wait: d}
}

func (d *Debounce) Allow() bool {
        d.mu.Lock()
        defer d.mu.Unlock()
        now := time.Now()
        if now.Sub(d.last) < d.wait {
                return false
        }
        d.last = now
        return true
}
