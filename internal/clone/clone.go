package clone
import "bytes"
func Bytes(b []byte) []byte {
        if b == nil { return nil }
        o := make([]byte, len(b)); copy(o, b); return o
}
func Strings(in []string) []string {
        if in == nil { return nil }
        o := make([]string, len(in)); copy(o, in); return o
}
func StringMap(m map[string]string) map[string]string {
        if m == nil { return nil }
        o := make(map[string]string, len(m))
        for k, v := range m { o[k] = v }
        return o
}
func Equal(a, b []byte) bool { return bytes.Equal(a, b) }
