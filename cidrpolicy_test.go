package cidrpolicy
import "testing"
func TestPutGet(t *testing.T) {
        e, err := New(Options{})
        if err != nil { t.Fatal(err) }
        defer e.Close()
        if err := e.Put(t.Context(), "a", []byte("x"), nil); err != nil { t.Fatal(err) }
        r, err := e.Get("a")
        if err != nil || string(r.Payload) != "x" { t.Fatalf("%v %#v", err, r) }
}
