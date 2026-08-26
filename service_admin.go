package cidrpolicy
import ("context"; "fmt")
func (e *Engine) PutString(ctx context.Context, id, s string) error {
        return e.Put(ctx, id, []byte(s), nil)
}
func (e *Engine) Describe() string {
        st := e.Stats()
        return fmt.Sprintf("ok=%d fail=%d size=%d", st.OK, st.Fail, st.Size)
}
