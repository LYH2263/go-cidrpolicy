package validate
import ("fmt"; "strings"; "unicode/utf8")
func NonEmpty(field, v string) error {
        if strings.TrimSpace(v) == "" { return fmt.Errorf("%s empty", field) }
        return nil
}
func MaxLen(field, v string, n int) error {
        if utf8.RuneCountInString(v) > n { return fmt.Errorf("%s too long", field) }
        return nil
}
func InRange(field string, v, lo, hi int) error {
        if v < lo || v > hi { return fmt.Errorf("%s out of range", field) }
        return nil
}
