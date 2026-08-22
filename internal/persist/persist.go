package persist
import ("encoding/json"; "os"; "path/filepath")
func SaveJSON(path string, v any) error {
        if d := filepath.Dir(path); d != "." {
                if err := os.MkdirAll(d, 0o755); err != nil { return err }
        }
        b, err := json.MarshalIndent(v, "", "  ")
        if err != nil { return err }
        tmp := path + ".tmp"
        if err := os.WriteFile(tmp, b, 0o644); err != nil { return err }
        return os.Rename(tmp, path)
}
func LoadJSON(path string, v any) error {
        b, err := os.ReadFile(path)
        if err != nil { return err }
        return json.Unmarshal(b, v)
}
