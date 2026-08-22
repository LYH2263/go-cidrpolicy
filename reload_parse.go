package cidrpolicy

import (
	"fmt"
	"net"
	"strings"
)

type ruleLine struct {
	Name string
	CIDR string
	Act  Action
}

func parseRuleLines(data string) ([]ruleLine, error) {
	var out []ruleLine
	for i, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			return out, fmt.Errorf("line %d: want name cidr allow|deny", i+1)
		}
		act := ActionDeny
		switch strings.ToLower(parts[2]) {
		case "allow":
			act = ActionAllow
		case "deny":
			act = ActionDeny
		default:
			return out, fmt.Errorf("line %d: bad action %q", i+1, parts[2])
		}
		if _, _, err := net.ParseCIDR(parts[1]); err != nil {
			return out, WrapBadCIDR(err)
		}
		out = append(out, ruleLine{Name: parts[0], CIDR: parts[1], Act: act})
	}
	return out, nil
}

func linesToRules(lines []ruleLine) []Rule {
	out := make([]Rule, 0, len(lines))
	for _, ln := range lines {
		_, n, _ := net.ParseCIDR(ln.CIDR)
		out = append(out, Rule{
			Name: ln.Name,
			Net:  cloneIPNet(n),
			Raw:  append([]byte(nil), ln.CIDR...),
			Act:  ln.Act,
		})
	}
	return out
}
