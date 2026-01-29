package config

import (
	"net/url"
	"regexp"
	"strings"
)

var invalidNodeKeywords = []string{
	"到期",
	"过期",
	"流量重置",
	"重置流量",
	"流量已重置",
	"剩余流量",
	"套餐到期",
	"长期有效",
	"距离下次重置",
	"下次重置",
	"建议",
	"感到卡顿",
	"专线",
	"官网",
	"官方网站",
	"官网地址",
	"subscription",
	"subscribe",
	"expired",
	"expire",
	"traffic reset",
	"traffic-reset",
}

var invalidNodeRegexps = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*\d+(?:[.-]\d+)?\s*-?\s*gb\s*$`),
}

// IsInvalidNode reports whether name/URI looks like a non-node entry.
func IsInvalidNode(name, uri string) (bool, string) {
	name = strings.TrimSpace(name)
	uri = strings.TrimSpace(uri)
	if name == "" && uri == "" {
		return false, ""
	}
	var candidates []string
	if name != "" {
		candidates = append(candidates, name)
	}
	if uri != "" {
		candidates = append(candidates, uri)
		if decoded, err := url.QueryUnescape(uri); err == nil && decoded != "" {
			candidates = append(candidates, decoded)
		}
		if parsed, err := url.Parse(uri); err == nil {
			if frag := strings.TrimSpace(parsed.Fragment); frag != "" {
				candidates = append(candidates, frag)
				if decodedFrag, err := url.QueryUnescape(frag); err == nil && decodedFrag != "" {
					candidates = append(candidates, decodedFrag)
				}
			}
		}
	}

	combined := strings.ToLower(strings.Join(candidates, " "))
	for _, keyword := range invalidNodeKeywords {
		if strings.Contains(combined, keyword) {
			return true, keyword
		}
	}
	for _, re := range invalidNodeRegexps {
		for _, candidate := range candidates {
			if re.MatchString(strings.TrimSpace(candidate)) {
				return true, "pattern"
			}
		}
		if re.MatchString(name) {
			return true, "pattern"
		}
	}
	return false, ""
}
