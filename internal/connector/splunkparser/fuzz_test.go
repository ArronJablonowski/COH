package splunkparser

import (
	"context"
	"testing"
)

func FuzzParseNeverPanics(f *testing.F) {
	seeds := []string{
		`search resource=endpoint action="blocked" | fields action,event_time,host,source | head 10`,
		`search resource=endpoint host IN ([ search resource=endpoint | table host | head 5 ]) | fields event_time,host`,
		`search resource=endpoint | collect value`,
		"search resource=endpoint `macro`",
		`search resource=endpoint (((host="value")))`,
		"\xff\x00|[]()",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = parse(context.Background(), input)
	})
}
