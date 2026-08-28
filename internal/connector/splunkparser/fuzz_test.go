package splunkparser

import (
	"context"
	"testing"
)

func FuzzParseNeverPanics(f *testing.F) {
	f.Add(`search resource=endpoint action="blocked" | fields action,event_time,host,source | head 10`)
	f.Add(`search resource=endpoint host IN ([ search resource=endpoint | table host | head 5 ]) | fields event_time,host`)
	f.Add(`search resource=endpoint | collect value`)
	f.Add("search resource=endpoint `macro`")
	f.Add(`search resource=endpoint (((host="value")))`)
	f.Add("\xff\x00|[]()")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = parse(context.Background(), input)
	})
}
