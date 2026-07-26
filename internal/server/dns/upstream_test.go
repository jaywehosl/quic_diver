package dns

import (
	"context"
	"errors"
	"testing"
)

type dummyUpstream struct {
	addr string
	fail bool
	resp []byte
}

func (d *dummyUpstream) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if d.fail {
		return nil, errors.New("upstream failed")
	}
	return d.resp, nil
}

func (d *dummyUpstream) String() string {
	return d.addr
}

func TestMultiUpstreamFallback(t *testing.T) {
	primary := &dummyUpstream{addr: "primary:53", fail: true}
	secondary := &dummyUpstream{addr: "secondary:53", fail: false, resp: []byte{0x01, 0x02}}

	multi := NewMulti(primary, secondary)
	resp, err := multi.Exchange(context.Background(), []byte{0x00})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(resp) != 2 || resp[0] != 0x01 {
		t.Fatalf("ожидался ответ от вторичного DNS, получено %v", resp)
	}
}
