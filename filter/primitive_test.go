package filter

import (
	"testing"
)

func TestPrimitiveCombine(t *testing.T) {
	tests := []struct {
		a, b primitive
		c    *primitive
	}{
		// NON-COMBINABLE
		// different ID
		{primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "def",
		}, nil},
		// different negator
		{primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			negator:   true,
			id:        "abc",
		}, nil},
		// different kind
		{primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, primitive{
			kind:      filterKindPort,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, nil},
		// different direction
		{primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, nil},
		// different protocol
		{primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolIP,
			id:        "abc",
		}, primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolArp,
			id:        "abc",
		}, nil},
		// different subprotocol
		{primitive{
			kind:        filterKindHost,
			direction:   filterDirectionSrc,
			protocol:    filterProtocolIP,
			subProtocol: filterSubProtocolTCP,
			id:          "abc",
		}, primitive{
			kind:        filterKindHost,
			direction:   filterDirectionSrc,
			protocol:    filterProtocolIP,
			subProtocol: filterSubProtocolUDP,
			id:          "abc",
		}, nil},

		// COMBINABLE
		// identical
		{primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, &primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		// "host abc and src" -> "host src abc"
		{primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, primitive{
			kind:      filterKindUnset,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, &primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		// "udp and port 53" -> "udp port 53"
		{primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionUnset,
			protocol:    filterProtocolUnset,
			subProtocol: filterSubProtocolUDP,
			id:          "",
		}, primitive{
			kind:      filterKindPort,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "53",
		}, &primitive{
			kind:        filterKindPort,
			direction:   filterDirectionUnset,
			protocol:    filterProtocolUnset,
			subProtocol: filterSubProtocolUDP,
			id:          "53",
		}},
	}
	for i, tt := range tests {
		c := tt.a.Combine(&tt.b)
		if (c == nil && tt.c != nil) || (c != nil && tt.c == nil) || (c != nil && tt.c != nil && !c.Equal(*tt.c)) {
			t.Errorf("%d: mismatched\na %#v\nb %#v\nactual %#v\nexpected %#v", i, tt.a, tt.b, c, tt.c)
		}
	}
}
