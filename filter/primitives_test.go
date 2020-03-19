package filter

import (
	"testing"
)

func TestPrimitivesCombine(t *testing.T) {
	tests := []struct {
		in, out primitives
	}{
		// NON-COMBINABLE
		// single
		{
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				},
			},
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				},
			},
		},
		// double
		{
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "def",
				},
			},
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "def",
				},
			},
		},
		// triple
		{
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "def",
				}, primitive{
					kind:      filterKindPort,
					direction: filterDirectionSrc,
					protocol:  filterProtocolUnset,
					id:        "25",
				},
			},
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "def",
				}, primitive{
					kind:      filterKindPort,
					direction: filterDirectionSrc,
					protocol:  filterProtocolUnset,
					id:        "25",
				},
			},
		},

		// COMBINABLE
		// "host abc and src" -> "host src abc"
		{
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindUnset,
					direction: filterDirectionSrc,
					protocol:  filterProtocolUnset,
					id:        "abc",
				},
			},
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionSrc,
					protocol:  filterProtocolUnset,
					id:        "abc",
				},
			},
		},
	}
	for i, tt := range tests {
		out := tt.in.combine()
		if !out.equal(&tt.out) {
			t.Errorf("%d: mismatched\nactual %#v\nexpected %#v", i, tt.in, tt.out)
		}
	}
}
