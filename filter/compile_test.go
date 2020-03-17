package filter

import (
	"context"
	"net"
	"os"
	"testing"

	"golang.org/x/net/bpf"
)

func setup() {
	dns := NewDNSServer(0, dnsRecords)
	addr := dns.StartAndServe()
	resolver = net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	os.Exit(code)
}

func TestExpressionEmpty(t *testing.T) {
	e := NewExpression("")
	if e != nil {
		t.Error("expected nil for blank expression")
	}
}
func TestExpressionHasNext(t *testing.T) {
	// single element
	e := NewExpression("a")
	if !e.HasNext() {
		t.Fatal("with one element remaining, should have HasNext()==true")
	}
	e.Next()
	if e.HasNext() {
		t.Fatal("with zero element remaining, should have HasNext()==false")
	}
}

func TestExpressionNextJoiner(t *testing.T) {
	tests := []struct {
		filter string
		prim   bool
		and    bool
	}{
		{"and", false, true},
		{"or", false, false},
		{"abc", true, false},
	}
	for i, tt := range tests {
		e := NewExpression(tt.filter)
		f := e.Next()
		if f.IsPrimitive() != tt.prim {
			t.Fatalf("%d: mismatched IsPrimitive, actual %v, expected %v", i, f.IsPrimitive(), tt.prim)
		}
		if tt.prim {
			continue
		}
		val := f.(*and)
		if bool(*val) != tt.and {
			t.Fatalf("%d: mismatched value, actual %v, expected %v", i, *val, tt.and)
		}
	}
}

// TestExpressionNextPrimitive tests Expression.Next(). This could be combined
// with the lists at testCasesExpressionFilterInstructions, but that includes
// setting defaults, which is a separate step
func TestExpressionNextPrimitive(t *testing.T) {
	tests := []struct {
		expression string
		prim       primitive
	}{
		{"abc", primitive{
			kind:      filterKindUnset,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"host", primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "",
		}},
		{"host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"src host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"src or dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"src and dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"port 22", primitive{
			kind:      filterKindPort,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "22",
		}},
		{"src port 22", primitive{
			kind:      filterKindPort,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "22",
		}},
		{"net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}},
		{"src net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}},
		{"ip proto tcp", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionUnset,
			protocol:    filterProtocolIP,
			subProtocol: filterSubProtocolTCP,
			id:          "",
		}},
	}
	for _, tt := range tests {
		e := NewExpression(tt.expression)
		f := e.Next()
		val := f.(*primitive)
		if !val.Equal(tt.prim) {
			t.Errorf("%s: mismatched value\nactual   %#v\nexpected %#v", tt.expression, *val, tt.prim)
		}
	}
}

func TestExpressionCompile(t *testing.T) {
	for k, v := range testCasesExpressionFilterInstructions {
		t.Run(k, func(t *testing.T) {
			for i, tt := range v {
				e := NewExpression(tt.expression)
				f := e.Compile()
				if !f.Equal(tt.filter) {
					t.Errorf("%d '%s': mismatched value\nactual   %#v\nexpected %#v", i, tt.expression, f, tt.filter)
				}
			}
		})
	}
}

func TestFilterSize(t *testing.T) {
	for k, v := range testCasesExpressionFilterInstructions {
		t.Run(k, func(t *testing.T) {
			for i, tt := range v {
				e := NewExpression(tt.expression)
				filter := e.Compile()
				if tt.err != nil {
					continue
				}
				size := filter.Size()
				if size != uint8(len(tt.instructions)) {
					t.Errorf("%d '%s': mismatched size actual %d, expected %d", i, tt.expression, size, len(tt.instructions))
				}
			}
		})
	}
}

func TestFilterCompile(t *testing.T) {
	for k, v := range testCasesExpressionFilterInstructions {
		t.Run(k, func(t *testing.T) {
			for i, tt := range v {
				e := NewExpression(tt.expression)
				filter := e.Compile()
				inst, err := filter.Compile()
				switch {
				case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && err.Error() != tt.err.Error()):
					t.Errorf("%d '%s': mismatched errors \nActual  : %v\nExpected: %v", i, tt.expression, err, tt.err)
				case !compareInstructions(inst, tt.instructions):
					t.Errorf("%d '%s': mismatched instructions \nActual  : %#v\nExpected: %#v", i, tt.expression, inst, tt.instructions)
				}
			}
		})
	}
}

// compare slices of bpf instruction
func compareInstructions(a, b []bpf.Instruction) bool {
	if len(a) != len(b) {
		return false
	}

	for i, item := range a {
		if item != b[i] {
			return false
		}
	}

	return true
}
