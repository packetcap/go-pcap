package filter

import (
	"golang.org/x/net/bpf"
)

// Filter constructed of a tcpdump filter expression
type Filter interface {
	Compile() ([]bpf.Instruction, error)
	Equal(o Filter) bool
	Size() uint8
}

type filterElement interface {
	IsPrimitive() bool
}
