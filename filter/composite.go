package filter

import (
	"sort"

	"golang.org/x/net/bpf"
)

// composite implements Filter
type composite struct {
	primitives primitives
	and        bool
}

func (c composite) Compile() ([]bpf.Instruction, error) {
	return nil, nil
}

func (c composite) Equal(o Filter) bool {
	if o == nil {
		return false
	}
	oc, ok := o.(composite)
	if !ok {
		return false
	}
	return c.and == oc.and && c.primitives.Equal(oc.primitives)
}

// Size how many elements do we expect
func (c composite) Size() uint8 {
	return 0
}

type primitives []primitive

func (p primitives) Len() int {
	return len(p)
}

func (p primitives) Less(i, j int) bool {
	return false
}

func (p primitives) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}
func (p primitives) Equal(o primitives) bool {
	// not matched if of the wrong length
	if len(p) != len(o) {
		return false
	}

	// copy so that our sort does not affect the original
	p1 := p[:]
	o1 := o[:]
	sort.Sort(p1)
	sort.Sort(o1)
	for i, val := range p1 {
		if !val.Equal(o1[i]) {
			return false
		}
	}
	return true
}
