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
	// first compile each one, then go through them and join with the 'and' or 'or'
	//   - if 'and', then a failure of any one is straight to fail
	//   - if 'or', then a failure of any one means to move on to the next
	// The simplest way to implement is to just have interim jump steps.
	inst := []bpf.Instruction{}
	size := uint32(c.Size())
	for i, p := range c.primitives {
		pinst, err := p.Compile()
		if err != nil {
			return nil, err
		}
		// remove the last two instructions, which are the returns, if we are not on the last one
		if i == len(c.primitives)-1 {
			inst = append(inst, pinst...)
			continue
		}
		pinst = pinst[:len(pinst)-2]
		inst = append(inst, pinst...)
		// now add the jump to the next steppf.
		// the expectation of every primitive is that the second to last is success,
		// and the last is fail. For that step.
		if c.and {
			// Each step is required, so if the previous step failed, it just fails.
			// If it succeeded, go to the next one.
			inst = append(inst, bpf.Jump{Skip: 1})
			inst = append(inst, bpf.Jump{Skip: size - uint32(len(inst)) - 2})
		} else {
			// Each step is not required, so if the previous step failed, go to next.
			// If it succeeded, return success.
			inst = append(inst, bpf.Jump{Skip: size - uint32(len(inst)) - 3})
			inst = append(inst, bpf.Jump{Skip: 0})
		}
	}
	return inst, nil
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
	var size uint8
	for _, p := range c.primitives {
		size += p.Size()
	}
	return size
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
