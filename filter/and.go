package filter

// and is a type that implements filterElement and reports if it is "and" or "or"
type and bool

func (a *and) IsPrimitive() bool {
	return false
}
