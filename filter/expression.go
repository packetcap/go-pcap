package filter

import "strings"

type Expression struct {
	raw     string
	split   []string
	current int
}

func NewExpression(s string) *Expression {
	if s == "" {
		return nil
	}
	return &Expression{
		raw:   s,
		split: strings.Fields(s),
	}
}

func (e *Expression) Compile() Filter {
	// hold our reply
	var combo composite

	for {
		var fe filterElement
		if fe = e.Next(); fe == nil {
			break
		}
		// if it is not a primitive, we move up a level and join
		if fe.IsPrimitive() {
			p := fe.(*primitive)
			var lastPrimitive *primitive
			if len(combo.primitives) > 0 {
				lastPrimitive = &combo.primitives[len(combo.primitives)-1]
			}
			setPrimitiveDefaults(p, lastPrimitive)
			combo.primitives = append(combo.primitives, *p)
			continue
		}
		// it is not a primitive, so it is a joiner
		isAnd := fe.(*and)
		combo.and = bool(*isAnd)
	}
	// is there just one element?
	if len(combo.primitives) == 1 {
		return combo.primitives[0]
	}
	return combo
}

// HasNext if there are any more primitives to return
func (e *Expression) HasNext() bool {
	return len(e.split) > e.current
}

// Next get the next primitive. If none left, return nil.
func (e *Expression) Next() filterElement {
	if !e.HasNext() {
		return nil
	}
	startCount := e.current

	p := &primitive{
		direction: filterDirectionUnset,
		kind:      filterKindUnset,
		protocol:  filterProtocolUnset,
	}

words:
	for {
		if !e.HasNext() {
			break
		}
		word := e.split[e.current]
		// first look for and/or joiner, or negator, and really special cases
		switch word {
		case "and":
			// we hit "and" or "or". If we already have started building a primitive,
			// return the started one. Else return a joiner.
			if e.current != startCount {
				return p
			}
			j := and(true)
			e.current++
			return &j
		case "or":
			// we hit "and" or "or". If we already have started building a primitive,
			// return the started one. Else return a joiner.
			if e.current != startCount {
				return p
			}
			j := and(false)
			e.current++
			return &j
		case "not":
			p.negator = true
			e.current++
			continue words
		case "gateway":
			// this really needs to use the composite of two primitives
			p.protocol = filterProtocolEther
			p.kind = filterKindHost
			e.current++
			continue words
		case "proto":
			// the next word is the sub-protocol
			if len(e.split) <= e.current+1 {
				e.current++
				continue words
			}
			// we will accept the protocol as "name" or "\name", because some get escaped
			protoName := strings.TrimLeft(e.split[e.current+1], "\\")
			if sub, ok := subProtocols[protoName]; ok {
				p.subProtocol = sub
			} else {
				p.subProtocol = filterSubProtocolUnknown
				p.id = protoName
			}
			e.current++
			// we got the next word, so indicate not to parse it
			e.current++
			continue words
		case "src":
			// handle the "src or dst"/"src and dst" case
			if len(e.split) > e.current+2 && (e.split[e.current+1] == "or" || e.split[e.current+1] == "and") {
				word = strings.Join(e.split[e.current:e.current+3], " ")
				e.current += 2
			}
		}
		// it must be a primitive word, so find it
		if kind, ok := kinds[word]; ok {
			p.kind = kind
		} else if direction, ok := directions[word]; ok {
			p.direction = direction
		} else if protocol, ok := protocols[word]; ok {
			p.protocol = protocol
		} else if subprotocol, ok := subProtocols[word]; ok {
			p.subProtocol = subprotocol
		} else {
			p.id = word
		}
		e.current++
	}

	return p
}

// setPrimitiveDefaults set defaults on expressions
func setPrimitiveDefaults(p, lastPrimitive *primitive) {
	// if nothing was set, do not try to fix it
	if p.direction == filterDirectionUnset && p.protocol == filterProtocolUnset && p.kind == filterKindUnset && p.subProtocol == filterSubProtocolUnset {
		if lastPrimitive == nil {
			return
		}

		// we only copy over the previous ones if everything else is identical, per the manpage:
		/*
			To save typing, identical qualifier lists can be omitted. E.g., `tcp dst port ftp or ftp-data or domain' is exactly the same as `tcp dst port ftp or tcp dst port ftp-data or tcp dst port domain'
		*/
		p.direction = lastPrimitive.direction
		p.kind = lastPrimitive.kind
		p.protocol = lastPrimitive.protocol
		p.subProtocol = lastPrimitive.subProtocol
	}
	// special cases
	if (p.subProtocol == filterSubProtocolUdp || p.subProtocol == filterSubProtocolTcp || p.subProtocol == filterSubProtocolIcmp) && p.protocol == filterProtocolUnset {
		p.protocol = filterProtocolIp
	}

	if p.kind == filterKindUnset && p.direction != filterDirectionUnset && (p.protocol == filterProtocolEther || p.protocol == filterProtocolIp || p.protocol == filterProtocolIp6 || p.protocol == filterProtocolArp || p.protocol == filterProtocolRarp) {
		p.kind = filterKindHost
	}
	if p.direction == filterDirectionUnset {
		p.direction = filterDirectionSrcOrDst
	}
	if p.kind == filterKindUnset && p.protocol == filterProtocolUnset {
		p.kind = filterKindHost
	}
}
