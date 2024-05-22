package filter

import (
	"errors"
	"fmt"

	"golang.org/x/net/bpf"
)

/*
 File contains the extensive test cases, so it is easier to read the tests
*/

// primitiveTests list of test cases. Includes the input expression,
// the intermediate filter from Expression.Compile(), and the expected error and
// instructions from Filter.Compile()
type testCaseExpressions struct {
	expression   string
	filter       Filter
	err          error
	instructions []bpf.Instruction
	_            string // output from "tcpdump -d <expression>"
}

var (
	dnsRecords = map[string]map[string]string{
		"www.google.com": {
			"A":    "216.58.207.36",
			"AAAA": "2a00:1450:4001:824::2004",
		},
	}
)

var testCasesExpressionFilterInstructions = map[string][]testCaseExpressions{
	"hostname_invalid": {
		{"abc", primitive{
			kind:      filterKindUnset,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, fmt.Errorf("parse error"), nil, ""},
		{"host", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "",
		}, fmt.Errorf("blank host"), nil, ""},
		{"host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, fmt.Errorf("unknown host: %s", "abc"), nil, ""},
		{"src host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, fmt.Errorf("unknown host: %s", "abc"), nil, ""},
		{"dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, fmt.Errorf("unknown host: %s", "abc"), nil, ""},
		{"src or dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, fmt.Errorf("unknown host: %s", "abc"), nil, ""},
		{"src and dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, fmt.Errorf("unknown host: %s", "abc"), nil, ""},
	},
	"host_ip4": {
		{"10.100.100.100", primitive{
			kind:      filterKindUnset,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "10.100.100.100",
		}, errors.New("parse error"), nil, ""},
		{"host 10.100.100.100/24", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "10.100.100.100/24",
		}, fmt.Errorf("invalid host address with CIDR: %s", "10.100.100.100/24"), nil, ""},
		{"ip host 10.100.100.100", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolIP,
			id:        "10.100.100.100",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 2},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 7
		(002) ld       [26]
		(003) jeq      #0xa646464       jt 6	jf 4
		(004) ld       [30]
		(005) jeq      #0xa646464       jt 6	jf 7
		(006) ret      #262144
		(007) ret      #0
		`},
		{"arp host 10.100.100.100", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolArp,
			id:        "10.100.100.100",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 28, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 2},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x806           jt 2	jf 7
		(002) ld       [28]
		(003) jeq      #0xa646464       jt 6	jf 4
		(004) ld       [38]
		(005) jeq      #0xa646464       jt 6	jf 7
		(006) ret      #262144
		(007) ret      #0
		`},
		{"src host 10.100.100.100", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "10.100.100.100",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 4, SkipFalse: 5},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 28, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]													load half-word at byte 12 (EtherType)
		(001) jeq      #0x800           jt 2	jf 4	if 0x800 (ethertype_ip) go to 2, else 4
		(002) ld       [26]													load word at byte 26 (source IP address)
		(003) jeq      #0xa646464       jt 8	jf 9	if bytes match 10.100.100.100 (0xa 0x64 0x64 0x64) go to 8, else go to 9
		(004) jeq      #0x806           jt 6	jf 5	if 0x806 (arp), go to 6, else go to 5
		(005) jeq      #0x8035          jt 6	jf 9	if 0x8035 (rarp), go to 6, else go to 9
		(006) ld       [28]													load word at byte 28 (sender protoocol address)
		(007) jeq      #0xa646464       jt 8	jf 9	if bytes match 10.100.100.100 (0xa 0x64 0x64 0x64) go to 8, else go to 9
		(008) ret      #262144											return 0x40000, i.e. the entire packet
		(009) ret      #0														return constant 0 (drop packet)
		`},
		{"dst host 10.100.100.100", primitive{
			kind:      filterKindHost,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "10.100.100.100",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 4, SkipFalse: 5},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]													load half-word at byte 12 (EtherType)
		(001) jeq      #0x800           jt 2	jf 4	if 0x800 (ethertype_ip) go to 2, else 4
		(002) ld       [30]													load word at byte 30 (destination IP address)
		(003) jeq      #0xa646464       jt 8	jf 9	if bytes match 10.100.100.100 (0xa 0x64 0x64 0x64) go to 8, else go to 9
		(004) jeq      #0x806           jt 6	jf 5	if 0x806 (arp), go to 6, else go to 5
		(005) jeq      #0x8035          jt 6	jf 9	if 0x8035 (rarp), go to 6, else go to 9
		(006) ld       [38]													load word at byte 38 (target protoocol address)
		(007) jeq      #0xa646464       jt 8	jf 9	if bytes match 10.100.100.100 (0xa 0x64 0x64 0x64) go to 8, else go to 9
		(008) ret      #262144											return 0x40000, i.e. the entire packet
		(009) ret      #0														return constant 0 (drop packet)
		`},
		{"src or dst host 10.100.100.100", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "10.100.100.100",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 6, SkipFalse: 7},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 28, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 2},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, ""},
		{"src and dst host 10.100.100.100", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "10.100.100.100",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 9},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 6, SkipFalse: 7},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 28, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]													load half-word at byte 12 (EtherType)
		(001) jeq      #0x800           jt 2	jf 6	if 0x800 (ethertype_ip) go to 2, else 6
		(002) ld       [26]													load word at byte 26 (source IP address)
		(003) jeq      #0xa646464       jt 4	jf 13	if bytes match 10.100.100.100 (0xa 0x64 0x64 0x64) go to 4, else go to 13
		(004) ld       [30]													load word at byte 30 (target IP address)
		(005) jeq      #0xa646464       jt 12	jf 13	if bytes match 10.100.100.100 (0xa 0x64 0x64 0x64) go to 12, else go to 13
		(006) jeq      #0x806           jt 8	jf 7	if 0x806 (arp), go to 8, else go to 7
		(007) jeq      #0x8035          jt 8	jf 13	if 0x8035 (rarp), go to 8, else go to 13
		(008) ld       [28]													load word at byte 28 (sender protoocol address)
		(009) jeq      #0xa646464       jt 10	jf 13	if bytes match 10.100.100.100 (0xa 0x64 0x64 0x64) go to 10, else go to 13
		(010) ld       [38]													load word at byte 38 (target protocol address)
		(011) jeq      #0xa646464       jt 12	jf 13	if bytes match 10.100.100.100 (0xa 0x64 0x64 0x64) go to 12, else go to 13
		(012) ret      #262144											return 0x40000, i.e. the entire packet
		(013) ret      #0														return constant 0 (drop packet)
		`},
	},
	"host_ip6": {
		{"2a00:1450:4001:824::2004", primitive{
			kind:      filterKindUnset,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::2004",
		}, errors.New("parse error"), nil, ""},
		{"host 2a00:1450:4001:824::2004/48", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::2004/48",
		}, fmt.Errorf("invalid host address with CIDR: %s", "2a00:1450:4001:824::2004/48"), nil, ""},
		{"ip6 host 2a00:1450:4001:824::2004", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolIP6,
			id:        "2a00:1450:4001:824::2004",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 17},
			bpf.LoadAbsolute{Off: 22, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 34, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 19
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 10
		(004) ld       [26]
		(005) jeq      #0x40010824      jt 6	jf 10
		(006) ld       [30]
		(007) jeq      #0x0             jt 8	jf 10
		(008) ld       [34]
		(009) jeq      #0x2004          jt 18	jf 10
		(010) ld       [38]
		(011) jeq      #0x2a001450      jt 12	jf 19
		(012) ld       [42]
		(013) jeq      #0x40010824      jt 14	jf 19
		(014) ld       [46]
		(015) jeq      #0x0             jt 16	jf 19
		(016) ld       [50]
		(017) jeq      #0x2004          jt 18	jf 19
		(018) ret      #262144
		(019) ret      #0
		`},
		{"src host 2a00:1450:4001:824::2004", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::2004",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 9},
			bpf.LoadAbsolute{Off: 22, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 34, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 11
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 11
		(004) ld       [26]
		(005) jeq      #0x40010824      jt 6	jf 11
		(006) ld       [30]
		(007) jeq      #0x0             jt 8	jf 11
		(008) ld       [34]
		(009) jeq      #0x2004          jt 10	jf 11
		(010) ret      #262144
		(011) ret      #0
		`},
		{"dst host 2a00:1450:4001:824::2004", primitive{
			kind:      filterKindHost,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::2004",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 9},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 11
		(002) ld       [38]
		(003) jeq      #0x2a001450      jt 4	jf 11
		(004) ld       [42]
		(005) jeq      #0x40010824      jt 6	jf 11
		(006) ld       [46]
		(007) jeq      #0x0             jt 8	jf 11
		(008) ld       [50]
		(009) jeq      #0x2004          jt 10	jf 11
		(010) ret      #262144
		(011) ret      #0
		`},
		{"src or dst host 2a00:1450:4001:824::2004", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::2004",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 17},
			bpf.LoadAbsolute{Off: 22, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 34, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, ""},
		{"src and dst host 2a00:1450:4001:824::2004", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::2004",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 17},
			bpf.LoadAbsolute{Off: 22, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 15},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 13},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 11},
			bpf.LoadAbsolute{Off: 34, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 9},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 19
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 19
		(004) ld       [26]
		(005) jeq      #0x40010824      jt 6	jf 19
		(006) ld       [30]
		(007) jeq      #0x0             jt 8	jf 19
		(008) ld       [34]
		(009) jeq      #0x2004          jt 10	jf 19
		(010) ld       [38]
		(011) jeq      #0x2a001450      jt 12	jf 19
		(012) ld       [42]
		(013) jeq      #0x40010824      jt 14	jf 19
		(014) ld       [46]
		(015) jeq      #0x0             jt 16	jf 19
		(016) ld       [50]
		(017) jeq      #0x2004          jt 18	jf 19
		(018) ret      #262144
		(019) ret      #0
		`},
	},
	"hostname_valid": {
		{"www.google.com", primitive{
			kind:      filterKindUnset,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "www.google.com",
		}, errors.New("parse error"), nil, ""},
		{"host www.google.com", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "www.google.com",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},                        // load ethernet protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 4}, // ipv4 next few, else skip
			bpf.LoadAbsolute{Off: 26, Size: 4},                        // ipv4 src
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 25},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ipv4 dst
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 23, SkipFalse: 24},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},   // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 4}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp/rarp src
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 19},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // arp/rarp dst
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 17, SkipFalse: 18},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 17}, // ipv6 next few, else skip
			bpf.LoadAbsolute{Off: 22, Size: 4},                          // ip6 src first 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 34, Size: 4}, // ip6 src last 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst first 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4}, // ip6 dst next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4}, // ip6 dst next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4}, // ip6 dst last 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 6
		(002) ld       [26]
		(003) jeq      #0xd83acf24      jt 29	jf 4
		(004) ld       [30]
		(005) jeq      #0xd83acf24      jt 29	jf 30
		(006) jeq      #0x806           jt 8	jf 7
		(007) jeq      #0x8035          jt 8	jf 12
		(008) ld       [28]
		(009) jeq      #0xd83acf24      jt 29	jf 10
		(010) ld       [38]
		(011) jeq      #0xd83acf24      jt 29	jf 30
		(012) jeq      #0x86dd          jt 13	jf 30
		(013) ld       [22]
		(014) jeq      #0x2a001450      jt 15	jf 21
		(015) ld       [26]
		(016) jeq      #0x40010809      jt 17	jf 21
		(017) ld       [30]
		(018) jeq      #0x0             jt 19	jf 21
		(019) ld       [34]
		(020) jeq      #0x2004          jt 29	jf 21
		(021) ld       [38]
		(022) jeq      #0x2a001450      jt 23	jf 30
		(023) ld       [42]
		(024) jeq      #0x40010809      jt 25	jf 30
		(025) ld       [46]
		(026) jeq      #0x0             jt 27	jf 30
		(027) ld       [50]
		(028) jeq      #0x2004          jt 29	jf 30
		(029) ret      #262144
		(030) ret      #0
		`},
		{"src www.google.com", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "www.google.com",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},                        // load ethernet protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 2}, // ipv4 next few, else skip
			bpf.LoadAbsolute{Off: 26, Size: 4},                        // ipv4 src
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 13, SkipFalse: 14},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},   // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 2}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp/rarp src
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 9, SkipFalse: 10},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 9}, // ipv6 next few, else skip
			bpf.LoadAbsolute{Off: 22, Size: 4},                         // ip6 src first 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 26, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 34, Size: 4}, // ip6 src last 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 4
		(002) ld       [26]
		(003) jeq      #0xacd912a4      jt 17	jf 18
		(004) jeq      #0x806           jt 6	jf 5
		(005) jeq      #0x8035          jt 6	jf 8
		(006) ld       [28]
		(007) jeq      #0xacd912a4      jt 17	jf 18
		(008) jeq      #0x86dd          jt 9	jf 18
		(009) ld       [22]
		(010) jeq      #0x2a001450      jt 11	jf 18
		(011) ld       [26]
		(012) jeq      #0x40010806      jt 13	jf 18
		(013) ld       [30]
		(014) jeq      #0x0             jt 15	jf 18
		(015) ld       [34]
		(016) jeq      #0x2004          jt 17	jf 18
		(017) ret      #262144
		(018) ret      #0
		`},
		{"dst www.google.com", primitive{
			kind:      filterKindHost,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "www.google.com",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},                        // load ethernet protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 2}, // ipv4 next few, else skip
			bpf.LoadAbsolute{Off: 30, Size: 4},                        // ipv4 dst
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 13, SkipFalse: 14},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},   // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 2}, // rarp
			bpf.LoadAbsolute{Off: 38, Size: 4},                         // arp/rarp dst
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 9, SkipFalse: 10},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 9}, // ipv6 next few, else skip
			bpf.LoadAbsolute{Off: 38, Size: 4},                         // ip6 dst first 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4}, // ip6 src last 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 4
		(002) ld       [30]
		(003) jeq      #0xacd912a4      jt 17	jf 18
		(004) jeq      #0x806           jt 6	jf 5
		(005) jeq      #0x8035          jt 6	jf 8
		(006) ld       [38]
		(007) jeq      #0xacd912a4      jt 17	jf 18
		(008) jeq      #0x86dd          jt 9	jf 18
		(009) ld       [38]
		(010) jeq      #0x2a001450      jt 11	jf 18
		(011) ld       [42]
		(012) jeq      #0x40010806      jt 13	jf 18
		(013) ld       [46]
		(014) jeq      #0x0             jt 15	jf 18
		(015) ld       [50]
		(016) jeq      #0x2004          jt 17	jf 18
		(017) ret      #262144
		(018) ret      #0
		`},
		{"src or dst host www.google.com", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "www.google.com",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},                        // load ethernet protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 4}, // ipv4 next few, else skip
			bpf.LoadAbsolute{Off: 26, Size: 4},                        // ipv4 src
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 25},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ipv4 dst
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 23, SkipFalse: 24},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},   // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 4}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp/rarp src
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 19},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // arp/rarp dst
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 17, SkipFalse: 18},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 17}, // ipv6 next few, else skip
			bpf.LoadAbsolute{Off: 22, Size: 4},                          // ip6 src first 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 34, Size: 4}, // ip6 src last 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst first 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4}, // ip6 dst next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4}, // ip6 dst next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4}, // ip6 dst last 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 6
		(002) ld       [26]
		(003) jeq      #0xacd912a4      jt 29	jf 4
		(004) ld       [30]
		(005) jeq      #0xacd912a4      jt 29	jf 30
		(006) jeq      #0x806           jt 8	jf 7
		(007) jeq      #0x8035          jt 8	jf 12
		(008) ld       [28]
		(009) jeq      #0xacd912a4      jt 29	jf 10
		(010) ld       [38]
		(011) jeq      #0xacd912a4      jt 29	jf 30
		(012) jeq      #0x86dd          jt 13	jf 30
		(013) ld       [22]
		(014) jeq      #0x2a001450      jt 15	jf 21
		(015) ld       [26]
		(016) jeq      #0x40010806      jt 17	jf 21
		(017) ld       [30]
		(018) jeq      #0x0             jt 19	jf 21
		(019) ld       [34]
		(020) jeq      #0x2004          jt 29	jf 21
		(021) ld       [38]
		(022) jeq      #0x2a001450      jt 23	jf 30
		(023) ld       [42]
		(024) jeq      #0x40010806      jt 25	jf 30
		(025) ld       [46]
		(026) jeq      #0x0             jt 27	jf 30
		(027) ld       [50]
		(028) jeq      #0x2004          jt 29	jf 30
		(029) ret      #262144
		(030) ret      #0
		`},
		{"src and dst host www.google.com", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "www.google.com",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},                        // load ethernet protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 4}, // ipv4 next few, else skip
			bpf.LoadAbsolute{Off: 26, Size: 4},                        // ipv4 src
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipFalse: 26},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ipv4 dst
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 23, SkipFalse: 24},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},   // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 4}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp/rarp src
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipFalse: 20},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // arp/rarp dst
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xd83acf24, SkipTrue: 17, SkipFalse: 18},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 17}, // ipv6 next few, else skip
			bpf.LoadAbsolute{Off: 22, Size: 4},                          // ip6 src first 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 15},
			bpf.LoadAbsolute{Off: 26, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 13},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ip6 src next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 11},
			bpf.LoadAbsolute{Off: 34, Size: 4}, // ip6 src last 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 9},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst first 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4}, // ip6 dst next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4}, // ip6 dst next 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4}, // ip6 dst last 4 bytes
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2004, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 6
		(002) ld       [26]
		(003) jeq      #0xacd912a4      jt 4	jf 30
		(004) ld       [30]
		(005) jeq      #0xacd912a4      jt 29	jf 30
		(006) jeq      #0x806           jt 8	jf 7
		(007) jeq      #0x8035          jt 8	jf 12
		(008) ld       [28]
		(009) jeq      #0xacd912a4      jt 10	jf 30
		(010) ld       [38]
		(011) jeq      #0xacd912a4      jt 29	jf 30
		(012) jeq      #0x86dd          jt 13	jf 30
		(013) ld       [22]
		(014) jeq      #0x2a001450      jt 15	jf 30
		(015) ld       [26]
		(016) jeq      #0x40010806      jt 17	jf 30
		(017) ld       [30]
		(018) jeq      #0x0             jt 19	jf 30
		(019) ld       [34]
		(020) jeq      #0x2004          jt 21	jf 30
		(021) ld       [38]
		(022) jeq      #0x2a001450      jt 23	jf 30
		(023) ld       [42]
		(024) jeq      #0x40010806      jt 25	jf 30
		(025) ld       [46]
		(026) jeq      #0x0             jt 27	jf 30
		(027) ld       [50]
		(028) jeq      #0x2004          jt 29	jf 30
		(029) ret      #262144
		(030) ret      #0
		`},
	},
	"port": {
		{"port foo", primitive{
			kind:      filterKindPort,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "foo",
		}, fmt.Errorf("invalid port: %s", "foo"), nil, ""},
		{"port 22", primitive{
			kind:      filterKindPort,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "22",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps; else check ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 8},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},   // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},   // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 17}, // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 14},
			bpf.LoadAbsolute{Off: 56, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 12, SkipFalse: 13},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 12},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},     // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},     // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 8},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 2},
			bpf.LoadIndirect{Off: 16, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]													load half-word at byte 12 (EtherType)
		(001) jeq      #0x86dd          jt 2	jf 10 if 0x86dd (IPv6), go to 2, else 10
		(002) ldb      [20]													load byte at byte 20 (next header, i.e. ip protocol)
		(003) jeq      #0x84            jt 6	jf 4	if 0x84 (sctp) go to 6, else go to 4
		(004) jeq      #0x6             jt 6	jf 5  if 0x06 (tcp) go to 6, else go to 5
		(005) jeq      #0x11            jt 6	jf 23 if 0x11 (udp) go to 6, else go to 23
		(006) ldh      [54]													load half-word at byte 54 (L4 header source port)
		(007) jeq      #0x16            jt 22	jf 8	if 0x16 (22) go to 22, else go to 8
		(008) ldh      [56]													load half-word at byte 56 (L4 header destination port)
		(009) jeq      #0x16            jt 22	jf 23	if 0x16 (22) go to 22, else go to 8
		(010) jeq      #0x800           jt 11	jf 23 if 0x800 (ipv4), go to 11, else 23
		(011) ldb      [23]													load byte at byte 23 (ip protocol)
		(012) jeq      #0x84            jt 15	jf 13	if 0x84 (sctp) go to 15, else go to 13
		(013) jeq      #0x6             jt 15	jf 14	if 0x06 (tcp) go to 15, else go to 14
		(014) jeq      #0x11            jt 15	jf 23	if 0x11 (udp) go to 15, else go to 23
		(015) ldh      [20]													load half-word at byte 20 (flags+fragment offset)
		(016) jset     #0x1fff          jt 23	jf 17	if 0x1fff mask (fragment 0), we do not have an L4 header, go to 23, else go to 17
		(017) ldxb     4*([14]&0xf)									load index register with byte size of IP header
		(018) ldh      [x + 14]											load half-word at position [index + 14], i.e. ethernet header (14) + IP header (x) - this gives first half-word in L4 header
		(019) jeq      #0x16            jt 22	jf 20	if 0x16 (22) go to 22, else go to 20
		(020) ldh      [x + 16]											load half-word at position [index + 16], L4 destination port
		(021) jeq      #0x16            jt 22	jf 23	if 0x16 (22) go to 22, else go to 23
		(022) ret      #262144											return 0x40000, i.e. the entire packet
		(023) ret      #0														return constant 0 (drop packet)
		`},
		{"port ssh", primitive{
			kind:      filterKindPort,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "ssh",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps; else check ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 8},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},   // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},   // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 17}, // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 14},
			bpf.LoadAbsolute{Off: 56, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 12, SkipFalse: 13},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 12},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},     // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},     // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 8},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 2},
			bpf.LoadIndirect{Off: 16, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, ""},
		{"src port 22", primitive{
			kind:      filterKindPort,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "22",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps; else check ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},   // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},   // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 13}, // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 10, SkipFalse: 11},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 10},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},     // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},     // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 6},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 8
		(002) ldb      [20]
		(003) jeq      #0x84            jt 6	jf 4
		(004) jeq      #0x6             jt 6	jf 5
		(005) jeq      #0x11            jt 6	jf 19
		(006) ldh      [54]
		(007) jeq      #0x35            jt 18	jf 19
		(008) jeq      #0x800           jt 9	jf 19
		(009) ldb      [23]
		(010) jeq      #0x84            jt 13	jf 11
		(011) jeq      #0x6             jt 13	jf 12
		(012) jeq      #0x11            jt 13	jf 19
		(013) ldh      [20]
		(014) jset     #0x1fff          jt 19	jf 15
		(015) ldxb     4*([14]&0xf)
		(016) ldh      [x + 14]
		(017) jeq      #0x35            jt 18	jf 19
		(018) ret      #262144
		(019) ret      #0
		`},
		{"dst port 22", primitive{
			kind:      filterKindPort,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "22",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps; else check ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},   // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},   // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 13}, // udp
			bpf.LoadAbsolute{Off: 56, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 10, SkipFalse: 11},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 10},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},     // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},     // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 6},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 16, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 8
		(002) ldb      [20]
		(003) jeq      #0x84            jt 6	jf 4
		(004) jeq      #0x6             jt 6	jf 5
		(005) jeq      #0x11            jt 6	jf 19
		(006) ldh      [56]
		(007) jeq      #0x35            jt 18	jf 19
		(008) jeq      #0x800           jt 9	jf 19
		(009) ldb      [23]
		(010) jeq      #0x84            jt 13	jf 11
		(011) jeq      #0x6             jt 13	jf 12
		(012) jeq      #0x11            jt 13	jf 19
		(013) ldh      [20]
		(014) jset     #0x1fff          jt 19	jf 15
		(015) ldxb     4*([14]&0xf)
		(016) ldh      [x + 16]
		(017) jeq      #0x35            jt 18	jf 19
		(018) ret      #262144
		(019) ret      #0
		`},
		{"src and dst port 22", primitive{
			kind:      filterKindPort,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "22",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps; else check ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 8},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},   // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},   // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 17}, // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipFalse: 15},
			bpf.LoadAbsolute{Off: 56, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipTrue: 12, SkipFalse: 13},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 12},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},     // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},     // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 8},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipFalse: 3},
			bpf.LoadIndirect{Off: 16, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x16, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, ""},
		// next one is interesting. It could be a composite "udp and port 23" or primitive "udp port 23".
		// so we test it with both.
		{"udp port 23", primitive{
			kind:        filterKindPort,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolUnset,
			subProtocol: filterSubProtocolUDP,
			id:          "23",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 20, Size: 1},                                      // protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 15},               // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                                      // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 12},                // port 23
			bpf.LoadAbsolute{Off: 56, Size: 2},                                      // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 10, SkipFalse: 11}, // port 23
			// ipv4? next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 10},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 8},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 2},     // port 23
			bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipFalse: 1},    // port 23
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
			(000) ldh      [12]
			(001) jeq      #0x86dd          jt 2	jf 8
			(002) ldb      [20]
			(003) jeq      #0x11            jt 4	jf 19
			(004) ldh      [54]
			(005) jeq      #0x17            jt 18	jf 6
			(006) ldh      [56]
			(007) jeq      #0x17            jt 18	jf 19
			(008) jeq      #0x800           jt 9	jf 19
			(009) ldb      [23]
			(010) jeq      #0x11            jt 11	jf 19
			(011) ldh      [20]
			(012) jset     #0x1fff          jt 19	jf 13
			(013) ldxb     4*([14]&0xf)
			(014) ldh      [x + 14]
			(015) jeq      #0x17            jt 18	jf 16
			(016) ldh      [x + 16]
			(017) jeq      #0x17            jt 18	jf 19
			(018) ret      #262144
			(019) ret      #0
			`},
	},
	"net_ip4": {
		{"net abc", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}, fmt.Errorf("invalid net: %s", "abc"), nil, ""},
		{"net 192.168.0.0", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// address is ipv4, so must be one of: ip4/arp/rarp
			// next section checks ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 26, Size: 4}, // ip4 src address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ip4 dst address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 6, SkipFalse: 7},
			// next section checks arp or rarp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 1},  // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 5}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp src address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 2},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // arp dst address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 6
		(002) ld       [26]
		(003) jeq      #0xc0a80000      jt 12	jf 4
		(004) ld       [30]
		(005) jeq      #0xc0a80000      jt 12	jf 13
		(006) jeq      #0x806           jt 8	jf 7
		(007) jeq      #0x8035          jt 8	jf 13
		(008) ld       [28]
		(009) jeq      #0xc0a80000      jt 12	jf 10
		(010) ld       [38]
		(011) jeq      #0xc0a80000      jt 12	jf 13
		(012) ret      #262144
		(013) ret      #0
		`},
		{"ip net 192.168.0.0", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolIP,
			id:        "192.168.0.0",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 26, Size: 4}, // ip4 src address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 2},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ip4 dst address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, ``},
		{"net 192.168.0.0/10", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/10",
		}, fmt.Errorf("invalid network, network bits extend past mask bits: %s", "192.168.0.0/10"), nil, ""},
		{"net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// address is ipv4, so must be one of: ip4/arp/rarp
			// next section checks ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4},                   // ip4 src address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 11},
			bpf.LoadAbsolute{Off: 30, Size: 4},                   // ip4 dst address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 8, SkipFalse: 9},
			// next section checks arp or rarp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 1},  // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 7}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp src address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00},       // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 3},
			bpf.LoadAbsolute{Off: 38, Size: 4},                   // arp dst address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 8
		(002) ld       [26]
		(003) and      #0xffffff00
		(004) jeq      #0xc0a80000      jt 16	jf 5
		(005) ld       [30]
		(006) and      #0xffffff00
		(007) jeq      #0xc0a80000      jt 16	jf 17
		(008) jeq      #0x806           jt 10	jf 9
		(009) jeq      #0x8035          jt 10	jf 17
		(010) ld       [28]
		(011) and      #0xffffff00
		(012) jeq      #0xc0a80000      jt 16	jf 13
		(013) ld       [38]
		(014) and      #0xffffff00
		(015) jeq      #0xc0a80000      jt 16	jf 17
		(016) ret      #262144
		(017) ret      #0
		`},
		{"src net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// address is ipv4, so must be one of: ip4/arp/rarp
			// next section checks ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 26, Size: 4},                   // ip4 src address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 5, SkipFalse: 6},
			// next section checks arp or rarp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 1},  // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 4}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp src address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00},       // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 5
		(002) ld       [26]
		(003) and      #0xffffff00
		(004) jeq      #0xc0a80000      jt 10	jf 11
		(005) jeq      #0x806           jt 7	jf 6
		(006) jeq      #0x8035          jt 7	jf 11
		(007) ld       [28]
		(008) and      #0xffffff00
		(009) jeq      #0xc0a80000      jt 10	jf 11
		(010) ret      #262144
		(011) ret      #0
		`},
		{"dst net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// address is ipv4, so must be one of: ip4/arp/rarp
			// next section checks ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 30, Size: 4},                   // ip4 dst address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 5, SkipFalse: 6},
			// next section checks arp or rarp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 1},  // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 4}, // rarp
			bpf.LoadAbsolute{Off: 38, Size: 4},                         // arp dst address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00},       // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 5
		(002) ld       [30]
		(003) and      #0xffffff00
		(004) jeq      #0xc0a80000      jt 10	jf 11
		(005) jeq      #0x806           jt 7	jf 6
		(006) jeq      #0x8035          jt 7	jf 11
		(007) ld       [38]
		(008) and      #0xffffff00
		(009) jeq      #0xc0a80000      jt 10	jf 11
		(010) ret      #262144
		(011) ret      #0
		`},
		{"src and dst net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// address is ipv4, so must be one of: ip4/arp/rarp
			// next section checks ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4},                   // ip4 src address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 12},
			bpf.LoadAbsolute{Off: 30, Size: 4},                   // ip4 dst address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 8, SkipFalse: 9},
			// next section checks arp or rarp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 1},  // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 7}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp src address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00},       // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 38, Size: 4},                   // arp dst address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 8
		(002) ld       [26]
		(003) and      #0xffffff00
		(004) jeq      #0xc0a80000      jt 5	jf 17
		(005) ld       [30]
		(006) and      #0xffffff00
		(007) jeq      #0xc0a80000      jt 16	jf 17
		(008) jeq      #0x806           jt 10	jf 9
		(009) jeq      #0x8035          jt 10	jf 17
		(010) ld       [28]
		(011) and      #0xffffff00
		(012) jeq      #0xc0a80000      jt 13	jf 17
		(013) ld       [38]
		(014) and      #0xffffff00
		(015) jeq      #0xc0a80000      jt 16	jf 17
		(016) ret      #262144
		(017) ret      #0
		`},
		{"src or dst net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// address is ipv4, so must be one of: ip4/arp/rarp
			// next section checks ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4},                   // ip4 src address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 11},
			bpf.LoadAbsolute{Off: 30, Size: 4},                   // ip4 dst address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 8, SkipFalse: 9},
			// next section checks arp or rarp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 1},  // arp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 7}, // rarp
			bpf.LoadAbsolute{Off: 28, Size: 4},                         // arp src address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00},       // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipTrue: 3},
			bpf.LoadAbsolute{Off: 38, Size: 4},                   // arp dst address
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xffffff00}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xc0a80000, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 8
		(002) ld       [26]
		(003) and      #0xffffff00
		(004) jeq      #0xc0a80000      jt 16	jf 5
		(005) ld       [30]
		(006) and      #0xffffff00
		(007) jeq      #0xc0a80000      jt 16	jf 17
		(008) jeq      #0x806           jt 10	jf 9
		(009) jeq      #0x8035          jt 10	jf 17
		(010) ld       [28]
		(011) and      #0xffffff00
		(012) jeq      #0xc0a80000      jt 16	jf 13
		(013) ld       [38]
		(014) and      #0xffffff00
		(015) jeq      #0xc0a80000      jt 16	jf 17
		(016) ret      #262144
		(017) ret      #0
		`},
	},
	"net_ip6": {
		{"net 2a00:1450:4001:824::", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 17},
			bpf.LoadAbsolute{Off: 22, Size: 4}, // ip6 src address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4}, // ip6 src address part2
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ip6 src address part3
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 34, Size: 4}, // ip6 src address part4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4}, // ip6 dst address part2
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4}, // ip6 dst address part3
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4}, // ip6 dst address part4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 19
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 10
		(004) ld       [26]
		(005) jeq      #0x40010824      jt 6	jf 10
		(006) ld       [30]
		(007) jeq      #0x0             jt 8	jf 10
		(008) ld       [34]
		(009) jeq      #0x0             jt 18	jf 10
		(010) ld       [38]
		(011) jeq      #0x2a001450      jt 12	jf 19
		(012) ld       [42]
		(013) jeq      #0x40010824      jt 14	jf 19
		(014) ld       [46]
		(015) jeq      #0x0             jt 16	jf 19
		(016) ld       [50]
		(017) jeq      #0x0             jt 18	jf 19
		(018) ret      #262144
		(019) ret      #0
		`},
		{"ip6 net 2a00:1450:4001:824::", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolIP6,
			id:        "2a00:1450:4001:824::",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 17},
			bpf.LoadAbsolute{Off: 22, Size: 4}, // ip6 src address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 26, Size: 4}, // ip6 src address part2
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 30, Size: 4}, // ip6 src address part3
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 34, Size: 4}, // ip6 src address part4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 42, Size: 4}, // ip6 dst address part2
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 46, Size: 4}, // ip6 dst address part3
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 50, Size: 4}, // ip6 dst address part4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 19
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 10
		(004) ld       [26]
		(005) jeq      #0x40010824      jt 6	jf 10
		(006) ld       [30]
		(007) jeq      #0x0             jt 8	jf 10
		(008) ld       [34]
		(009) jeq      #0x0             jt 18	jf 10
		(010) ld       [38]
		(011) jeq      #0x2a001450      jt 12	jf 19
		(012) ld       [42]
		(013) jeq      #0x40010824      jt 14	jf 19
		(014) ld       [46]
		(015) jeq      #0x0             jt 16	jf 19
		(016) ld       [50]
		(017) jeq      #0x0             jt 18	jf 19
		(018) ret      #262144
		(019) ret      #0
		`},
		{"net 2a00:1450:4001:824::/10", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::/10",
		}, fmt.Errorf("invalid network, network bits extend past mask bits: %s", "2a00:1450:4001:824::/10"), nil, ""},
		{"net 2a00:1450:4001:824::/62", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::/62",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 11},
			bpf.LoadAbsolute{Off: 22, Size: 4}, // ip6 src address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 26, Size: 4},                   // ip6 src address part2
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffffc}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipTrue: 5},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 42, Size: 4},                   // ip6 dst address part2
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffffc}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 13
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 7
		(004) ld       [26]
		(005) and      #0xfffffffc
		(006) jeq      #0x40010824      jt 12	jf 7
		(007) ld       [38]
		(008) jeq      #0x2a001450      jt 9	jf 13
		(009) ld       [42]
		(010) and      #0xfffffffc
		(011) jeq      #0x40010824      jt 12	jf 13
		(012) ret      #262144
		(013) ret      #0
		`},
		{"src net 2a00:1450:4001:824::/62", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::/62",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 22, Size: 4}, // ip6 src address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 26, Size: 4},                   // ip6 src address part2
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffffc}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 8
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 8
		(004) ld       [26]
		(005) and      #0xfffffffc
		(006) jeq      #0x40010824      jt 7	jf 8
		(007) ret      #262144
		(008) ret      #0
		`},
		{"dst net 2a00:1450:4001:824::/62", primitive{
			kind:      filterKindNet,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::/62",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 42, Size: 4},                   // ip6 dst address part2
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffffc}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 8
		(002) ld       [38]
		(003) jeq      #0x2a001450      jt 4	jf 8
		(004) ld       [42]
		(005) and      #0xfffffffc
		(006) jeq      #0x40010824      jt 7	jf 8
		(007) ret      #262144
		(008) ret      #0
		`},
		{"src and dst net 2a00:1450:4001:824::/62", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::/62",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 11},
			bpf.LoadAbsolute{Off: 22, Size: 4}, // ip6 src address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 9},
			bpf.LoadAbsolute{Off: 26, Size: 4},                   // ip6 src address part2
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffffc}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 42, Size: 4},                   // ip6 dst address part2
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffffc}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 13
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 13
		(004) ld       [26]
		(005) and      #0xfffffffc
		(006) jeq      #0x40010824      jt 7	jf 13
		(007) ld       [38]
		(008) jeq      #0x2a001450      jt 9	jf 13
		(009) ld       [42]
		(010) and      #0xfffffffc
		(011) jeq      #0x40010824      jt 12	jf 13
		(012) ret      #262144
		(013) ret      #0
		`},
		{"src or dst net 2a00:1450:4001:824::/62", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "2a00:1450:4001:824::/62",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 11},
			bpf.LoadAbsolute{Off: 22, Size: 4}, // ip6 src address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 26, Size: 4},                   // ip6 src address part2
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffffc}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipTrue: 5},
			bpf.LoadAbsolute{Off: 38, Size: 4}, // ip6 dst address part1
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2a001450, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 42, Size: 4},                   // ip6 dst address part2
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffffc}, // netmask
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40010824, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 13
		(002) ld       [22]
		(003) jeq      #0x2a001450      jt 4	jf 7
		(004) ld       [26]
		(005) and      #0xfffffffc
		(006) jeq      #0x40010824      jt 12	jf 7
		(007) ld       [38]
		(008) jeq      #0x2a001450      jt 9	jf 13
		(009) ld       [42]
		(010) and      #0xfffffffc
		(011) jeq      #0x40010824      jt 12	jf 13
		(012) ret      #262144
		(013) ret      #0
		`},
	},
	"ether_address": {
		{"ether abc", primitive{
			kind:      filterKindUnset,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolEther,
			id:        "abc",
		}, errors.New("parse error"), nil, ""},
		{"ether dst abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionDst,
			protocol:  filterProtocolEther,
			id:        "abc",
		}, fmt.Errorf("invalid ethernet address: %s", "abc"), nil, ""},
		{"ether src abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolEther,
			id:        "abc",
		}, fmt.Errorf("invalid ethernet address: %s", "abc"), nil, ""},
		{"ether host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolEther,
			id:        "abc",
		}, fmt.Errorf("invalid ethernet address: %s", "abc"), nil, ""},
		{"ether src or dst abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolEther,
			id:        "abc",
		}, fmt.Errorf("invalid ethernet address: %s", "abc"), nil, ""},
		// the next group have a valid address
		{"ether aa:bb:cc:dd:ee:ff", primitive{
			kind:      filterKindUnset,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolEther,
			id:        "aa:bb:cc:dd:ee:ff",
		}, errors.New("parse error"), nil, ""},
		{"ether host aa:bb:cc:dd:ee:ff", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolEther,
			id:        "aa:bb:cc:dd:ee:ff",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 8, Size: 4}, // last 4 bytes of src mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xccddeeff, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 6, Size: 2}, // first 2 bytes of src mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xaabb, SkipTrue: 4},
			bpf.LoadAbsolute{Off: 2, Size: 4}, // last 4 bytes of dst mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xccddeeff, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 0, Size: 2}, // first 2 bytes of dst mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xaabb, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ld       [8]
		(001) jeq      #0xccddeeff      jt 2	jf 4
		(002) ldh      [6]
		(003) jeq      #0xaabb          jt 8	jf 4
		(004) ld       [2]
		(005) jeq      #0xccddeeff      jt 6	jf 9
		(006) ldh      [0]
		(007) jeq      #0xaabb          jt 8	jf 9
		(008) ret      #262144
		(009) ret      #0
		`},
		{"ether src aa:bb:cc:dd:ee:ff", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolEther,
			id:        "aa:bb:cc:dd:ee:ff",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 8, Size: 4}, // last 4 bytes of src mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xccddeeff, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 6, Size: 2}, // first 2 bytes of src mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xaabb, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ld       [8]
		(001) jeq      #0xccddeeff      jt 2	jf 5
		(002) ldh      [6]
		(003) jeq      #0xaabb          jt 4	jf 5
		(004) ret      #262144
		(005) ret      #0
		`},
		{"ether dst aa:bb:cc:dd:ee:ff", primitive{
			kind:      filterKindHost,
			direction: filterDirectionDst,
			protocol:  filterProtocolEther,
			id:        "aa:bb:cc:dd:ee:ff",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 2, Size: 4}, // last 4 bytes of dst mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xccddeeff, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 0, Size: 2}, // first 2 bytes of dst mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xaabb, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ld       [2]
		(001) jeq      #0xccddeeff      jt 2	jf 5
		(002) ldh      [0]
		(003) jeq      #0xaabb          jt 4	jf 5
		(004) ret      #262144
		(005) ret      #0
		`},
		{"ether src or dst aa:bb:cc:dd:ee:ff", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolEther,
			id:        "aa:bb:cc:dd:ee:ff",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 8, Size: 4}, // last 4 bytes of src mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xccddeeff, SkipFalse: 2},
			bpf.LoadAbsolute{Off: 6, Size: 2}, // first 2 bytes of src mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xaabb, SkipTrue: 4},
			bpf.LoadAbsolute{Off: 2, Size: 4}, // last 4 bytes of dst mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xccddeeff, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 0, Size: 2}, // first 2 bytes of dst mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xaabb, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ld       [8]
		(001) jeq      #0xccddeeff      jt 2	jf 4
		(002) ldh      [6]
		(003) jeq      #0xaabb          jt 8	jf 4
		(004) ld       [2]
		(005) jeq      #0xccddeeff      jt 6	jf 9
		(006) ldh      [0]
		(007) jeq      #0xaabb          jt 8	jf 9
		(008) ret      #262144
		(009) ret      #0
		`},
		{"ether src and dst aa:bb:cc:dd:ee:ff", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolEther,
			id:        "aa:bb:cc:dd:ee:ff",
		}, nil, []bpf.Instruction{
			bpf.LoadAbsolute{Off: 8, Size: 4}, // last 4 bytes of src mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xccddeeff, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 6, Size: 2}, // first 2 bytes of src mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xaabb, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 2, Size: 4}, // last 4 bytes of dst mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xccddeeff, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 0, Size: 2}, // first 2 bytes of dst mac address
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xaabb, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ld       [8]
		(001) jeq      #0xccddeeff      jt 2	jf 9
		(002) ldh      [6]
		(003) jeq      #0xaabb          jt 4	jf 9
		(004) ld       [2]
		(005) jeq      #0xccddeeff      jt 6	jf 9
		(006) ldh      [0]
		(007) jeq      #0xaabb          jt 8	jf 9
		(008) ret      #262144
		(009) ret      #0
		`},
	},
	"ether_proto": {
		{"ether proto foo", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolEther,
			subProtocol: filterSubProtocolUnknown,
			id:          "foo",
		}, fmt.Errorf("unknown protocol %s", "foo"), nil, ""},
		{"ether proto ip", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolEther,
			subProtocol: filterSubProtocolIP,
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 3
		(002) ret      #262144
		(003) ret      #0
		`},
		{"ether proto ip6", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolEther,
			subProtocol: filterSubProtocolIP6,
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 3
		(002) ret      #262144
		(003) ret      #0
		`},
		{"ether proto arp", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolEther,
			subProtocol: filterSubProtocolArp,
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x806           jt 2	jf 3
		(002) ret      #262144
		(003) ret      #0
		`},
		{"ether proto rarp", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolEther,
			subProtocol: filterSubProtocolRarp,
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x8035          jt 2	jf 3
		(002) ret      #262144
		(003) ret      #0
		`},
	},
	"ip_proto": {
		{"ip proto abc", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolIP,
			subProtocol: filterSubProtocolUnknown,
			id:          "abc",
		}, fmt.Errorf("unknown protocol %s", "abc"), nil, ""},
		// valid protocol
		{"ip proto tcp", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolIP,
			subProtocol: filterSubProtocolTCP,
			id:          "",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipFalse: 1}, // tcp
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 5
		(002) ldb      [23]
		(003) jeq      #0x6             jt 4	jf 5
		(004) ret      #262144
		(005) ret      #0
		`},
		{"ip proto udp", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolIP,
			subProtocol: filterSubProtocolUDP,
			id:          "",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 1}, // tcp
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, ""},

		{"udp", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolUnset,
			subProtocol: filterSubProtocolUDP,
			id:          "",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6: next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 20, Size: 1},                                    // ip6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 6},               // udp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2c, SkipFalse: 6},              // is a continuation packet
			bpf.LoadAbsolute{Off: 54, Size: 1},                                    // ip6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 3, SkipFalse: 4}, // udp
			// ipv4: next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 1}, // udp
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 7
		(002) ldb      [20]
		(003) jeq      #0x11            jt 10	jf 4
		(004) jeq      #0x2c            jt 5	jf 11
		(005) ldb      [54]
		(006) jeq      #0x11            jt 10	jf 11
		(007) jeq      #0x800           jt 8	jf 11
		(008) ldb      [23]
		(009) jeq      #0x11            jt 10	jf 11
		(010) ret      #262144
		(011) ret      #0
		`},
	},
	"composite": {
		// simple case that should combine down
		{"udp and port 23", primitive{
			kind:        filterKindPort,
			direction:   filterDirectionSrcOrDst,
			protocol:    filterProtocolUnset,
			subProtocol: filterSubProtocolUDP,
			id:          "23",
		}, nil, []bpf.Instruction{
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 6},
			bpf.LoadAbsolute{Off: 20, Size: 1},                                      // protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 15},               // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                                      // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 12},                // port 23
			bpf.LoadAbsolute{Off: 56, Size: 2},                                      // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 10, SkipFalse: 11}, // port 23
			// ipv4? next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 10},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 8},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 2},     // port 23
			bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipFalse: 1},    // port 23
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
		}, `
		// This is the real one given by "tcpdump -d udp and port 23".
		// However, we are not doing it for now; just some interim steps
		// we can optimize later
			(000) ldh      [12]
			(001) jeq      #0x86dd          jt 2	jf 8
			(002) ldb      [20]
			(003) jeq      #0x11            jt 4	jf 19
			(004) ldh      [54]
			(005) jeq      #0x17            jt 18	jf 6
			(006) ldh      [56]
			(007) jeq      #0x17            jt 18	jf 19
			(008) jeq      #0x800           jt 9	jf 19
			(009) ldb      [23]
			(010) jeq      #0x11            jt 11	jf 19
			(011) ldh      [20]
			(012) jset     #0x1fff          jt 19	jf 13
			(013) ldxb     4*([14]&0xf)
			(014) ldh      [x + 14]
			(015) jeq      #0x17            jt 18	jf 16
			(016) ldh      [x + 16]
			(017) jeq      #0x17            jt 18	jf 19
			(018) ret      #262144
			(019) ret      #0
			`},
		{"host 10.100.100.100 or port 23", composite{
			and: false,
			filters: []Filter{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionSrcOrDst,
					id:        "10.100.100.100",
				},
				primitive{
					kind:      filterKindPort,
					direction: filterDirectionSrcOrDst,
					protocol:  filterProtocolUnset,
					id:        "23",
				},
			},
		}, nil, []bpf.Instruction{
			// first condition: "host 10.100.100.100"
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 8},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 6, SkipFalse: 7},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 28, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 2},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipFalse: 1},
			// OR - so success to end and fail to next
			bpf.Jump{Skip: 23},
			bpf.Jump{Skip: 0},

			// second condition: "port 23"
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps; else check ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 8},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},   // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},   // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 17}, // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 14},
			bpf.LoadAbsolute{Off: 56, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 12, SkipFalse: 13},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 12},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},     // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},     // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 8},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 2},
			bpf.LoadIndirect{Off: 16, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
			/* the real steps
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 15},
			bpf.LoadAbsolute{Off: 26, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 28},
			bpf.LoadAbsolute{Off: 30, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 26},
			bpf.LoadAbsolute{Off: 23, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 23},
			bpf.LoadAbsolute{Off: 20, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 21},
			bpf.LoadMemShift{Off: 14},
			bpf.LoadIndirect{Off: 14, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 17},
			bpf.LoadIndirect{Off: 16, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 15},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x806, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8035, SkipFalse: 4},
			bpf.LoadAbsolute{Off: 28, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 11},
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa646464, SkipTrue: 9},
			// ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 9},
			bpf.LoadAbsolute{Off: 20, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 54, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipTrue: 2},
			bpf.LoadAbsolute{Off: 56, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x17, SkipFalse: 1},
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
			*/
		}, `
			// this is the real one given by "tcpdump -d"; we may optimize towards it in the future
		(000) ldh      [12]
		(001) jeq      #0x800           jt 2	jf 17
		(002) ld       [26]
		(003) jeq      #0xa646464       jt 32	jf 4
		(004) ld       [30]
		(005) jeq      #0xa646464       jt 32	jf 6
		(006) ldb      [23]
		(007) jeq      #0x84            jt 10	jf 8
		(008) jeq      #0x6             jt 10	jf 9
		(009) jeq      #0x11            jt 10	jf 33
		(010) ldh      [20]
		(011) jset     #0x1fff          jt 33	jf 12
		(012) ldxb     4*([14]&0xf)
		(013) ldh      [x + 14]
		(014) jeq      #0x17            jt 32	jf 15
		(015) ldh      [x + 16]
		(016) jeq      #0x17            jt 32	jf 33
		(017) jeq      #0x806           jt 19	jf 18
		(018) jeq      #0x8035          jt 19	jf 23
		(019) ld       [28]
		(020) jeq      #0xa646464       jt 32	jf 21
		(021) ld       [38]
		(022) jeq      #0xa646464       jt 32	jf 33
		(023) jeq      #0x86dd          jt 24	jf 33
		(024) ldb      [20]
		(025) jeq      #0x84            jt 28	jf 26
		(026) jeq      #0x6             jt 28	jf 27
		(027) jeq      #0x11            jt 28	jf 33
		(028) ldh      [54]
		(029) jeq      #0x17            jt 32	jf 30
		(030) ldh      [56]
		(031) jeq      #0x17            jt 32	jf 33
		(032) ret      #262144
		(033) ret      #0
		`},
		// automatic carry-forward of defaults
		{"tcp dst port ftp or ftp-data or domain", composite{
			and: false,
			filters: []Filter{
				primitive{
					kind:        filterKindPort,
					direction:   filterDirectionDst,
					protocol:    filterProtocolUnset,
					subProtocol: filterSubProtocolTCP,
					id:          "ftp",
				},
				primitive{
					kind:        filterKindPort,
					direction:   filterDirectionDst,
					protocol:    filterProtocolUnset,
					subProtocol: filterSubProtocolTCP,
					id:          "ftp-data",
				},
				primitive{
					kind:        filterKindPort,
					direction:   filterDirectionDst,
					protocol:    filterProtocolUnset,
					subProtocol: filterSubProtocolTCP,
					id:          "domain",
				},
			},
		}, nil, []bpf.Instruction{
			// first: tcp dst port ftp
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 4},            // check ipv6
			bpf.LoadAbsolute{Off: 20, Size: 1},                                    // ipv6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 11},              // tcp
			bpf.LoadAbsolute{Off: 56, Size: 2},                                    // ipv6 dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x15, SkipTrue: 8, SkipFalse: 9}, // ftp
			// ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 8}, // ipv4
			bpf.LoadAbsolute{Off: 23, Size: 1},                         // ipv4 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 6},    // tcp
			bpf.LoadAbsolute{Off: 20, Size: 2},                         // next few steps calculate location of ipv4 port
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4},
			bpf.LoadMemShift{Off: 14},
			bpf.LoadIndirect{Off: 16, Size: 2},                       // ipv4 dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x15, SkipFalse: 1}, // ftp

			// OR - jump to next
			bpf.Jump{Skip: 31},
			bpf.Jump{Skip: 0},

			// second: tcp dst port ftp-data
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 4},            // check ipv6
			bpf.LoadAbsolute{Off: 20, Size: 1},                                    // ipv6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 11},              // tcp
			bpf.LoadAbsolute{Off: 56, Size: 2},                                    // ipv6 dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x14, SkipTrue: 8, SkipFalse: 9}, // ftp-data
			// ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 8}, // ipv4
			bpf.LoadAbsolute{Off: 23, Size: 1},                         // ipv4 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 6},    // tcp
			bpf.LoadAbsolute{Off: 20, Size: 2},                         // next few steps calculate location of ipv4 port
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4},
			bpf.LoadMemShift{Off: 14},
			bpf.LoadIndirect{Off: 16, Size: 2},                       // ipv4 dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x14, SkipFalse: 1}, // ftp-data

			// OR - jump to next
			bpf.Jump{Skip: 15},
			bpf.Jump{Skip: 0},

			// third: tcp dst port domain
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 4},            // check ipv6
			bpf.LoadAbsolute{Off: 20, Size: 1},                                    // ipv6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 11},              // tcp
			bpf.LoadAbsolute{Off: 56, Size: 2},                                    // ipv6 dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 8, SkipFalse: 9}, // domain
			// ipv4
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 8}, // ipv4
			bpf.LoadAbsolute{Off: 23, Size: 1},                         // ipv4 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 6},    // tcp
			bpf.LoadAbsolute{Off: 20, Size: 2},                         // next few steps calculate location of ipv4 port
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4},
			bpf.LoadMemShift{Off: 14},
			bpf.LoadIndirect{Off: 16, Size: 2},                       // ipv4 dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipFalse: 1}, // domain

			// end
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
			/*
				Here is the real one; we may optimize for it later
				bpf.LoadAbsolute{Off: 12, Size: 2},
				// ipv6
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 4}, // check ipv6
				bpf.LoadAbsolute{Off: 20, Size: 1},  												// ipv6 protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 13},		// tcp
				bpf.LoadAbsolute{Off: 56, Size: 2},													// ipv6 dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x15, SkipTrue: 10, SkipFalse: 8},	// ftp
				// ipv4
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 10}, // ipv4
				bpf.LoadAbsolute{Off: 23, Size: 1}, 												 // ipv4 protocol
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x6, SkipFalse: 8},		 // tcp
				bpf.LoadAbsolute{Off: 20, Size: 2},													 // next few steps calculate location of ipv4 port
				bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 21},
				bpf.LoadMemShift{Off: 14},
				bpf.LoadIndirect{Off: 16, Size: 2},														// ipv4 dst port
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x15, SkipTrue: 2},			// ftp
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x14, SkipTrue: 1},			// ftp-data
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipFalse: 1},			// domain/dns
				bpf.RetConstant{Val: 262144},
				bpf.RetConstant{Val: 0},

			*/
		}, `
		// this is the true one given by "tcpdump -d"; we may optimize towards it later
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 6
		(002) ldb      [20]
		(003) jeq      #0x6             jt 4	jf 17
		(004) ldh      [56]
		(005) jeq      #0x15            jt 16	jf 14
		(006) jeq      #0x800           jt 7	jf 17
		(007) ldb      [23]
		(008) jeq      #0x6             jt 9	jf 17
		(009) ldh      [20]
		(010) jset     #0x1fff          jt 17	jf 11
		(011) ldxb     4*([14]&0xf)
		(012) ldh      [x + 16]
		(013) jeq      #0x15            jt 16	jf 14
		(014) jeq      #0x14            jt 16	jf 15
		(015) jeq      #0x35            jt 16	jf 17
		(016) ret      #262144
		(017) ret      #0
		`},
		{"udp and (port 53 or port 67)", composite{
			and: true,
			filters: []Filter{
				primitive{
					kind:        filterKindUnset,
					direction:   filterDirectionSrcOrDst,
					protocol:    filterProtocolUnset,
					subProtocol: filterSubProtocolUDP,
					id:          "",
				},
				composite{
					and: false,
					filters: []Filter{
						primitive{
							kind:      filterKindPort,
							direction: filterDirectionSrcOrDst,
							protocol:  filterProtocolUnset,
							id:        "53",
						},
						primitive{
							kind:      filterKindPort,
							direction: filterDirectionSrcOrDst,
							protocol:  filterProtocolUnset,
							id:        "67",
						},
					},
				},
			},
		}, nil, []bpf.Instruction{
			// our interim one

			// the first primitive: udp
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6: next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 5},
			bpf.LoadAbsolute{Off: 20, Size: 1},                                    // ip6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 6},               // udp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x2c, SkipFalse: 6},              // is a continuation packet
			bpf.LoadAbsolute{Off: 54, Size: 1},                                    // ip6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipTrue: 3, SkipFalse: 4}, // udp
			// ipv4: next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 3},
			bpf.LoadAbsolute{Off: 23, Size: 1},                       // ip6 protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 1}, // udp
			bpf.Jump{Skip: 1},
			bpf.Jump{Skip: 47},

			// the second primitive: port 53
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps; else check ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 8},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},   // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},   // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 17}, // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 14},
			bpf.LoadAbsolute{Off: 56, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 12, SkipFalse: 13},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 12},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},     // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},     // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 8},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 2},
			bpf.LoadIndirect{Off: 16, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipFalse: 1},
			bpf.Jump{Skip: 23},
			bpf.Jump{Skip: 0},

			// the second primitive: port 67
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps; else check ipv6
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 8},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},   // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},   // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 17}, // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipTrue: 14},
			bpf.LoadAbsolute{Off: 56, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipTrue: 12, SkipFalse: 13},
			// ipv4? next several steps, else fail
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 12},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x84, SkipTrue: 2},     // sctp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x06, SkipTrue: 1},     // tcp
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 8},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipTrue: 2},
			bpf.LoadIndirect{Off: 16, Size: 2}, // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipFalse: 1},

			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
			/* the real steps
			// get ethernet protocol
			bpf.LoadAbsolute{Off: 12, Size: 2},
			// ipv6? next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipFalse: 7},
			bpf.LoadAbsolute{Off: 20, Size: 1},                        // protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 18}, // udp
			bpf.LoadAbsolute{Off: 54, Size: 2},                        // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 15},  // port 53
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x43, SkipTrue: 14},  // port 67
			bpf.LoadAbsolute{Off: 56, Size: 2},                        // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 12, JumpFalse: 11},  // port 53
			// ipv4? next several steps
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 12},
			bpf.LoadAbsolute{Off: 23, Size: 1},                          // ip protocol
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x11, SkipFalse: 9},    // udp
			bpf.LoadAbsolute{Off: 20, Size: 2},                          // flags+fragment offset, since we need to calc where the src/dst port is
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 8}, // do we have an L4 header?
			bpf.LoadMemShift{Off: 14},                                   // calculate size of IP header
			bpf.LoadIndirect{Off: 14, Size: 2},                          // src port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 4},     // port 53
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x43, SkipTrue: 3},     // port 67
			bpf.LoadIndirect{Off: 16, Size: 2},                          // dst port
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x35, SkipTrue: 1},     // port 53
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x43, SkipFalse: 1},     // port 67
			bpf.RetConstant{Val: 262144},
			bpf.RetConstant{Val: 0},
			*/
		}, `
		// This is the real one given by "tcpdump -d".
		// However, we are not doing it for now; just some interim steps
		// we can optimize later
		(000) ldh      [12]
		(001) jeq      #0x86dd          jt 2	jf 9
		(002) ldb      [20]
		(003) jeq      #0x11            jt 4	jf 22
		(004) ldh      [54]
		(005) jeq      #0x35            jt 21	jf 6
		(006) jeq      #0x43            jt 21	jf 7
		(007) ldh      [56]
		(008) jeq      #0x35            jt 21	jf 20
		(009) jeq      #0x800           jt 10	jf 22
		(010) ldb      [23]
		(011) jeq      #0x11            jt 12	jf 22
		(012) ldh      [20]
		(013) jset     #0x1fff          jt 22	jf 14
		(014) ldxb     4*([14]&0xf)
		(015) ldh      [x + 14]
		(016) jeq      #0x35            jt 21	jf 17
		(017) jeq      #0x43            jt 21	jf 18
		(018) ldh      [x + 16]
		(019) jeq      #0x35            jt 21	jf 20
		(020) jeq      #0x43            jt 21	jf 22
		(021) ret      #262144
		(022) ret      #0
			`},
	},
}

/* missing:
composites
*/
