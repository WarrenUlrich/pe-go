package pe

type DOSHeader struct {
	Magic    uint16
	Cblp     uint16
	Cp       uint16
	Crlc     uint16
	Cparhdr  uint16
	MinAlloc uint16
	MaxAlloc uint16
	SS       uint16
	Sp       uint16
	Csum     uint16
	Ip       uint16
	Cs       uint16
	Lfarlc   uint16
	Ovno     uint16
	Res      [4]uint16
	Oemid    uint16
	Oeminfo  uint16
	Res2     [10]uint16
	Lfanew   uint32
}