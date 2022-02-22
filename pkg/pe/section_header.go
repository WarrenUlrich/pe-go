package pe

type Section struct {
	Name string
	VirtualSize uint32
	VirtualAddress uint32
	RawSize uint32
	RawAddress uint32
	RelocAddress uint32
	LineNumbers uint32
	RelocCount uint16
	LineNumbersCount uint16
	Characteristics uint32
	Data []byte
}