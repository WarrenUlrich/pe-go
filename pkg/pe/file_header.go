package pe

type FileHeader struct {
	Machine uint16
	NumberOfSections uint16
	TimeDateStamp uint32
	PointerToSymbolTable uint32
	NumberOfSymbols uint32
	SizeOfOptionalHeader uint16
	Characteristics uint16
}
