package pe

type NTHeaders struct {
	Signature uint32
	FileHeader FileHeader
	OptionalHeader OptionalHeader
}
