package pe

type OptionalHeader interface {
	GetMagic() uint16
	GetMajorLinkerVersion() uint8
	GetMinorLinkerVersion() uint8
	GetSizeOfCode() uint32
	GetSizeOfInitializedData() uint32
	GetSizeOfUninitializedData() uint32
	GetAddressOfEntryPoint() uint32
	GetBaseOfCode() uint32
	GetBaseOfData() (uint32, bool)
	GetImageBase() uint64
	GetSectionAlignment() uint32
	GetFileAlignment() uint32
	GetMajorOperatingSystemVersion() uint16
	GetMinorOperatingSystemVersion() uint16
	GetMajorImageVersion() uint16
	GetMinorImageVersion() uint16
	GetMajorSubsystemVersion() uint16
	GetMinorSubsystemVersion() uint16
	GetWin32VersionValue() uint32
	GetSizeOfImage() uint32
	GetSizeOfHeaders() uint32
	GetCheckSum() uint32
	GetSubsystem() uint16
	GetDllCharacteristics() uint16
	GetSizeOfStackReserve() uint64
	GetSizeOfStackCommit() uint64
	GetSizeOfHeapReserve() uint64
	GetSizeOfHeapCommit() uint64
	GetLoaderFlags() uint32
	GetNumberOfRvaAndSizes() uint32
	GetDataDirectories() [16]DataDirectory
}

type OptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectories             [16]DataDirectory
}

func (o OptionalHeader32) GetMagic() uint16 {
	return o.Magic
}

func (o OptionalHeader32) GetMajorLinkerVersion() uint8 {
	return o.MajorLinkerVersion
}

func (o OptionalHeader32) GetMinorLinkerVersion() uint8 {
	return o.MinorLinkerVersion
}

func (o OptionalHeader32) GetSizeOfCode() uint32 {
	return o.SizeOfCode
}

func (o OptionalHeader32) GetSizeOfInitializedData() uint32 {
	return o.SizeOfInitializedData
}

func (o OptionalHeader32) GetSizeOfUninitializedData() uint32 {
	return o.SizeOfUninitializedData
}

func (o OptionalHeader32) GetAddressOfEntryPoint() uint32 {
	return o.AddressOfEntryPoint
}

func (o OptionalHeader32) GetBaseOfCode() uint32 {
	return o.BaseOfCode
}

func (o OptionalHeader32) GetBaseOfData() (uint32, bool) {
	return o.BaseOfData, true
}

func (o OptionalHeader32) GetImageBase() uint64 {
	return uint64(o.ImageBase)
}

func (o OptionalHeader32) GetSectionAlignment() uint32 {
	return o.SectionAlignment
}

func (o OptionalHeader32) GetFileAlignment() uint32 {
	return o.FileAlignment
}

func (o OptionalHeader32) GetMajorOperatingSystemVersion() uint16 {
	return o.MajorOperatingSystemVersion
}

func (o OptionalHeader32) GetMinorOperatingSystemVersion() uint16 {
	return o.MinorOperatingSystemVersion
}

func (o OptionalHeader32) GetMajorImageVersion() uint16 {
	return o.MajorImageVersion
}

func (o OptionalHeader32) GetMinorImageVersion() uint16 {
	return o.MinorImageVersion
}

func (o OptionalHeader32) GetMajorSubsystemVersion() uint16 {
	return o.MajorSubsystemVersion
}

func (o OptionalHeader32) GetMinorSubsystemVersion() uint16 {
	return o.MinorSubsystemVersion
}

func (o OptionalHeader32) GetWin32VersionValue() uint32 {
	return o.Win32VersionValue
}

func (o OptionalHeader32) GetSizeOfImage() uint32 {
	return o.SizeOfImage
}

func (o OptionalHeader32) GetSizeOfHeaders() uint32 {
	return o.SizeOfHeaders
}

func (o OptionalHeader32) GetCheckSum() uint32 {
	return o.CheckSum
}

func (o OptionalHeader32) GetSubsystem() uint16 {
	return o.Subsystem
}

func (o OptionalHeader32) GetDllCharacteristics() uint16 {
	return o.DllCharacteristics
}

func (o OptionalHeader32) GetSizeOfStackReserve() uint64 {
	return uint64(o.SizeOfStackReserve)
}

func (o OptionalHeader32) GetSizeOfStackCommit() uint64 {
	return uint64(o.SizeOfStackCommit)
}

func (o OptionalHeader32) GetSizeOfHeapReserve() uint64 {
	return uint64(o.SizeOfHeapReserve)
}

func (o OptionalHeader32) GetSizeOfHeapCommit() uint64 {
	return uint64(o.SizeOfHeapCommit)
}

func (o OptionalHeader32) GetLoaderFlags() uint32 {
	return o.LoaderFlags
}

func (o OptionalHeader32) GetNumberOfRvaAndSizes() uint32 {
	return o.NumberOfRvaAndSizes
}

func (o OptionalHeader32) GetDataDirectories() [16]DataDirectory {
	return o.DataDirectories
}

type OptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectories             [16]DataDirectory
}

func (o OptionalHeader64) GetMagic() uint16 {
	return o.Magic
}

func (o OptionalHeader64) GetMajorLinkerVersion() uint8 {
	return o.MajorLinkerVersion
}

func (o OptionalHeader64) GetMinorLinkerVersion() uint8 {
	return o.MinorLinkerVersion
}

func (o OptionalHeader64) GetSizeOfCode() uint32 {
	return o.SizeOfCode
}

func (o OptionalHeader64) GetSizeOfInitializedData() uint32 {
	return o.SizeOfInitializedData
}

func (o OptionalHeader64) GetSizeOfUninitializedData() uint32 {
	return o.SizeOfUninitializedData
}

func (o OptionalHeader64) GetAddressOfEntryPoint() uint32 {
	return o.AddressOfEntryPoint
}

func (o OptionalHeader64) GetBaseOfCode() uint32 {
	return o.BaseOfCode
}

func (o OptionalHeader64) GetBaseOfData() (uint32, bool) {
	return 0, false
}

func (o OptionalHeader64) GetImageBase() uint64 {
	return uint64(o.ImageBase)
}

func (o OptionalHeader64) GetSectionAlignment() uint32 {
	return o.SectionAlignment
}

func (o OptionalHeader64) GetFileAlignment() uint32 {
	return o.FileAlignment
}

func (o OptionalHeader64) GetMajorOperatingSystemVersion() uint16 {
	return o.MajorOperatingSystemVersion
}

func (o OptionalHeader64) GetMinorOperatingSystemVersion() uint16 {
	return o.MinorOperatingSystemVersion
}

func (o OptionalHeader64) GetMajorImageVersion() uint16 {
	return o.MajorImageVersion
}

func (o OptionalHeader64) GetMinorImageVersion() uint16 {
	return o.MinorImageVersion
}

func (o OptionalHeader64) GetMajorSubsystemVersion() uint16 {
	return o.MajorSubsystemVersion
}

func (o OptionalHeader64) GetMinorSubsystemVersion() uint16 {
	return o.MinorSubsystemVersion
}

func (o OptionalHeader64) GetWin32VersionValue() uint32 {
	return o.Win32VersionValue
}

func (o OptionalHeader64) GetSizeOfImage() uint32 {
	return o.SizeOfImage
}

func (o OptionalHeader64) GetSizeOfHeaders() uint32 {
	return o.SizeOfHeaders
}

func (o OptionalHeader64) GetCheckSum() uint32 {
	return o.CheckSum
}

func (o OptionalHeader64) GetSubsystem() uint16 {
	return o.Subsystem
}

func (o OptionalHeader64) GetDllCharacteristics() uint16 {
	return o.DllCharacteristics
}

func (o OptionalHeader64) GetSizeOfStackReserve() uint64 {
	return o.SizeOfStackReserve
}

func (o OptionalHeader64) GetSizeOfStackCommit() uint64 {
	return o.SizeOfStackCommit
}

func (o OptionalHeader64) GetSizeOfHeapReserve() uint64 {
	return o.SizeOfHeapReserve
}

func (o OptionalHeader64) GetSizeOfHeapCommit() uint64 {
	return o.SizeOfHeapCommit
}

func (o OptionalHeader64) GetLoaderFlags() uint32 {
	return o.LoaderFlags
}

func (o OptionalHeader64) GetNumberOfRvaAndSizes() uint32 {
	return o.NumberOfRvaAndSizes
}

func (o OptionalHeader64) GetDataDirectories() [16]DataDirectory {
	return o.DataDirectories
}