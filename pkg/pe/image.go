package pe

import (
	"encoding/binary"
	"errors"
	"strings"
)

type Image struct {
	DOSHeader DOSHeader
	NTHeaders NTHeaders
	Sections  []Section
}

func Parse(data []byte) (Image, error) {
	var image Image
	image.DOSHeader = DOSHeader{
		Magic:    binary.LittleEndian.Uint16(data[0:2]),
		Cblp:     binary.LittleEndian.Uint16(data[2:4]),
		Cp:       binary.LittleEndian.Uint16(data[4:6]),
		Crlc:     binary.LittleEndian.Uint16(data[6:8]),
		Cparhdr:  binary.LittleEndian.Uint16(data[8:10]),
		MinAlloc: binary.LittleEndian.Uint16(data[10:12]),
		MaxAlloc: binary.LittleEndian.Uint16(data[12:14]),
		SS:       binary.LittleEndian.Uint16(data[14:16]),
		Sp:       binary.LittleEndian.Uint16(data[16:18]),
		Csum:     binary.LittleEndian.Uint16(data[18:20]),
		Ip:       binary.LittleEndian.Uint16(data[20:22]),
		Cs:       binary.LittleEndian.Uint16(data[22:24]),
		Lfarlc:   binary.LittleEndian.Uint16(data[24:26]),
		Ovno:     binary.LittleEndian.Uint16(data[26:28]),
		Res:      [4]uint16{binary.LittleEndian.Uint16(data[28:30]), binary.LittleEndian.Uint16(data[30:32]), binary.LittleEndian.Uint16(data[32:34]), binary.LittleEndian.Uint16(data[34:36])},
		Oemid:    binary.LittleEndian.Uint16(data[36:38]),
		Oeminfo:  binary.LittleEndian.Uint16(data[38:40]),
		Res2:     [10]uint16{binary.LittleEndian.Uint16(data[40:42]), binary.LittleEndian.Uint16(data[42:44]), binary.LittleEndian.Uint16(data[44:46]), binary.LittleEndian.Uint16(data[46:48]), binary.LittleEndian.Uint16(data[48:50]), binary.LittleEndian.Uint16(data[50:52]), binary.LittleEndian.Uint16(data[52:54]), binary.LittleEndian.Uint16(data[54:56]), binary.LittleEndian.Uint16(data[56:58]), binary.LittleEndian.Uint16(data[58:60])},
		Lfanew:   binary.LittleEndian.Uint32(data[60:64]),
	}

	ntHeaderData := data[image.DOSHeader.Lfanew:]
	image.NTHeaders = NTHeaders{
		Signature: binary.LittleEndian.Uint32(ntHeaderData[0:4]),
		FileHeader: FileHeader{
			Machine:              binary.LittleEndian.Uint16(ntHeaderData[4:6]),
			NumberOfSections:     binary.LittleEndian.Uint16(ntHeaderData[6:8]),
			TimeDateStamp:        binary.LittleEndian.Uint32(ntHeaderData[8:12]),
			PointerToSymbolTable: binary.LittleEndian.Uint32(ntHeaderData[12:16]),
			NumberOfSymbols:      binary.LittleEndian.Uint32(ntHeaderData[16:20]),
			SizeOfOptionalHeader: binary.LittleEndian.Uint16(ntHeaderData[20:22]),
			Characteristics:      binary.LittleEndian.Uint16(ntHeaderData[22:24]),
		},
	}

	if image.NTHeaders.FileHeader.SizeOfOptionalHeader == 0xE0 {
		image.NTHeaders.OptionalHeader = &OptionalHeader32{
			Magic:                       binary.LittleEndian.Uint16(ntHeaderData[24:26]),
			MajorLinkerVersion:          *(*uint8)(&ntHeaderData[26]),
			MinorLinkerVersion:          *(*uint8)(&ntHeaderData[27]),
			SizeOfCode:                  binary.LittleEndian.Uint32(ntHeaderData[28:32]),
			SizeOfInitializedData:       binary.LittleEndian.Uint32(ntHeaderData[32:36]),
			SizeOfUninitializedData:     binary.LittleEndian.Uint32(ntHeaderData[36:40]),
			AddressOfEntryPoint:         binary.LittleEndian.Uint32(ntHeaderData[40:44]),
			BaseOfCode:                  binary.LittleEndian.Uint32(ntHeaderData[44:48]),
			BaseOfData:                  binary.LittleEndian.Uint32(ntHeaderData[48:52]),
			ImageBase:                   binary.LittleEndian.Uint32(ntHeaderData[52:56]),
			SectionAlignment:            binary.LittleEndian.Uint32(ntHeaderData[56:60]),
			FileAlignment:               binary.LittleEndian.Uint32(ntHeaderData[60:64]),
			MajorOperatingSystemVersion: binary.LittleEndian.Uint16(ntHeaderData[64:66]),
			MinorOperatingSystemVersion: binary.LittleEndian.Uint16(ntHeaderData[66:68]),
			MajorImageVersion:           binary.LittleEndian.Uint16(ntHeaderData[68:70]),
			MinorImageVersion:           binary.LittleEndian.Uint16(ntHeaderData[70:72]),
			MajorSubsystemVersion:       binary.LittleEndian.Uint16(ntHeaderData[72:74]),
			MinorSubsystemVersion:       binary.LittleEndian.Uint16(ntHeaderData[74:76]),
			Win32VersionValue:           binary.LittleEndian.Uint32(ntHeaderData[76:80]),
			SizeOfImage:                 binary.LittleEndian.Uint32(ntHeaderData[80:84]),
			SizeOfHeaders:               binary.LittleEndian.Uint32(ntHeaderData[84:88]),
			CheckSum:                    binary.LittleEndian.Uint32(ntHeaderData[88:92]),
			Subsystem:                   binary.LittleEndian.Uint16(ntHeaderData[92:94]),
			DllCharacteristics:          binary.LittleEndian.Uint16(ntHeaderData[94:96]),
			SizeOfStackReserve:          binary.LittleEndian.Uint32(ntHeaderData[96:100]),
			SizeOfStackCommit:           binary.LittleEndian.Uint32(ntHeaderData[100:104]),
			SizeOfHeapReserve:           binary.LittleEndian.Uint32(ntHeaderData[104:108]),
			SizeOfHeapCommit:            binary.LittleEndian.Uint32(ntHeaderData[108:112]),
			LoaderFlags:                 binary.LittleEndian.Uint32(ntHeaderData[112:116]),
			NumberOfRvaAndSizes:         binary.LittleEndian.Uint32(ntHeaderData[116:120]),
			DataDirectories: [16]DataDirectory{
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[120:124]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[124:128]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[128:132]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[132:136]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[136:140]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[140:144]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[144:148]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[148:152]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[152:156]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[156:160]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[160:164]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[164:168]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[168:172]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[172:176]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[176:180]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[180:184]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[184:188]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[188:192]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[192:196]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[196:200]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[200:204]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[204:208]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[208:212]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[212:216]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[216:220]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[220:224]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[224:228]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[228:232]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[232:236]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[236:240]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[240:244]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[244:248]),
				},
			},
		}
		sectionData := ntHeaderData[248:]
		for i := 0; i < int(image.NTHeaders.FileHeader.NumberOfSections); i++ {
			sectionData := sectionData[i*40:]
			section := Section{
				Name:             strings.TrimSpace(string(sectionData[0:8])),
				VirtualSize:      binary.LittleEndian.Uint32(sectionData[8:12]),
				VirtualAddress:   binary.LittleEndian.Uint32(sectionData[12:16]),
				RawSize:          binary.LittleEndian.Uint32(sectionData[16:20]),
				RawAddress:       binary.LittleEndian.Uint32(sectionData[20:24]),
				RelocAddress:     binary.LittleEndian.Uint32(sectionData[24:28]),
				LineNumbers:      binary.LittleEndian.Uint32(sectionData[28:32]),
				RelocCount:       binary.LittleEndian.Uint16(sectionData[32:34]),
				LineNumbersCount: binary.LittleEndian.Uint16(sectionData[34:36]),
				Characteristics:  binary.LittleEndian.Uint32(sectionData[36:40]),
			}
			section.Data = data[section.RawAddress : section.RawAddress+section.RawSize]
			image.Sections = append(image.Sections, section)
		}
	} else if image.NTHeaders.FileHeader.SizeOfOptionalHeader == 0xF0 {
		image.NTHeaders.OptionalHeader = &OptionalHeader64{
			Magic:                       binary.LittleEndian.Uint16(ntHeaderData[24:26]),
			MajorLinkerVersion:          *(*uint8)(&ntHeaderData[26]),
			MinorLinkerVersion:          *(*uint8)(&ntHeaderData[27]),
			SizeOfCode:                  binary.LittleEndian.Uint32(ntHeaderData[28:32]),
			SizeOfInitializedData:       binary.LittleEndian.Uint32(ntHeaderData[32:36]),
			SizeOfUninitializedData:     binary.LittleEndian.Uint32(ntHeaderData[36:40]),
			AddressOfEntryPoint:         binary.LittleEndian.Uint32(ntHeaderData[40:44]),
			BaseOfCode:                  binary.LittleEndian.Uint32(ntHeaderData[44:48]),
			ImageBase:                   binary.LittleEndian.Uint64(ntHeaderData[48:56]),
			SectionAlignment:            binary.LittleEndian.Uint32(ntHeaderData[56:60]),
			FileAlignment:               binary.LittleEndian.Uint32(ntHeaderData[60:64]),
			MajorOperatingSystemVersion: binary.LittleEndian.Uint16(ntHeaderData[64:66]),
			MinorOperatingSystemVersion: binary.LittleEndian.Uint16(ntHeaderData[66:68]),
			MajorImageVersion:           binary.LittleEndian.Uint16(ntHeaderData[68:70]),
			MinorImageVersion:           binary.LittleEndian.Uint16(ntHeaderData[70:72]),
			MajorSubsystemVersion:       binary.LittleEndian.Uint16(ntHeaderData[72:74]),
			MinorSubsystemVersion:       binary.LittleEndian.Uint16(ntHeaderData[74:76]),
			Win32VersionValue:           binary.LittleEndian.Uint32(ntHeaderData[76:80]),
			SizeOfImage:                 binary.LittleEndian.Uint32(ntHeaderData[80:84]),
			SizeOfHeaders:               binary.LittleEndian.Uint32(ntHeaderData[84:88]),
			CheckSum:                    binary.LittleEndian.Uint32(ntHeaderData[88:92]),
			Subsystem:                   binary.LittleEndian.Uint16(ntHeaderData[92:94]),
			DllCharacteristics:          binary.LittleEndian.Uint16(ntHeaderData[94:96]),
			SizeOfStackReserve:          binary.LittleEndian.Uint64(ntHeaderData[96:104]),
			SizeOfStackCommit:           binary.LittleEndian.Uint64(ntHeaderData[104:112]),
			SizeOfHeapReserve:           binary.LittleEndian.Uint64(ntHeaderData[112:120]),
			SizeOfHeapCommit:            binary.LittleEndian.Uint64(ntHeaderData[120:128]),
			LoaderFlags:                 binary.LittleEndian.Uint32(ntHeaderData[128:132]),
			NumberOfRvaAndSizes:         binary.LittleEndian.Uint32(ntHeaderData[132:136]),
			DataDirectories: [16]DataDirectory{
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[136:140]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[140:144]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[144:148]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[148:152]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[152:156]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[156:160]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[160:164]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[164:168]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[168:172]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[172:176]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[176:180]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[180:184]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[184:188]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[188:192]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[192:196]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[196:200]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[200:204]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[204:208]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[208:212]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[212:216]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[216:220]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[220:224]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[224:228]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[228:232]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[232:236]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[236:240]),
				},
				{
					VirtualAddress: binary.LittleEndian.Uint32(ntHeaderData[240:244]),
					Size:           binary.LittleEndian.Uint32(ntHeaderData[244:248]),
				},
			},
		}
		sectionData := ntHeaderData[264:]
		for i := 0; i < int(image.NTHeaders.FileHeader.NumberOfSections); i++ {
			sectionData := sectionData[i*40:]
			section := Section{
				Name:             strings.TrimSpace(string(sectionData[0:8])),
				VirtualSize:      binary.LittleEndian.Uint32(sectionData[8:12]),
				VirtualAddress:   binary.LittleEndian.Uint32(sectionData[12:16]),
				RawSize:          binary.LittleEndian.Uint32(sectionData[16:20]),
				RawAddress:       binary.LittleEndian.Uint32(sectionData[20:24]),
				RelocAddress:     binary.LittleEndian.Uint32(sectionData[24:28]),
				LineNumbers:      binary.LittleEndian.Uint32(sectionData[28:32]),
				RelocCount:       binary.LittleEndian.Uint16(sectionData[32:34]),
				LineNumbersCount: binary.LittleEndian.Uint16(sectionData[34:36]),
				Characteristics:  binary.LittleEndian.Uint32(sectionData[36:40]),
			}
			section.Data = data[section.RawAddress : section.RawAddress+section.RawSize]
			image.Sections = append(image.Sections, section)
		}
	}
	return image, nil
}

func (img Image) RvaToOffset(rva uint32) (uint32, []byte) {
	for _, section := range img.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return ((rva - section.VirtualAddress + section.RawAddress) - section.RawAddress), section.Data
		}
	}
	return 0, nil
}

func parseNullTerminatedString(data []byte) (string, error) {
	for i, b := range data {
		if b == 0 {
			return string(data[:i]), nil
		}
	}

	return "", errors.New("no null terminator found")
}

func (img Image) GetExportDirectory() (ExportDirectory, error) {
	var result ExportDirectory
	exportDir := img.NTHeaders.OptionalHeader.GetDataDirectories()[0]
	if exportDir.VirtualAddress == 0 {
		return result, errors.New("export directory not found")
	}

	offset, sectionData := img.RvaToOffset(exportDir.VirtualAddress)
	if sectionData == nil {
		return result, errors.New("export directory not found")
	}

	result = ExportDirectory{
		Characteristics:       binary.LittleEndian.Uint32(sectionData[offset : offset+4]),
		TimeDateStamp:         binary.LittleEndian.Uint32(sectionData[offset+4 : offset+8]),
		MajorVersion:          binary.LittleEndian.Uint16(sectionData[offset+8 : offset+10]),
		MinorVersion:          binary.LittleEndian.Uint16(sectionData[offset+10 : offset+12]),
		Name:                  binary.LittleEndian.Uint32(sectionData[offset+12 : offset+16]),
		Base:                  binary.LittleEndian.Uint32(sectionData[offset+16 : offset+20]),
		NumberOfFunctions:     binary.LittleEndian.Uint32(sectionData[offset+20 : offset+24]),
		NumberOfNames:         binary.LittleEndian.Uint32(sectionData[offset+24 : offset+28]),
		AddressOfFunctions:    binary.LittleEndian.Uint32(sectionData[offset+28 : offset+32]),
		AddressOfNames:        binary.LittleEndian.Uint32(sectionData[offset+32 : offset+36]),
		AddressOfNameOrdinals: binary.LittleEndian.Uint32(sectionData[offset+36 : offset+40]),
	}

	namesTableOffset, _ := img.RvaToOffset(result.AddressOfNames)
	namesTable := sectionData[namesTableOffset:]
	rvaTableOffset, _ := img.RvaToOffset(result.AddressOfFunctions)
	rvaTable := sectionData[rvaTableOffset:]
	for i := 0; i < int(result.NumberOfFunctions); i++ {
		nameOffset := binary.LittleEndian.Uint32(namesTable[i*4 : i*4+4])
		nameOffset, _ = img.RvaToOffset(nameOffset)
		name, err := parseNullTerminatedString(sectionData[nameOffset:])
		if err != nil {
			return result, err
		}

		rva := binary.LittleEndian.Uint32(rvaTable[i*4 : i*4+4])
		result.Exports = append(result.Exports, Export{
			Name: name,
			RVA:  rva,
		})
	}

	return result, nil
}
