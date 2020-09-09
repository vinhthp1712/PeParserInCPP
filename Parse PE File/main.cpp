#include <windows.h>
#include <iostream>

int main(int argc, char* argv[]) {
	const int MAX_FILEPATH = 255;
	char fileName[MAX_FILEPATH] = { 0 };
	memcpy_s(&fileName, MAX_PATH, argv[1], MAX_FILEPATH);
	HANDLE hFile = NULL;
	DWORD fileSize = NULL;
	DWORD byteRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER dosHeader = {};
	PIMAGE_NT_HEADERS64 ntHeader = {};
	PIMAGE_SECTION_HEADER sectionHeader = {};
	PIMAGE_SECTION_HEADER importHeader = {};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
	PIMAGE_THUNK_DATA thunkData = {};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;

	//openfile
	hFile = CreateFileA(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Can not read the file");
	}
	//allocate heap 
	fileSize = GetFileSize(hFile, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

	//readfile
	ReadFile(hFile, fileData, fileSize, &byteRead, NULL);

	//IMAGE_DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;
	printf("******** DOS_HEADER ********\n");
	printf("\t0x%x\tMagic Number\n", dosHeader->e_magic);
	printf("\t0x%x\tBytes on last page of file\n", dosHeader->e_cblp);
	printf("\t0x%x\tPages in file\n", dosHeader->e_cp);
	printf("\t0x%x\tRelocations\n", dosHeader->e_crlc);
	printf("\t0x%x\tSize of header in paragraphs\n", dosHeader->e_cparhdr);
	printf("\t0x%x\tMinimum extra paragraphs needed\n", dosHeader->e_minalloc);
	printf("\t0x%x\tMaximum extra paragraphs needed\n", dosHeader->e_maxalloc);
	printf("\t0x%x\tInitial (relative) SS value\n", dosHeader->e_ss);
	printf("\t0x%x\tInitial SP value\n", dosHeader->e_sp);
	printf("\t0x%x\tChecksum\n", dosHeader->e_csum);
	printf("\t0x%x\tInitial IP value\n", dosHeader->e_ip);
	printf("\t0x%x\tInitial (relative) CS value\n", dosHeader->e_cs);
	printf("\t0x%x\tFile address of relocation table\n", dosHeader->e_lfarlc);
	printf("\t0x%x\tOverlay number\n", dosHeader->e_ovno);
	printf("\t0x%x\tOEM identifier (for e_oeminfo)\n", dosHeader->e_oemid);
	printf("\t0x%x\tOEM information; e_oemid specific\n", dosHeader->e_oeminfo);
	printf("\t0x%x\tFile address of new exe header\n", dosHeader->e_lfanew);

	//IMAGE_NT_HEADER
	//PIMAGE_NT_HEADERS{DWORD Signature;  IMAGE_FILE_HEADER FileHeader;  IMAGE_OPTIONAL_HEADER32 OptionalHeader;}

	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD)fileData + dosHeader->e_lfanew);
	printf("\n******* NT HEADERS *******\n");
	printf("\t%x\t\tSignature\n", ntHeader->Signature);
	
	//IMAGE_FILE_HEADER
	printf("\t0x%x\t\tMachine\n", ntHeader->FileHeader.Machine);
	printf("\t0x%x\t\tNumber of Sections\n", ntHeader->FileHeader.NumberOfSections);
	printf("\t0x%x\tTime Stamp\n", ntHeader->FileHeader.TimeDateStamp);
	printf("\t0x%x\t\tPointer to Symbol Table\n", ntHeader->FileHeader.PointerToSymbolTable);
	printf("\t0x%x\t\tNumber of Symbols\n", ntHeader->FileHeader.NumberOfSymbols);
	printf("\t0x%x\t\tSize of Optional Header\n", ntHeader->FileHeader.SizeOfOptionalHeader);
	printf("\t0x%x\t\tCharacteristics\n", ntHeader->FileHeader.Characteristics);

	//OPTIONAL_HEADER
	printf("\n******* OPTIONAL HEADER *******\n");
	printf("\t0x%x\t\tMagic\n", ntHeader->OptionalHeader.Magic);
	printf("\t0x%x\t\tMajor Linker Version\n", ntHeader->OptionalHeader.MajorLinkerVersion);
	printf("\t0x%x\t\tMinor Linker Version\n", ntHeader->OptionalHeader.MinorLinkerVersion);
	printf("\t0x%x\t\tSize Of Code\n", ntHeader->OptionalHeader.SizeOfCode);
	printf("\t0x%x\t\tSize Of Initialized Data\n", ntHeader->OptionalHeader.SizeOfInitializedData);
	printf("\t0x%x\t\tSize Of UnInitialized Data\n", ntHeader->OptionalHeader.SizeOfUninitializedData);
	printf("\t0x%x\t\tAddress Of Entry Point (.text)\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
	printf("\t0x%x\t\tBase Of Code\n", ntHeader->OptionalHeader.BaseOfCode);
	//printf("\t0x%x\t\tBase Of Data\n", ntHeader->OptionalHeader.BaseOfData);
	printf("\t0x%x\t\tImage Base\n", ntHeader->OptionalHeader.ImageBase);
	printf("\t0x%x\t\tSection Alignment\n", ntHeader->OptionalHeader.SectionAlignment);
	printf("\t0x%x\t\tFile Alignment\n", ntHeader->OptionalHeader.FileAlignment);
	printf("\t0x%x\t\tMajor Operating System Version\n", ntHeader->OptionalHeader.MajorOperatingSystemVersion);
	printf("\t0x%x\t\tMinor Operating System Version\n", ntHeader->OptionalHeader.MinorOperatingSystemVersion);
	printf("\t0x%x\t\tMajor Image Version\n", ntHeader->OptionalHeader.MajorImageVersion);
	printf("\t0x%x\t\tMinor Image Version\n", ntHeader->OptionalHeader.MinorImageVersion);
	printf("\t0x%x\t\tMajor Subsystem Version\n", ntHeader->OptionalHeader.MajorSubsystemVersion);
	printf("\t0x%x\t\tMinor Subsystem Version\n", ntHeader->OptionalHeader.MinorSubsystemVersion);
	printf("\t0x%x\t\tWin32 Version Value\n", ntHeader->OptionalHeader.Win32VersionValue);
	printf("\t0x%x\t\tSize Of Image\n", ntHeader->OptionalHeader.SizeOfImage);
	printf("\t0x%x\t\tSize Of Headers\n", ntHeader->OptionalHeader.SizeOfHeaders);
	printf("\t0x%x\t\tCheckSum\n", ntHeader->OptionalHeader.CheckSum);
	printf("\t0x%x\t\tSubsystem\n", ntHeader->OptionalHeader.Subsystem);
	printf("\t0x%x\t\tDllCharacteristics\n", ntHeader->OptionalHeader.DllCharacteristics);
	printf("\t0x%x\t\tSize Of Stack Reserve\n", ntHeader->OptionalHeader.SizeOfStackReserve);
	printf("\t0x%x\t\tSize Of Stack Commit\n", ntHeader->OptionalHeader.SizeOfStackCommit);
	printf("\t0x%x\t\tSize Of Heap Reserve\n", ntHeader->OptionalHeader.SizeOfHeapReserve);
	printf("\t0x%x\t\tSize Of Heap Commit\n", ntHeader->OptionalHeader.SizeOfHeapCommit);
	printf("\t0x%x\t\tLoader Flags\n", ntHeader->OptionalHeader.LoaderFlags);
	printf("\t0x%x\t\tNumber Of Rva And Sizes\n", ntHeader->OptionalHeader.NumberOfRvaAndSizes);

	// DATA_DIRECTORIES
	printf("\n******** DATA DIRECTORIES *******\n");
	printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress, ntHeader->OptionalHeader.DataDirectory[0].Size);
	printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", ntHeader->OptionalHeader.DataDirectory[1].VirtualAddress, ntHeader->OptionalHeader.DataDirectory[1].Size);

	//SECTION_HEADER
	printf("\n******** SECTION HEADER ********\n");
	DWORD sectionLocate = (DWORD)ntHeader + 4 + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + DWORD(ntHeader->FileHeader.SizeOfOptionalHeader); //pointer to ntheader + signature in ntHeader + image_file_header + IMAGE_OPTIONAL_HEADER
	DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);
	DWORD importDirectoryRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocate;
		printf("\t%s\n", sectionHeader->Name);
		printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
		printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
		printf("\t\t0x%x\t\tSize of Raw Data\n",sectionHeader->SizeOfRawData);
		printf("\t\t0x%x\t\tPointer to Raw Data\n", sectionHeader->PointerToRawData);
		printf("\t\t0x%x\t\tPointer to Relocations\n", sectionHeader->PointerToRelocations);
		printf("\t\t0x%x\t\tPointer to Line Numbers\n", sectionHeader->PointerToLinenumbers);
		printf("\t\t0x%x\t\tNumber of Relocations\n", sectionHeader->NumberOfRelocations);
		printf("\t\t0x%x\t\tNumber of Relocations\n", sectionHeader->NumberOfLinenumbers);
		printf("\t\t0x%x\t\tCharacteristics\n", sectionHeader->Characteristics);
		sectionLocate += sectionSize;
	}

}