#pragma once
#ifndef _PECOFF_WRAPPER_H_
#define _PECOFF_WRAPPER_H_

#include <iostream>
#include <vector>
#include <algorithm>
#include <windows.h> 
#include <cassert>
#include <string>

#include "relocblk.h"

/* buffer-const input PE wrapping */
class Wrapper
{
public:
	Wrapper() = delete;
	const Wrapper(const void* pRaw, size_t length);		/* buffer constant */
	Wrapper(void *pRaw, size_t length) : Wrapper((const void*)pRaw, length) {};
	~Wrapper();	/* this is not responsible for pRaw discard */

public:	/* prevent caching issues */
	Wrapper(const Wrapper&) = delete;
	Wrapper& operator=(const Wrapper&) = delete;

public:
	const void* get() const { return p; }
	size_t length() const { return len; }
	const IMAGE_FILE_HEADER& fileHeader() const { return *pHeader; }
	const IMAGE_OPTIONAL_HEADER& optionalHeader() const { return *pOpHeader; }

public:	/* non-caching version */
	std::vector<std::pair<std::string, uintptr_t>> getExports() const;	/* funcName, RVA */
	std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>> getImports() const;	/* dllname, {name, PointerToFunction(RVA+Base)} / {std::to_string(ordinal), PointerToFunction(RVA+Base)} */ /* call dword [PointerToFunction] */
	std::vector<std::pair<uint32_t, relocBlk>> getRelocations() const;
	std::vector<std::pair<uint32_t, relocBlk>> getRelocations(IMAGE_SECTION_HEADER* pSection) const;	/* get relocations within the given section */

public:	/* caching */
	std::vector<std::pair<std::string, uintptr_t>>& getExports();
	std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>& getImports();	/* dllname, {name, PointerToFunction(RVA+Base)} / {std::to_string(ordinal), PointerToFunction(RVA+Base)} */ /* call dword [PointerToFunction] */
	std::vector<std::pair<uint32_t, relocBlk>>& getRelocations();
	void flush_cache();

public:	/* utility */
	uintptr_t fromRVA(uintptr_t RelativeVirtualAddress) const;
	void* fromRVA(void* RelativeVirtualAddress) const { return (void*)fromRVA((uintptr_t)RelativeVirtualAddress); }
	uintptr_t toRVA(uintptr_t addressInMemory) const;
	void* toRVA(void* addressInMemory) const { return (void*)toRVA((uintptr_t)addressInMemory); }
	IMAGE_SECTION_HEADER* getSectionHeader(unsigned int sectionIndx) const { return pSectionHeader + sectionIndx; }
	IMAGE_SECTION_HEADER* getSectionHeaderByRVA(uintptr_t RelativeVirtualAddress) const { return getSectionHeader(getRVAoffsetFromSectionBase(RelativeVirtualAddress).first); }
	IMAGE_SECTION_HEADER* getSectionHeaderByDataDirectory(uint8_t dataDirectoryType) const { return (pOpHeader->DataDirectory[dataDirectoryType & 0x0f].VirtualAddress == 0) ? nullptr : getSectionHeaderByRVA(pOpHeader->DataDirectory[dataDirectoryType & 0x0f].VirtualAddress); }
	uint32_t imageBase() const { return pOpHeader->ImageBase; }
	size_t nSections() const { return pHeader->NumberOfSections; }

private:	/* cached, release on ~Wrapper */
	std::vector<std::pair<std::string, uintptr_t>>* pvExports = nullptr;
	std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>* pvImports = nullptr;
	std::vector<std::pair<uint32_t, relocBlk>>* pvRelocations = nullptr;

protected:	/* initialized at construction time */
	const void* p = nullptr;
	size_t len;

	IMAGE_DOS_HEADER* pDosHeader = nullptr;
	IMAGE_FILE_HEADER* pHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOpHeader = nullptr;
	IMAGE_SECTION_HEADER* pSectionHeader = nullptr;

	IMAGE_EXPORT_DIRECTORY* pDirExport = nullptr;
	IMAGE_IMPORT_DESCRIPTOR* pDirImport = nullptr;	// zero for terminating import descriptor @ 0x00

protected:	/* utility */
	std::pair<unsigned int, unsigned int> getRVAoffsetFromSectionBase(uintptr_t RelativeVirtualAddress) const;	/* section indx, offset from section-vaddr */

};

#endif
