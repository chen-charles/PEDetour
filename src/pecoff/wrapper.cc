#include "wrapper.h"

Wrapper::Wrapper(const void *pRaw, size_t length)
{
	p = pRaw;
	len = length;

	pDosHeader = (IMAGE_DOS_HEADER*)p;
	pHeader = (IMAGE_FILE_HEADER*)((uintptr_t)p + pDosHeader->e_lfanew + sizeof(uint32_t));

	if (pHeader->SizeOfOptionalHeader != 0)
		pOpHeader = (IMAGE_OPTIONAL_HEADER*)((uintptr_t)pHeader + sizeof(IMAGE_FILE_HEADER));

#ifndef _M_X64
	if (pOpHeader->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) throw;	/* arch != 32 */
#else
	if (pOpHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) throw;
#endif

	pSectionHeader = (IMAGE_SECTION_HEADER*)((uintptr_t)pOpHeader + sizeof(IMAGE_OPTIONAL_HEADER));
	/* pHeader->NumberOfSections */
}

Wrapper::~Wrapper()
{
	/* release cache */
	flush_cache();
}

/* utility */
uintptr_t Wrapper::fromRVA(uintptr_t RelativeVirtualAddress) const
{
	auto pii = getRVAoffsetFromSectionBase(RelativeVirtualAddress);
	return pii.second + (pSectionHeader + pii.first)->PointerToRawData + (uintptr_t)p;
}

uintptr_t Wrapper::toRVA(uintptr_t addressInMemory) const
{
	auto offset = addressInMemory - (uintptr_t)p;
	for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER* pSec = pSectionHeader + i;
		auto vBase = pSec->PointerToRawData;
		auto vEnd = pSec->PointerToRawData + pSec->SizeOfRawData;
		if (vBase <= offset && offset < vEnd)
		{
			return offset + pSec->VirtualAddress - pSec->PointerToRawData;
		}
	}
	throw std::out_of_range("invalid addressInMemory, unable to find a section containing the specified addressInMemory");
}

std::pair<unsigned int, unsigned int> Wrapper::getRVAoffsetFromSectionBase(uintptr_t RelativeVirtualAddress) const
{
	for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER* pSec = pSectionHeader + i;
		/* va <= rva < va+size */
		if (pSec->VirtualAddress <= RelativeVirtualAddress && RelativeVirtualAddress <= pSec->VirtualAddress + (pSec->Misc.VirtualSize == 0 ? pSec->SizeOfRawData : pSec->Misc.VirtualSize))
			return std::make_pair(i, RelativeVirtualAddress - pSec->VirtualAddress);
	}
	throw std::out_of_range("invalid rva, unable to find a section containing the specified rva");
}

std::vector<std::pair<std::string, std::vector<std::pair<std::pair<uint16_t, std::string>, uintptr_t>>*>>& Wrapper::getImports()
{
	if (pvImports == nullptr)
		pvImports = &((const Wrapper*)this)->getImports();
	return *pvImports;
}

std::vector<std::pair<std::string, std::vector<std::pair<std::pair<uint16_t, std::string>, uintptr_t>>*>> Wrapper::getImports() const
{
	IMAGE_IMPORT_DESCRIPTOR* pDirImport;

	if (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
		pDirImport = (IMAGE_IMPORT_DESCRIPTOR*)fromRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	else
		throw std::runtime_error("required field: import dir");

	std::vector<std::pair<std::string, std::vector<std::pair<std::pair<uint16_t, std::string>, uintptr_t>>*>> vImports;
	int i = 0;
	while ((pDirImport + i)->OriginalFirstThunk != 0)
	{
		auto impDesc = pDirImport + i;

		char* pDllName = (char*)fromRVA(impDesc->Name);
		std::string dllName;
		while (*pDllName != 0) dllName += *(pDllName++);

		auto pvFunctions = new std::vector<std::pair<std::pair<uint16_t, std::string>, uintptr_t>>;

		try
		{
			uintptr_t* ppThunk = (uintptr_t*)fromRVA(impDesc->OriginalFirstThunk);
			int j = 0;

			while (*(ppThunk + j) != 0)
			{
				auto pFunc = pOpHeader->ImageBase + impDesc->FirstThunk + j * sizeof(uintptr_t);
#ifdef _M_X64
				if (*(ppThunk + j) & IMAGE_ORDINAL_FLAG64)
				{
					pvFunctions->push_back(std::make_pair(std::make_pair((IMAGE_ORDINAL64(*(ppThunk + j))), ""), pFunc));
				}
#else
				if (*(ppThunk + j) & IMAGE_ORDINAL_FLAG32)
				{
					pvFunctions->push_back(std::make_pair(std::make_pair((IMAGE_ORDINAL32(*(ppThunk + j))), ""), pFunc));
				}
#endif
				else
				{
					char* pName = (char*)fromRVA(*(ppThunk + j));
					uint16_t* pHint = (uint16_t*)pName;
					pName += 2;

					std::string s;
					while (*pName != 0) s += *(pName++);
#ifdef _M_X64
					pvFunctions->push_back(std::make_pair(std::make_pair((IMAGE_ORDINAL64(*(ppThunk + j))), s), pFunc));	/* pointer to address */
#else
					pvFunctions->push_back(std::make_pair(std::make_pair((IMAGE_ORDINAL32(*(ppThunk + j))), s), pFunc));	/* pointer to address */
#endif
					
				}

				j++;
			}

		}
		catch (...)
		{
			;
		}

		vImports.push_back(std::make_pair(dllName, pvFunctions));

		i++;
	}

	return vImports;
}

std::vector<std::pair<std::string, uintptr_t>>& Wrapper::getExports()
{
	if (pvExports == nullptr)
		pvExports = &((const Wrapper*)this)->getExports();
	return *pvExports;
}

std::vector<std::pair<std::string, uintptr_t>> Wrapper::getExports() const
{
	IMAGE_EXPORT_DIRECTORY* pDirExport;

	if (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
		pDirExport = (IMAGE_EXPORT_DIRECTORY*)fromRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	else
		throw std::runtime_error("required field: export dir");

	/* Exports */
	uint32_t* ppNames = (uint32_t*)fromRVA(pDirExport->AddressOfNames);
	uint16_t* pOrdinals = (uint16_t*)fromRVA(pDirExport->AddressOfNameOrdinals);
	uint32_t* pFunctions = (uint32_t*)fromRVA(pDirExport->AddressOfFunctions);

	std::vector<std::pair<std::string, uintptr_t>> vExports;
	for (unsigned int i = 0; i < pDirExport->NumberOfNames; i++)
	{
		char* pName = (char*)fromRVA(*(ppNames + i));
		std::string s;
		while (*pName != 0) s += *(pName++);
		vExports.push_back(make_pair(s, fromRVA(*(pFunctions + *(pOrdinals + i)))));
	}

	return vExports;
}

std::vector<std::pair<uint32_t, relocblk>>& Wrapper::getRelocations()
{
	if (pvRelocations == nullptr)
		pvRelocations = &((const Wrapper*)this)->getRelocations();
	return *pvRelocations;
}

std::vector<std::pair<uint32_t, relocblk>> Wrapper::getRelocations() const
{
	IMAGE_BASE_RELOCATION* pReloc;

	if (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		pReloc = (IMAGE_BASE_RELOCATION*)fromRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	else
		throw std::runtime_error("required field: base relocation");

	std::vector<std::pair<uint32_t, relocblk>> vRelocations;

	while (pReloc->VirtualAddress != 0)
	{
		uint32_t pgRVA = pReloc->VirtualAddress;
		for (auto i = 0; i < (pReloc->SizeOfBlock - 8) / 2; i++)
		{
			uint16_t* ptypeoffset = ((uint16_t*)((uintptr_t)pReloc + 8)) + i;
			assert(sizeof(relocblk) == sizeof(uint16_t));
			vRelocations.push_back(std::make_pair(pgRVA, *(relocblk*)ptypeoffset));
		}

		pReloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)pReloc + pReloc->SizeOfBlock);
	}

	return vRelocations;
}

std::vector<std::pair<uint32_t, relocblk>> Wrapper::getRelocations(IMAGE_SECTION_HEADER* pSection) const
{
	std::vector<std::pair<uint32_t, relocblk>> relocs;
	for (auto pii : getRelocations())
	{
		uint32_t pgRVA = pii.first;
		relocblk blk = pii.second;
		if ((pgRVA + blk.offset >= pSection->VirtualAddress) && (pgRVA + blk.offset < pSection->VirtualAddress + pSection->SizeOfRawData))
			relocs.push_back(pii);
	}
	return relocs;
}

void Wrapper::flush_cache()
{
	if (pvExports != nullptr) delete pvExports;
	if (pvImports != nullptr)
	{
		while (!pvImports->empty())
		{
			auto b = pvImports->back();
			if (b.second != nullptr)
				delete b.second;
			pvImports->pop_back();
		}
		delete pvImports;
	}

	pvExports = nullptr;
	pvImports = nullptr;

	if (pvRelocations != nullptr) delete pvRelocations;
	pvRelocations = nullptr;
}
