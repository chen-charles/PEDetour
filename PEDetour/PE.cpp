/*
PEDetour --- modify binary Portable Executable to hook its export functions
Copyright (C) 2016  Jianye Chen
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "PE.h"

PE::PE()
{
	p = nullptr;
	len = 0;
	pvExports = nullptr;
	pvImports = nullptr;
}

PE::PE(void* pRaw, int length) : PE::PE()
{
	load(pRaw, length);
}

void PE::load(void* pRaw, int length)
{
	if (p != nullptr) delete p;
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

std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>& PE::getImports()
{
	if (pvImports == nullptr && (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0))
	{
		pDirImport = (IMAGE_IMPORT_DESCRIPTOR*)ParseRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		pvImports = new std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>;
		int i = 0;
		while ((pDirImport + i)->OriginalFirstThunk != 0)
		{
			auto impDesc = pDirImport + i;

			char* pDllName = (char*)ParseRVA(impDesc->Name);
			std::string dllName;
			while (*pDllName != 0) dllName += *(pDllName++);

			std::vector<std::pair<std::string, uintptr_t>>* pvFunctions = new std::vector<std::pair<std::string, uintptr_t>>;
			pvImports->push_back(std::make_pair(dllName, pvFunctions));

			try
			{
				uintptr_t* ppThunk = (uintptr_t*)ParseRVA(impDesc->OriginalFirstThunk);
				int j = 0;

				while (*(ppThunk + j) != 0)
				{
#ifdef _M_X64
					if (*(ppThunk + j) & IMAGE_ORDINAL_FLAG64)
					{
						pvFunctions->push_back(std::make_pair("", IMAGE_ORDINAL64(*(ppThunk + j))));
					}
#else
					if (*(ppThunk + j) & IMAGE_ORDINAL_FLAG32) 
					{
						pvFunctions->push_back(std::make_pair("", IMAGE_ORDINAL32(*(ppThunk + j))));
					}
#endif
					else
					{
						char* pName = (char*)ParseRVA(*(ppThunk + j));
						uint16_t* pHint = (uint16_t*)pName;
						pName += 2;

						std::string s;
						while (*pName != 0) s += *(pName++);
						pvFunctions->push_back(std::make_pair(s, pOpHeader->ImageBase + impDesc->FirstThunk + j * sizeof(uintptr_t)));	/* pointer to address */
					}

					j++;
				}

			}
			catch (...)
			{
				;
			}

			i++;
		}
	}
	return *pvImports;
}

std::vector<std::pair<std::string, uintptr_t>>& PE::getExports()
{
	if (pvExports == nullptr && (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0))
	{
		pDirExport = (IMAGE_EXPORT_DIRECTORY*)ParseRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (pDirExport != 0)
		{
			/* Exports */
			uint32_t* ppNames = (uint32_t*)ParseRVA(pDirExport->AddressOfNames);
			uint16_t* pOrdinals = (uint16_t*)ParseRVA(pDirExport->AddressOfNameOrdinals);
			uint32_t* pFunctions = (uint32_t*)ParseRVA(pDirExport->AddressOfFunctions);

			pvExports = new std::vector<std::pair<std::string, uintptr_t>>;
			for (unsigned int i = 0; i < pDirExport->NumberOfNames; i++)
			{
				char* pName = (char*)ParseRVA(*(ppNames + i));
				std::string s;
				while (*pName != 0) s += *(pName++);
				pvExports->push_back(make_pair(s, ParseRVA(*(pFunctions + *(pOrdinals + i)))));
			}
		}
	}
	return *pvExports;
}

uintptr_t PE::changeExportFunctionEntry(std::string functionName, uintptr_t RVAdesiredEntry)	/* return old entry */
{
	if (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
	{
		pDirExport = (IMAGE_EXPORT_DIRECTORY*)ParseRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		/* Exports */
		uint32_t* ppNames = (uint32_t*)ParseRVA(pDirExport->AddressOfNames);
		uint16_t* pOrdinals = (uint16_t*)ParseRVA(pDirExport->AddressOfNameOrdinals);
		uint32_t* pFunctions = (uint32_t*)ParseRVA(pDirExport->AddressOfFunctions);

		for (unsigned int i = 0; i < pDirExport->NumberOfNames; i++)
		{
			char* pName = (char*)ParseRVA(*(ppNames + i));
			std::string s;
			while (*pName != 0) s += *(pName++);
			if (s.compare(functionName) == 0)
			{
				uint32_t orig = *(pFunctions + *(pOrdinals + i));
				*(pFunctions + *(pOrdinals + i)) = RVAdesiredEntry;
				return orig;
			}
		}
	}
	return 0;
}

bool PE::addRelocation(uintptr_t RelativeVirtualAddress)
{
	uintptr_t PageRVA = aligndown(RelativeVirtualAddress, 0x1000);
	uint16_t offsetHIGHLOW = RelativeVirtualAddress - PageRVA;

	bool found = false;
	if (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
	{
		auto pReloc = (IMAGE_BASE_RELOCATION*)ParseRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (pReloc->VirtualAddress != 0)
		{
			if (pReloc->VirtualAddress < PageRVA)
				pReloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)pReloc + pReloc->SizeOfBlock);
			else if (pReloc->VirtualAddress == PageRVA)
			{
				/* if the page already exist */
				for (int i = 0; i < (pReloc->SizeOfBlock - 8) / 2; i++)
				{
					uint16_t* ptypeoffset = ((uint16_t*)((uintptr_t)pReloc + 8)) + i;
					uint8_t type = *ptypeoffset >> 12;
					uint16_t offset = *ptypeoffset & 0x0fff;

					if (offset < offsetHIGHLOW) continue;
					else if (offset == offsetHIGHLOW) return false;	// no modif
					else break;	// need modif
				}

				sectionExtendInPlace(".reloc", sizeof(uint16_t));
				found = true;
				break;
			}
			else
			{
				/* create a header as well */
				sectionExtendInPlace(".reloc", sizeof(IMAGE_BASE_RELOCATION) + sizeof(uint16_t));
				found = true;
				break;
			}
		}

		/* the desired rva is greater than the last entry, append */
		if (!found)
		{
			auto szBlockAligned = align(sizeof(IMAGE_BASE_RELOCATION) + sizeof(uint16_t), sizeof(uint32_t));
			sectionExtendInPlace(".reloc", szBlockAligned);
			char * pData = new char[szBlockAligned];
			memset(pData, 0, szBlockAligned);

			*(uint32_t*)pData = PageRVA;
			*(uint32_t*)(pData + sizeof(uint32_t)) = sizeof(IMAGE_BASE_RELOCATION) + sizeof(uint16_t);
			*(uint16_t*)(pData + 2 * sizeof(uint32_t)) = (IMAGE_REL_BASED_HIGHLOW << 12) + offsetHIGHLOW;

			for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
			{
				const IMAGE_SECTION_HEADER* pSec = pSectionHeader + i;
				if (std::string((const char*)pSec->Name).compare(".reloc") == 0)
				{
					int desiredEntryPosition = pSec->Misc.VirtualSize - szBlockAligned + pSec->VirtualAddress;
					memcpy((void*)ParseRVA(desiredEntryPosition), pData, szBlockAligned);
					return true;
				}
			}

			throw;
		}
	}

	if (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
	{
		auto pReloc = (IMAGE_BASE_RELOCATION*)ParseRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (pReloc->VirtualAddress != 0)
		{
			if (pReloc->VirtualAddress < PageRVA)
				pReloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)pReloc + pReloc->SizeOfBlock);
			else if (pReloc->VirtualAddress == PageRVA)
			{
				/* if the page already exist*/

				/* check if the last entry is 0 (padding) */
				if (*(uint16_t*)((uintptr_t)pReloc + pReloc->SizeOfBlock - 2) == 0)
				{
					//pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeof(uint16_t);
					// move everything in this entry back
					uint16_t* pData = nullptr;
					for (int i = 0; i < (pReloc->SizeOfBlock - 8) / 2; i++)
					{
						uint16_t* ptypeoffset = ((uint16_t*)((uintptr_t)pReloc + 8)) + i;
						uint8_t type = *ptypeoffset >> 12;
						uint16_t offset = *ptypeoffset & 0x0fff;

						if (offset < offsetHIGHLOW) continue;
						else // greater (equal eliminated)
						{
							pData = ptypeoffset;
							break;
						}
					}

					if (pData == nullptr)
					{
						pData = (uint16_t*)((uintptr_t)pReloc + pReloc->SizeOfBlock - 2);
					}
					else
					{
						// pReloc+pReloc->SizeOfBlock-pData
						// 0		1		2		3		4
						// pReloc   4		xx		0		pReloc+pReloc->SizeOfBlock
						memmove(pData + 1, pData, (uintptr_t)pReloc + pReloc->SizeOfBlock - (uintptr_t)pData);
					}

					*pData = (
#ifndef _M_X64
						IMAGE_REL_BASED_HIGHLOW
#else
						IMAGE_REL_BASED_DIR64
#endif
						<< 12) + offsetHIGHLOW;
					return true;
				}
				else
				{
					pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeof(uint32_t);
					std::vector<std::pair<uint16_t, uint8_t>> vOffsets;
					for (int i = 0; i < (pReloc->SizeOfBlock - 8) / 2; i++)
					{
						uint16_t* ptypeoffset = ((uint16_t*)((uintptr_t)pReloc + 8)) + i;
						uint8_t type = *ptypeoffset >> 12;
						uint16_t offset = *ptypeoffset & 0x0fff;

						vOffsets.push_back(std::make_pair(offset, type));
					}
					vOffsets.push_back(std::make_pair(offsetHIGHLOW, 
#ifndef _M_X64
						IMAGE_REL_BASED_HIGHLOW
#else
						IMAGE_REL_BASED_DIR64
#endif
					));
					std::sort(vOffsets.begin(), vOffsets.end());
					vOffsets.push_back(std::make_pair(0, 0));

					auto pTemp = (IMAGE_BASE_RELOCATION*)((uintptr_t)pReloc + pReloc->SizeOfBlock);
					int sizeToMove = 0;
					while (pTemp->VirtualAddress != 0)
					{
						sizeToMove += pTemp->SizeOfBlock;
						pTemp = (IMAGE_BASE_RELOCATION*)((uintptr_t)pTemp + pTemp->SizeOfBlock);
					}
					memmove((void*)((uintptr_t)pReloc + pReloc->SizeOfBlock + 4), (void*)((uintptr_t)pReloc + pReloc->SizeOfBlock), sizeToMove);

					char* pData = (char*)pReloc;
					*(uint32_t*)pData = PageRVA;
					*(uint32_t*)(pData + sizeof(uint32_t)) = 2 * sizeof(uint32_t) + 2 * vOffsets.size();
					uint16_t* pEntry = (uint16_t*)(pData + 8);
					for (auto i : vOffsets)
					{
						*(pEntry++) = (i.second << 12) + i.first;
					}

					return true;
				}
			}
			else
			{
				/* query size to move */
				int sizeToMove = 0;
				auto pTemp = pReloc;
				while (pTemp->VirtualAddress != 0)
				{
					sizeToMove += pTemp->SizeOfBlock;
					pTemp = (IMAGE_BASE_RELOCATION*)((uintptr_t)pTemp + pTemp->SizeOfBlock);
				}

				/* align 32 bit boundary */
				auto szBlockAligned = align(sizeof(IMAGE_BASE_RELOCATION) + sizeof(uint16_t), sizeof(uint32_t));
				pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += szBlockAligned;
				memmove((void*)((uintptr_t)pReloc + szBlockAligned), (void*)pReloc, sizeToMove);
				memset((void*)pReloc, 0, szBlockAligned);

				/* create a header as well */
				char* pData = (char*)pReloc;
				*(uint32_t*)pData = PageRVA;
				*(uint32_t*)(pData + sizeof(uint32_t)) = szBlockAligned;
				*(uint16_t*)(pData + 2 * sizeof(uint32_t)) = (
#ifndef _M_X64
					IMAGE_REL_BASED_HIGHLOW
#else
					IMAGE_REL_BASED_DIR64
#endif
					<< 12) + offsetHIGHLOW;

				return true;
			}
		}
	}
}

bool PE::addImport(std::string dll, std::string functionName)
{
	std::transform(dll.begin(), dll.end(), dll.begin(), ::tolower);
	bool dllExist = false;
	auto vImports = getImports();
	for (auto i : vImports)
	{
		std::transform(i.first.begin(), i.first.end(), i.first.begin(), ::tolower);
		if (i.first.compare(dll) == 0)
		{
			dllExist = true;
			for (auto j : *i.second)
			{
				if (j.first.compare(functionName) == 0)
					return true;
			}
			i.second->push_back(std::make_pair(functionName, 0));
			break;
		}
	}

	if (!dllExist)
	{
		vImports.push_back(std::make_pair(dll, new std::vector<std::pair<std::string, uintptr_t>>));
		vImports.back().second->push_back(std::make_pair(functionName, 0));
	}

	// since the location of the import tables can be anywhere
	// extending the section and add entries in place will mess up all the address after the table
	// therefore, we can do a reconstruct at the end of the current section
	// we need to fix relocations due to the IAT shift

	int spacesNeeded = (vImports.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 1000;
	for (auto i : vImports)
	{
		spacesNeeded += i.first.length() + 1;
		for (auto j : *i.second)
		{
			// ILT && IAT -> * 2
			spacesNeeded += sizeof(uintptr_t) * 2;

			if (j.first.length() == 0)	// by ordinal
			{
				
			}
			else
			{
				spacesNeeded += align(2 + j.first.length() + 1, 2);
			}
		}
		spacesNeeded += sizeof(uintptr_t) * 2;	// ILT end signal
	}

	sectionExtendInPlace(ParseCString(getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->Name), spacesNeeded);
	IMAGE_IMPORT_DESCRIPTOR* pDesc = (IMAGE_IMPORT_DESCRIPTOR*)ParseRVA(getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->Misc.VirtualSize - spacesNeeded + getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);
	memset((void*)pDesc, 0, spacesNeeded);

	uintptr_t* pILT = (uintptr_t*)((uintptr_t)pDesc + (dllExist ? pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size : (vImports.size() + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
	
	for (auto i : vImports)
	{
		pDesc->OriginalFirstThunk = (uintptr_t)toRVA(pILT);
		pDesc->FirstThunk = 0;
		for (auto j : *i.second)
		{
			*(pILT++) = j.first.length() == 0 ?
#ifdef _M_X64
				IMAGE_ORDINAL_FLAG64
#else
				IMAGE_ORDINAL_FLAG32
#endif
				| j.second : 0x19000;
		}
		*(pILT++) = 0;

		pDesc++;
	}

	pDesc++;	// terminating null desc

	void* pEntryData = (void*)pILT;	// hint name table with dll name entries
	pDesc = (IMAGE_IMPORT_DESCRIPTOR*)ParseRVA(getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->Misc.VirtualSize - spacesNeeded + getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);	// reset pDesc
#define advanceVoidPtr(pVoid, nBytes) pVoid = (void*)((uintptr_t)pVoid + nBytes)
	for (auto i : vImports)
	{
		memcpy(pEntryData, i.first.c_str(), i.first.length() + 1);
		pDesc->Name = (uint32_t)toRVA(pEntryData);
		advanceVoidPtr(pEntryData, i.first.length() + 1);

		uintptr_t* ppThunk = (uintptr_t*)ParseRVA(pDesc->OriginalFirstThunk);
		int j = 0;

		while (*(ppThunk + j) != 0)
		{
			if (*(ppThunk + j) &
#ifdef _M_X64
				IMAGE_ORDINAL_FLAG64
#else
				IMAGE_ORDINAL_FLAG32
#endif
				)
			{
				// pass
			}
			else
			{
				*(ppThunk+j) = toRVA((uintptr_t)pEntryData);
				*((uint16_t*)pEntryData) = 1;	// Hint, invalid value
				advanceVoidPtr(pEntryData, 2);
				memcpy(pEntryData, i.second->at(j).first.c_str(), i.second->at(j).first.length() + 1);
				advanceVoidPtr(pEntryData, i.second->at(j).first.length() + 1);
				if (toRVA((uintptr_t)pEntryData) % 2)	// odd? align to even
					advanceVoidPtr(pEntryData, 1);
			}

			j++;
		}
		*(uintptr_t*)(pEntryData) = 0;
		advanceVoidPtr(pEntryData, sizeof(uintptr_t));
		pDesc++;
	}

	uintptr_t IATRVA = toRVA((uintptr_t)pEntryData);
	pDesc = (IMAGE_IMPORT_DESCRIPTOR*)ParseRVA(getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->Misc.VirtualSize - spacesNeeded + getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);	// reset pDesc
	for (auto i : vImports)
	{
		uintptr_t* ppThunk = (uintptr_t*)ParseRVA(pDesc->OriginalFirstThunk);
		pDesc->FirstThunk = (uint32_t)toRVA(pEntryData);
		int j = 0;
		while (*(ppThunk + j) != 0)
		{
			*(uintptr_t*)(pEntryData) = *(ppThunk + j);
			advanceVoidPtr(pEntryData, sizeof(uintptr_t));
			j++;
		}
		*(uintptr_t*)(pEntryData) = 0;
		advanceVoidPtr(pEntryData, sizeof(uintptr_t));
		//for (int k = 0; k < 15; k++)
		//{
		//	*(uintptr_t*)(pEntryData) = *(ppThunk + j);
		//	advanceVoidPtr(pEntryData, sizeof(uintptr_t));
		//}
		pDesc++;
	}

	pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->Misc.VirtualSize - spacesNeeded + getSectionHeaderByDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress;
	pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += (dllExist ? 0 : sizeof(IMAGE_IMPORT_DESCRIPTOR));
	pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = (uint32_t)IATRVA;
	pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = (uint32_t)(toRVA((uintptr_t)pEntryData) - IATRVA);

	//std::ofstream ofs("a.dll", std::ofstream::out | std::ofstream::binary);
	//ofs.write((char*)p, len);
	//ofs.close();


	pvImports = nullptr;
	auto newImports = getImports();

#ifndef _M_X64
	/* fix relocations */
	if (pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
	{
		auto pReloc = (IMAGE_BASE_RELOCATION*)ParseRVA(pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (pReloc->VirtualAddress != 0)
		{
			for (unsigned int i = 0; i < (pReloc->SizeOfBlock - 8) / 2; i++)
			{
				uint16_t* ptypeoffset = ((uint16_t*)((uintptr_t)pReloc + 8)) + i;
				uint8_t type = *ptypeoffset >> 12;
				uint16_t offset = *ptypeoffset & 0x0fff;

				if (type == IMAGE_REL_BASED_HIGHLOW && *(uintptr_t*)(ParseRVA(pReloc->VirtualAddress + offset)) - pOpHeader->ImageBase != 0)
				{
					for (int i = 0; i < vImports.size(); i++)
					{
						for (int j = 0; j < vImports[i].second->size(); j++)
						{
							if (vImports[i].second->at(j).second == *(uintptr_t*)(ParseRVA(pReloc->VirtualAddress + offset)))
							{
								*(uintptr_t*)(ParseRVA(pReloc->VirtualAddress + offset)) = newImports[i].second->at(j).second;
							}
						}
					}
				}
			}

			pReloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)pReloc + pReloc->SizeOfBlock);
		}
	}
#else

	/* scan code section && fix offset in  "call qword ptr [rip + offset]"/"jmp qword ptr [rip + offset]" : ff 15/25 xx xx xx xx */
	for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
	{
		const IMAGE_SECTION_HEADER* pSec = pSectionHeader + i;
		if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			x64FixImports fixImports(pSec, this, vImports, newImports);
			fixImports.process((char*)ParseRVA(pSec->VirtualAddress), pSec->SizeOfRawData);
		}
	}

#endif

	return true;
}

PE::~PE()
{
	//if (p != nullptr) delete p;
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
}

uintptr_t PE::ParseRVA(uintptr_t RelativeVirtualAddress) const
{
	auto pii = getRVAoffsetFromSectionBase(RelativeVirtualAddress);
	return pii.second + (pSectionHeader + pii.first)->PointerToRawData + (uintptr_t)p;
}

std::pair<unsigned int, unsigned int> PE::getRVAoffsetFromSectionBase(uintptr_t RelativeVirtualAddress) const
{
	for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER* pSec = pSectionHeader + i;
		/* va <= rva < va+size */
		if (pSec->VirtualAddress <= RelativeVirtualAddress && RelativeVirtualAddress <= pSec->VirtualAddress + (pSec->Misc.VirtualSize == 0 ? pSec->SizeOfRawData : pSec->Misc.VirtualSize))
			return std::make_pair(i, RelativeVirtualAddress - pSec->VirtualAddress);
	}
	throw std::exception("invalid rva, unable to find a section containing the specified rva");
}

uintptr_t PE::toRVA(uintptr_t addressInMemory) const
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
	throw std::exception("invalid addressInMemory, unable to find a section containing the specified addressInMemory");
}

uintptr_t PE::patchRVA(uintptr_t RelativeVirtualAddress, PE& target)
{
	auto pii = getRVAoffsetFromSectionBase(RelativeVirtualAddress);
	auto sectionIndex = pii.first;
	auto offsetFromSectionBase = pii.second;
	return (target.pSectionHeader + sectionIndex)->VirtualAddress + offsetFromSectionBase;
}

void PE::sectionExtendInPlace(std::string name, unsigned int deltaSize)
{
	void* ptr;
	size_t sz = sectionExtend(name, deltaSize, &ptr);
	load(ptr, sz);
}

size_t PE::sectionExtend(std::string name, unsigned int deltaSize, void** output)
{
	void* buf = nullptr;

	/* calculate final file size */
	for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
	{
		const IMAGE_SECTION_HEADER* pSec = pSectionHeader + i;
		if (std::string((const char*)pSec->Name).compare(name) == 0)
		{
			deltaSize = align((pSec->SizeOfRawData + deltaSize), pOpHeader->FileAlignment) - pSec->SizeOfRawData;
			//buf = new buffer(len + deltaSize);
			buf = new unsigned char[len + deltaSize];
			break;
		}
	}

	if (buf == nullptr) throw std::exception("section specified does not exist");

	memcpy((void*)buf, (void*)p, (uintptr_t)pSectionHeader - (uintptr_t)p);

	uintptr_t pNewSecHeader = (uintptr_t)buf + (uintptr_t)pSectionHeader - (uintptr_t)p;

	for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
	{
		const IMAGE_SECTION_HEADER* pSec = pSectionHeader + i;
		IMAGE_SECTION_HEADER* pNewSec = (IMAGE_SECTION_HEADER*)pNewSecHeader + i;
		*pNewSec = *pSec;

		if (std::string((const char*)pSec->Name).compare(name) == 0)
		{
			memcpy((void*)(pNewSec->PointerToRawData + (uintptr_t)buf), (void*)(pSec->PointerToRawData + (uintptr_t)p), pSec->SizeOfRawData);
			memset((void*)(pNewSec->PointerToRawData + (uintptr_t)buf + pSec->SizeOfRawData), 0xCC, deltaSize);
			pNewSec->SizeOfRawData += deltaSize;
			pNewSec->Misc.VirtualSize += deltaSize;
			
			/* now, fix the rest sections (and their data could now be copied into the new PE) */
			for (unsigned int j = i + 1; j < pHeader->NumberOfSections; j++)
			{
				pSec = pSectionHeader + j;
				pNewSec = (IMAGE_SECTION_HEADER*)pNewSecHeader + j;
				*pNewSec = *pSec;

				pNewSec->VirtualAddress = align((pNewSec - 1)->VirtualAddress + (pNewSec - 1)->Misc.VirtualSize, pOpHeader->SectionAlignment);
				pNewSec->PointerToRawData += deltaSize;
				memcpy((void*)(pNewSec->PointerToRawData + (uintptr_t)buf), (void*)(pSec->PointerToRawData + (uintptr_t)p), pSec->SizeOfRawData);
			}

			break;
		}
		else
		{
			/* before the desired section header, simply copy the original header */
			/* copy the data into the new PE */
			memcpy((void*)(pNewSec->PointerToRawData + (uintptr_t)buf), (void*)(pSec->PointerToRawData + (uintptr_t)p), pSec->SizeOfRawData);
		}
	}

	/* get PE object */
	PE newPE(buf, len+deltaSize);

#pragma region 	/* fix optional header */
	newPE.pOpHeader->SizeOfCode = 0;
	newPE.pOpHeader->SizeOfInitializedData = 0;
	newPE.pOpHeader->SizeOfUninitializedData = 0;
	newPE.pOpHeader->BaseOfCode = 0;

#ifndef _M_X64
	newPE.pOpHeader->BaseOfData = 0;
#endif

	newPE.pOpHeader->SizeOfImage = 0;
	int SizeOfRawData_LastSection;

	for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
	{
		const IMAGE_SECTION_HEADER* pSec = (IMAGE_SECTION_HEADER*)pNewSecHeader + i;
		if (pSec->Characteristics & IMAGE_SCN_CNT_CODE)
		{
			newPE.pOpHeader->SizeOfCode += pSec->SizeOfRawData;
			if (newPE.pOpHeader->BaseOfCode == 0) newPE.pOpHeader->BaseOfCode = pSec->VirtualAddress;
		}

		if (pSec->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
		{
			newPE.pOpHeader->SizeOfInitializedData += pSec->SizeOfRawData;
#ifndef _M_X64
			if (newPE.pOpHeader->BaseOfData == 0) newPE.pOpHeader->BaseOfData = pSec->VirtualAddress;
#endif
		}
		if (pSec->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
		{
			newPE.pOpHeader->SizeOfUninitializedData += pSec->SizeOfRawData;
#ifndef _M_X64
			if (newPE.pOpHeader->BaseOfData == 0) newPE.pOpHeader->BaseOfData = pSec->VirtualAddress;
#endif
		}

		/* search for last section */
		if (pSec->VirtualAddress > newPE.pOpHeader->SizeOfImage)
		{
			newPE.pOpHeader->SizeOfImage = pSec->VirtualAddress;
			SizeOfRawData_LastSection = pSec->SizeOfRawData;
		}
	}

	newPE.pOpHeader->SizeOfImage = align(newPE.pOpHeader->SizeOfImage + SizeOfRawData_LastSection, pOpHeader->SectionAlignment);

	/* fix EP */
	newPE.pOpHeader->AddressOfEntryPoint = patchRVA(pOpHeader->AddressOfEntryPoint, newPE);

	/* fix Data Directory RVAs */
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		auto pDirEntry = &(newPE.pOpHeader->DataDirectory[i]);
		if (pDirEntry->Size != 0)
		{
			pDirEntry->VirtualAddress = patchRVA(pDirEntry->VirtualAddress, newPE);	// the original vaddr -> the original offset
		}
	}
#pragma endregion

	// CheckSum --- it is ok to leave it zero, but you can calculate it through the alg. here: https://www.codeproject.com/Articles/19326/An-Analysis-of-the-Windows-PE-Checksum-Algorithm
	// Or use the PEChecksum program included there to update it
	// Or make it zero to bypass the loader check

	newPE.pOpHeader->CheckSum = 0;


	/*
	Remain unFixed
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
	*/

	/* fix exports */
	if (newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
	{
		newPE.pDirExport = (IMAGE_EXPORT_DIRECTORY*)newPE.ParseRVA(newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		newPE.pDirExport->AddressOfNames = patchRVA(newPE.pDirExport->AddressOfNames, newPE);
		newPE.pDirExport->AddressOfNameOrdinals = patchRVA(newPE.pDirExport->AddressOfNameOrdinals, newPE);
		newPE.pDirExport->AddressOfFunctions = patchRVA(newPE.pDirExport->AddressOfFunctions, newPE);
		newPE.pDirExport->Name = patchRVA(newPE.pDirExport->Name, newPE);

		uint32_t* ppNames = (uint32_t*)newPE.ParseRVA(newPE.pDirExport->AddressOfNames);
		uint16_t* pOrdinals = (uint16_t*)newPE.ParseRVA(newPE.pDirExport->AddressOfNameOrdinals);
		uint32_t* pFunctions = (uint32_t*)newPE.ParseRVA(newPE.pDirExport->AddressOfFunctions);

		for (unsigned int i = 0; i < newPE.pDirExport->NumberOfNames; i++)
		{
			*(ppNames + i) = patchRVA(*(ppNames + i), newPE);
			*(pFunctions + *(pOrdinals + i)) = patchRVA(*(pFunctions + *(pOrdinals + i)), newPE);
		}
	}

	/* fix imports */
	if (newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0)
	{
		newPE.pDirImport = (IMAGE_IMPORT_DESCRIPTOR*)newPE.ParseRVA(newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		int i = 0;
		while ((newPE.pDirImport + i)->OriginalFirstThunk != 0)
		{
			auto impDesc = newPE.pDirImport + i;

			impDesc->Name = patchRVA(impDesc->Name, newPE);
			impDesc->OriginalFirstThunk = patchRVA(impDesc->OriginalFirstThunk, newPE);
			impDesc->FirstThunk = patchRVA(impDesc->FirstThunk, newPE);

			try
			{
				uintptr_t* ppFirstThunk = (uintptr_t*)newPE.ParseRVA(impDesc->FirstThunk);
				uintptr_t* ppThunk = (uintptr_t*)newPE.ParseRVA(impDesc->OriginalFirstThunk);
				int j = 0;
				while (*(ppThunk + j) != 0)
				{
					*(ppThunk + j) = patchRVA(*(ppThunk + j), newPE);
					*(ppFirstThunk + j) = *(ppThunk + j);
					j++;
				}
			}
			catch (...)
			{
				;
			}
			
			i++;
		}
	}

	/* fix relocations */
	if (newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
	{
		auto pReloc = (IMAGE_BASE_RELOCATION*)newPE.ParseRVA(newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (pReloc->VirtualAddress != 0)
		{
			pReloc->VirtualAddress = patchRVA(pReloc->VirtualAddress, newPE);

			for (unsigned int i = 0; i < (pReloc->SizeOfBlock - 8) / 2; i++)
			{
				uint16_t* ptypeoffset = ((uint16_t*)((uintptr_t)pReloc + 8)) + i;
				uint8_t type = *ptypeoffset >> 12;
				uint16_t offset = *ptypeoffset & 0x0fff;

				if (type == 
#ifndef _M_X64
					IMAGE_REL_BASED_HIGHLOW
#else
					IMAGE_REL_BASED_DIR64
#endif
					&& *(uintptr_t*)(newPE.ParseRVA(pReloc->VirtualAddress + offset)) - pOpHeader->ImageBase != 0)
				try
				{
					*(uintptr_t*)(newPE.ParseRVA(pReloc->VirtualAddress + offset)) = patchRVA(*(uintptr_t*)(newPE.ParseRVA(pReloc->VirtualAddress + offset)) - pOpHeader->ImageBase, newPE) + pOpHeader->ImageBase;
				}
				catch (...)
				{
					//throw;
				}
			}

			pReloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)pReloc + pReloc->SizeOfBlock);
		}
	}

#ifdef _M_X64
	/* scan code section && fix offset in  "call qword ptr [rip + offset]"/"jmp qword ptr [rip + offset]" : ff 15/25 xx xx xx xx */
	for (unsigned int i = 0; i < newPE.pHeader->NumberOfSections; i++)
	{
		const IMAGE_SECTION_HEADER* pSec = newPE.pSectionHeader + i;
		if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			x64FixRIPReloc ripfix(pSec, this, &newPE);
			ripfix.process((char*)newPE.ParseRVA(pSec->VirtualAddress), pSec->SizeOfRawData);
		}
	}
#endif

	/* fix resources */
	patchResources((IMAGE_RESOURCE_DIRECTORY*)-1, newPE);

	newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
	newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;

	/* fix debug infos */
	newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	////if (newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0)
	////{
	////	auto pDebug = (IMAGE_DEBUG_DIRECTORY*)newPE.ParseRVA(newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
	////	for (int i = 0; i < newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
	////	{
	////		(pDebug + i)->AddressOfRawData = patchRVA(pDebug->AddressOfRawData, newPE);
	////	}
	////}

	/* fix load config */
	newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
	newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
	if (newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != 0)
	{
		auto pCfg = (IMAGE_LOAD_CONFIG_DIRECTORY*)newPE.ParseRVA(newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
		pCfg->SecurityCookie = patchRVA(pCfg->SecurityCookie - pOpHeader->ImageBase, newPE) + pOpHeader->ImageBase;
		pCfg->GuardCFCheckFunctionPointer = patchRVA(pCfg->GuardCFCheckFunctionPointer - pOpHeader->ImageBase, newPE) + pOpHeader->ImageBase;
		pCfg->GuardCFDispatchFunctionPointer = patchRVA(pCfg->GuardCFDispatchFunctionPointer - pOpHeader->ImageBase, newPE) + pOpHeader->ImageBase;
	}

	/* fix exception */
	if (newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress != 0)
	{
#ifdef _M_X64
		auto pExp = (IMAGE_RUNTIME_FUNCTION_ENTRY*)newPE.ParseRVA(newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
		while (pExp->BeginAddress != 0)
		{
			pExp->BeginAddress = patchRVA(pExp->BeginAddress, newPE);
			pExp->EndAddress = patchRVA(pExp->EndAddress, newPE);
			pExp->UnwindData = patchRVA(pExp->UnwindData, newPE);
			auto unwind = (llvm::Win64EH::UnwindInfo*)newPE.ParseRVA(pExp->UnwindData);
			if (unwind->flags & llvm::Win64EH::UNW_ExceptionHandler || unwind->flags & llvm::Win64EH::UNW_TerminateHandler)
			{
				*(unsigned long*)((uintptr_t)unwind + 4 + 2 * align(unwind->numCodes, 2)) = patchRVA(*(unsigned long*)((uintptr_t)unwind + 4 + 2 * align(unwind->numCodes, 2)), newPE);
			}
			else if (unwind->flags & llvm::Win64EH::UNW_ChainInfo)
			{

			}
			else
			{
				; // pass
			}

			pExp++;
		}
#else
		newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0;
		newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0;
#endif
	}
	newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0;
	newPE.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0;

	*output = buf;
	return len + deltaSize;
	load(buf, len + deltaSize);
}

void PE::patchResources(IMAGE_RESOURCE_DIRECTORY* pResDir, PE& target)
{
	if (target.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != 0)
	{
		auto pResBase = (IMAGE_RESOURCE_DIRECTORY*)target.ParseRVA(target.pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
		if ((int)pResDir == -1) pResDir = pResBase;

		int nRes = pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries;
		auto pResDirEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((uintptr_t)pResDir + sizeof(IMAGE_RESOURCE_DIRECTORY));
		for (int i = 0; i < nRes; i++)
		{
			auto pResCurDirEntry = pResDirEntry + i;
			if (pResCurDirEntry->DataIsDirectory)
			{
				patchResources((IMAGE_RESOURCE_DIRECTORY*)(pResCurDirEntry->OffsetToDirectory + (uintptr_t)pResBase), target);
			}
			else
			{
				auto pResData = (IMAGE_RESOURCE_DATA_ENTRY*)(pResCurDirEntry->OffsetToDirectory + (uintptr_t)pResBase);
				pResData->OffsetToData = patchRVA(pResData->OffsetToData, target);
			}
		}

	}
}

/* 
import relocations: 
addrOfInstruction(in injectionFunction)	// note: x86arch max inst. = 15 bytes
desiredImportFunctionName

note:
if the relocated instruction length does not match the original length, an exception will be thrown.
*this will happen when the generated instruction is at an improper length

note on x86_64:
impRelocations throws an exception if the instruction is RIP based

*/
std::pair<uint32_t, uint32_t> PE::injectFunction(std::string originalFunctionName, const char* injectionFunction, unsigned int injectionSize)
{
	sectionExtendInPlace(".text", injectionSize);
	for (unsigned int i = 0; i < pHeader->NumberOfSections; i++)
	{
		const IMAGE_SECTION_HEADER* pSec = pSectionHeader + i;
		if (std::string((const char*)pSec->Name).compare(".text") == 0)
		{
			int desiredEntryPosition = pSec->Misc.VirtualSize - injectionSize + pSec->VirtualAddress;
			memcpy((void*)ParseRVA(desiredEntryPosition), injectionFunction, injectionSize);
			return std::make_pair(desiredEntryPosition, changeExportFunctionEntry(originalFunctionName, desiredEntryPosition));
		}
	}
}

std::pair<uint32_t, uint32_t> PE::injectFunction(std::string originalFunctionName, std::string strCode)
{
#ifndef _M_X64
	KeystoneAssembler assembler(KS_ARCH_X86, KS_MODE_32);
#else
	KeystoneAssembler assembler(KS_ARCH_X86, KS_MODE_64);
#endif
	/* remove comments*/
	strCode = std::regex_replace(strCode, std::regex("/\\*[^*]*\\*+(?:[^/*][^*]*\\*+)*/"), "");
	strCode = std::regex_replace(strCode, std::regex("[/]+.*"), "");
	strCode = std::regex_replace(strCode, std::regex("\r\n"), "\n");

	/* prepare mapping table */
	std::unordered_map<std::string, uintptr_t> impMap;
	for (auto i : getImports())
	{
		std::transform(i.first.begin(), i.first.end(), i.first.begin(), ::tolower);
		for (auto j : *i.second)
		{
			impMap[i.first + "::" + j.first] = j.second;
			//std::cout << i.first + "::" + j.first << "\t" << std::hex << impMap[i.first + "::" + j.first] << std::endl;
		}
	}

	std::vector<std::pair<unsigned char*, size_t>> vLinesCompiled;
	uint32_t curOffset = 0;
	for (auto i : split(strCode, '\n'))
	{
		if (i.length() != 0)
		{
			for (auto psi : impMap)
			{
				if (i.find(psi.first) != std::string::npos)
				{
					i = i.replace(i.find(psi.first), psi.first.length(), std::to_string(psi.second));
					break;
				}
			}
			unsigned char* line_compiled;
			auto szCompiled = assembler.process(i.c_str(), &line_compiled);
			if (szCompiled != 0) vLinesCompiled.push_back(std::make_pair(line_compiled, szCompiled));
			curOffset += szCompiled;
		}
	}

	// curOffset size calculated
	void *pExt;
	auto szExt = sectionExtend(".text", curOffset, &pExt);
	PE newPE(pExt, szExt);

	/* prepare mapping table */
	impMap.clear();
	for (auto i : newPE.getImports())
	{
		std::transform(i.first.begin(), i.first.end(), i.first.begin(), ::tolower);
		for (auto j : *i.second)
		{
			impMap[i.first + "::" + j.first] = j.second;
			//std::cout << i.first + "::" + j.first << "\t" << std::hex << impMap[i.first + "::" + j.first] << std::endl;
		}
	}
	for (auto ppi : vLinesCompiled)
		delete ppi.first;
	vLinesCompiled.clear();
	curOffset = 0;
	std::vector<uint32_t> vRelocations;
	for (auto i : split(strCode, '\n'))
	{
		if (i.length() != 0)
		{
			for (auto psi : impMap)
			{
				if (i.find(psi.first) != std::string::npos)
				{
					i = i.replace(i.find(psi.first), psi.first.length(), std::to_string(psi.second));
					vRelocations.push_back(curOffset);
					break;
				}
			}
			unsigned char* line_compiled;
			auto szCompiled = assembler.process(i.c_str(), &line_compiled);
			if (szCompiled != 0) vLinesCompiled.push_back(std::make_pair(line_compiled, szCompiled));
			curOffset += szCompiled;
		}
	}

	unsigned char* compiled = new unsigned char[curOffset];
	curOffset = 0;
	for (auto i : vLinesCompiled)
	{
		memcpy(compiled + curOffset, i.first, i.second);
		curOffset += i.second;
	}

	/* get exact relocation locations */
	for (int i = 0; i < vRelocations.size(); i++)
	{
		vRelocations[i] += 2;
	}

	PrintDisassembler disasm;
	disasm.process((char*)compiled, curOffset);
	auto result = injectFunction(originalFunctionName, (char*)compiled, curOffset);

	for (auto i : vRelocations)
		addRelocation(result.first + i);

	for (auto ppi : vLinesCompiled)
		delete ppi.first;
	delete compiled;
	delete pExt;
	return result;
}

IMAGE_SECTION_HEADER* PE::getSectionHeader(unsigned int sectionIndx) const
{
	return pSectionHeader + sectionIndx;
}

IMAGE_SECTION_HEADER* PE::getSectionHeaderByRVA(uintptr_t RelativeVirtualAddress) const
{
	return getSectionHeader(getRVAoffsetFromSectionBase(RelativeVirtualAddress).first);
}

IMAGE_SECTION_HEADER* PE::getSectionHeaderByDataDirectory(uint8_t dataDirectoryType) const
{
	dataDirectoryType = dataDirectoryType & 0x0f;
	if (pOpHeader->DataDirectory[dataDirectoryType].VirtualAddress == 0) return nullptr;
	else return getSectionHeaderByRVA(pOpHeader->DataDirectory[dataDirectoryType].VirtualAddress);
}
