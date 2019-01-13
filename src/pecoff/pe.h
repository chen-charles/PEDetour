#pragma once
#ifndef _PECOFF_PE_H_
#define _PECOFF_PE_H_


#include "CapstoneDisassembler.h"
#include "KeystoneAssembler.h"
#include "memblk.h"
#include "wrapper.h"
#include "section.h"
#include "impDir.h"


class PE
{
public:
	PE() = delete;
	PE(const void *pRaw, size_t length)
	{
		/* wrapper is solely designed for alias purposes, so we don't have to access pRaw */
		pWrapper = new Wrapper(pRaw, length);

		pvSections = new std::vector<Section*>;
		for (auto i = 0; i < pWrapper->nSections(); i++)
			pvSections->push_back(new Section(*pWrapper, pWrapper->getSectionHeader(i)));
		
	}

	~PE()	/* this is not responsible for pRaw discard */
	{
		delete pWrapper;
		for (auto i : *pvSections) delete i;
		delete pvSections;
	}

public:	/* prevent caching issues */
	PE(const PE&) = delete;
	PE& operator=(const PE&) = delete;

public:
	const Wrapper& wrapper() const { (const Wrapper*)pWrapper; }

public:
	memblk produce()
	{
		size_t szProduct = 0;

		auto secPRawData = (*pvSections)[0]->header.PointerToRawData;
		szProduct += secPRawData;

		/* collect all section imports */
		importDirectory impDir;
		for (auto pSec : *pvSections)
		{
			impDir.add(*pSec);
		}
		auto iatDirVAddr = impDir.produce();
		int impDirVAddr = 0;

		uintptr_t secvaddr = (*pvSections)[0]->header.VirtualAddress;
		for (auto pSec : *pvSections)
		{
			// put imp/exp/reloc table in their original containing section
			// calculate actural size
			if (pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress >=pSec->original().VirtualAddress &&
				pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress < pSec->original().VirtualAddress + pSec->original().Misc.VirtualSize)
			{
				//pSec->extend(0x1000);
			}
			if (pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress >= pSec->original().VirtualAddress &&
				pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress < pSec->original().VirtualAddress + pSec->original().Misc.VirtualSize)
			{
				impDirVAddr = pSec->header.VirtualAddress + pSec->size();
				iatDirVAddr += impDirVAddr;
				pSec->append(impDir);
			}
			if (pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC).VirtualAddress >= pSec->original().VirtualAddress &&
				pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC).VirtualAddress < pSec->original().VirtualAddress + pSec->original().Misc.VirtualSize)
			{
				//pSec->extend(0x1000);
			}

			pSec->align();
			

			pSec->header.PointerToRawData = secPRawData;
			secPRawData += pSec->size();

			pSec->header.VirtualAddress = secvaddr;
			secvaddr += pSec->vsize();

			szProduct += pSec->size();
			szProduct += sizeof(IMAGE_SECTION_HEADER);
		}

		// Another exception is that attribute certificate and debug information must be placed at the very end of an image file, with the attribute certificate table immediately preceding the debug section, because the loader does not map these into memory. 
		// drop them for now
		uint8_t* product = new uint8_t[szProduct];
		int offset = (*pvSections)[0]->header.PointerToRawData;
		memcpy(product, (void*)pWrapper->get(), offset);
		const Wrapper wProduct(product, szProduct);

		// patch in the end
		auto pDosHeader = (IMAGE_DOS_HEADER*)product;
		auto pHeader = (IMAGE_FILE_HEADER*)((uintptr_t)product + pDosHeader->e_lfanew + sizeof(uint32_t));
		pHeader->NumberOfSections = (WORD)pvSections->size();
		auto pOpHeader = (IMAGE_OPTIONAL_HEADER*)((uintptr_t)pHeader + sizeof(IMAGE_FILE_HEADER));
		for (auto pSec : *pvSections)
		{
			if (pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress >= pSec->original().VirtualAddress &&
				pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress < pSec->original().VirtualAddress + pSec->original().Misc.VirtualSize)
			{
				pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = impDirVAddr;
				pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = impDir.size();
			}
			if (pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_IAT).VirtualAddress >= pSec->original().VirtualAddress &&
				pWrapper->DataDirectory(IMAGE_DIRECTORY_ENTRY_IAT).VirtualAddress < pSec->original().VirtualAddress + pSec->original().Misc.VirtualSize)
			{
				pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = iatDirVAddr;
				pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = impDir.szIAT;
			}
		}

		auto pSectionHeader = (IMAGE_SECTION_HEADER*)((uintptr_t)pOpHeader + sizeof(IMAGE_OPTIONAL_HEADER));
		offset = (uintptr_t)pSectionHeader - (uintptr_t)product;
		// fill in section headers
		for (auto pSec : *pvSections)
		{
			*(IMAGE_SECTION_HEADER*)(product + offset) = pSec->header;

			// apply actual relocations; SECTION SIZE IS NOW FINALIZED. 
			pSec->applyTo(pSec->header.VirtualAddress, pSec->header.PointerToRawData);
			offset += sizeof(IMAGE_SECTION_HEADER);
		}

		// fix calls to imports 
		// since IAT is rebuilt and relocated, all calls to functions must be fixed
		// analyze which linkage it previous has, match by function name ( ordinal ). (since order is rebuilt)

		//int64_t iat_offset = iatDirVAddr - pWrapper->optionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
		//for (auto pSec : *pvSections)
		//{
		//	// loop through all relocs, modify their pointer to the newly built iat
		//	for (auto &&i : pSec->relocations())
		//	{
		//		
		//		if (i.second >= pWrapper->optionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress &&
		//			i.second < pWrapper->optionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress +
		//			pWrapper->optionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size)
		//		{
		//			i.second += iat_offset;
		//		}
		//	}
		//}

		// generate export with containing section's final header info 
		
		// generate reloc, sorted 
		

		
		// fix rsrc (simple rva patches)



		// apply section data
		offset = (*pvSections)[0]->header.PointerToRawData;
		for (auto pSec : *pvSections)
		{
			if (offset + pSec->size() > szProduct) throw;
			memcpy(product + offset, pSec->get(), pSec->size());
			offset += pSec->size();
		}

		// return
		memblk result;
		result.ptr = product;
		result.size = szProduct;
		return result;
	}

protected:
	Wrapper* pWrapper = nullptr;
	std::vector<Section*>* pvSections = nullptr;

};

#endif
