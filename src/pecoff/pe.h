#pragma once
#ifndef _PECOFF_PE_H_
#define _PECOFF_PE_H_

#include <unordered_map>
#include <unordered_set>
#include "CapstoneDisassembler.h"
#include "KeystoneAssembler.h"
#include "wrapper.h"
#include "section.h"

struct memblock
{
	void* ptr;
	size_t size;
};

class PE
{
public:
	PE() = delete;
	PE(const void *pRaw, size_t length)
	{
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
	memblock produce()
	{
		size_t szProduct = 0;

		auto secPRawData = (*pvSections)[0]->get()->PointerToRawData;
		szProduct += secPRawData;
		std::unordered_map<std::string, std::unordered_set<std::string>*> imps;
		for (auto pSec : *pvSections)
		{
			// put imp/exp/reloc table in their original containing section
			// calculate actural size
			if (pWrapper->optionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - pSec->original().VirtualAddress > pSec->original().SizeOfRawData)
			{
				//pSec->extend(0x1000);
			}
			if (pWrapper->optionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - pSec->original().VirtualAddress > pSec->original().SizeOfRawData)
			{
				//pSec->extend(0x1000);
			}
			if (pWrapper->optionalHeader().DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress - pSec->original().VirtualAddress > pSec->original().SizeOfRawData)
			{
				//pSec->extend(0x1000);
			}

			pSec->align();

			pSec->get()->PointerToRawData = secPRawData;
			secPRawData += pSec->size();

			szProduct += pSec->size();
			szProduct += sizeof(IMAGE_SECTION_HEADER);

			// collect imports
			for (auto i : pSec->imps)
			{
				if (imps.find(i.first.first) == imps.end())
					imps.insert({i.first.first, new std::unordered_set<std::string>});
				imps[i.first.first]->insert(i.first.second);
			}
		}
		
		// Another exception is that attribute certificate and debug information must be placed at the very end of an image file, with the attribute certificate table immediately preceding the debug section, because the loader does not map these into memory. 
		// drop them for now
		uint8_t* product = new uint8_t[szProduct];
		int offset = (*pvSections)[0]->get()->PointerToRawData;
		memcpy(product, (void*)pWrapper->get(), offset);
		const Wrapper wProduct(product, szProduct);

		// patch in the end
		auto pDosHeader = (IMAGE_DOS_HEADER*)product;
		auto pHeader = (IMAGE_FILE_HEADER*)((uintptr_t)product + pDosHeader->e_lfanew + sizeof(uint32_t));
		pHeader->NumberOfSections = (WORD)pvSections->size();
		auto pOpHeader = (IMAGE_OPTIONAL_HEADER*)((uintptr_t)pHeader + sizeof(IMAGE_FILE_HEADER));

		// fill in section headers
		for (auto pSec : *pvSections)
		{
			*(IMAGE_SECTION_HEADER*)(product + offset) = *pSec->get();
			offset += sizeof(IMAGE_SECTION_HEADER);
		}

		// generate import 

		// fix calls to imports 

		// generate export with containing section's final header info 
		
		// generate reloc, sorted 
		

		
		// fix rsrc (simple rva patches)


		// apply section data
		offset = (*pvSections)[0]->get()->PointerToRawData;
		for (auto pSec : *pvSections)
		{
			if (offset + pSec->size() > szProduct) throw;
			memcpy(product + offset, pSec->ptr(), pSec->size());
			offset += pSec->size();
		}

		// return
		memblock result;
		result.ptr = product;
		result.size = szProduct;
		return result;
	}

protected:
	Wrapper* pWrapper = nullptr;
	std::vector<Section*>* pvSections = nullptr;

};

#endif
