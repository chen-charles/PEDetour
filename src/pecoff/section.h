#pragma once
#ifndef _PECOFF_SECTION_H_
#define _PECOFF_SECTION_H_

#include <iostream>
#include <vector>
#include <algorithm>
#include <windows.h> 
#include <cassert>

#include "wrapper.h"

class Section
{
public:
	Section(const Wrapper& pe, IMAGE_SECTION_HEADER* pSec)
	{
		this->pWrapper = &pe;
		this->header = *pSec;
		this->pSec = pSec;
		for (auto i : pe.getRelocations(pSec))
			relocs.push_back(std::make_pair(i.first-pSec->VirtualAddress, i.second));

		pe.getImports();
		for (auto i : pe.getImports())
		{
			for (auto j : *(i.second))
			{
				if (j.second - pe.imageBase() >= pSec->VirtualAddress && j.second - pe.imageBase() < pSec->VirtualAddress + pSec->SizeOfRawData)
				{
					for (auto k : relocs)
					{
						if (k.second.type == IMAGE_REL_BASED_DIR64 || k.second.type == IMAGE_REL_BASED_HIGHLOW)
							if (*(uintptr_t*)((uintptr_t)ptr() + k.first + k.second.offset) == j.second)
								imps.push_back(std::make_pair(std::make_pair(i.first, j.first), k.first + k.second.offset));
					}
				}
			}
		}
		for (auto i : pe.getExports())
		{
			if (i.second >= pSec->VirtualAddress && i.second < pSec->VirtualAddress + pSec->SizeOfRawData)
				exps.push_back(std::make_pair(i.first, i.second - pSec->VirtualAddress));
		}

		pRaw = malloc(size());
		memcpy(pRaw, (void*)((uintptr_t)pe.get() + pSec->PointerToRawData), size());
	}

	~Section()
	{
		free(pRaw);
	}

public:	/* prevent caching issues */
	Section(const Section&) = delete;
	Section& operator=(const Section&) = delete;

public:
	IMAGE_SECTION_HEADER* get() { return &header; }
	IMAGE_SECTION_HEADER original() const { return *pSec; }
	void* ptr() const { return pRaw; }
	size_t size() const { return header.SizeOfRawData; }
	size_t vsize() const { return header.Misc.VirtualSize; }

public:
	/* effective immeidiately */
	void extend(size_t szExt) { insert(size(), szExt); }
	void insert(size_t offset, size_t szExt)
	{
		pRaw = realloc(pRaw, size() + szExt);
		memmove((void*)((uintptr_t)pRaw + offset + szExt), (void*)((uintptr_t)pRaw + offset), size()-offset);
		header.SizeOfRawData += szExt;
		header.Misc.VirtualSize += szExt;

		// apply relocation fixes
		for (auto i = 0; i < relocs.size(); i++)
		{
			auto secOff = relocs[i].first + relocs[i].second.offset;
			if (secOff > offset)
			{
				secOff += szExt;
				relocs[i].first = secOff / 0x1000;
				relocs[i].second.offset = secOff % 0x1000;
			}
		}

		// imports && exports are rebuilt when producing product
		// imports are always relocated, modify calls when producing
		// exports can be processed as if they are relocs, notify new addresses when producing
		for (auto i = 0; i < imps.size(); i++)
		{
			if (imps[i].second > offset)
				imps[i].second += szExt;
		}
		for (auto i = 0; i < exps.size(); i++)
		{
			if (exps[i].second > offset)
				exps[i].second += szExt;
		}

	}

	void align()	// fix alignment
	{
		if (size() % pWrapper->optionalHeader().FileAlignment != 0)
			extend(pWrapper->optionalHeader().FileAlignment - size() % pWrapper->optionalHeader().FileAlignment);
		if (vsize() % pWrapper->optionalHeader().SectionAlignment != 0)
			header.Misc.VirtualSize += pWrapper->optionalHeader().SectionAlignment - vsize();
	}

public:
	std::vector<std::pair<uint32_t, relocBlk>> relocs;
	std::vector<std::pair<std::pair<std::string, std::string>, uintptr_t>> imps;
	std::vector<std::pair<std::string, uintptr_t>> exps;	// dllname(::)[,]functionName, offset-rel-to-sec-base (address to patch)

protected:

	IMAGE_SECTION_HEADER header;	// new header
	IMAGE_SECTION_HEADER* pSec = nullptr;	// original header
	const Wrapper* pWrapper = nullptr;
	void* pRaw = nullptr;
};



#endif
