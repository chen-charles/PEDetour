#pragma once
#ifndef _PECOFF_SECTION_H_
#define _PECOFF_SECTION_H_

#include <iostream>
#include <vector>
#include <algorithm>
#include <windows.h> 
#include <cassert>

#include "wrapper.h"
#include "relocatable.h"

class Section : public Relocatable
{
public:
	Section() = delete;
	Section(const Wrapper& pe, IMAGE_SECTION_HEADER* pSec) : Relocatable(pSec->SizeOfRawData, *pSec)
	{
		this->pWrapper = &pe;
		this->header = *pSec;
		this->pSec = pSec;
		memcpy(get(), (void*)((uintptr_t)pe.get() + pSec->PointerToRawData), size());

		for (auto i : pe.getRelocations(pSec))
		{
			add_reloc(reloc_type::RVA, i.first - pSec->VirtualAddress + i.second.offset);
			b_relocs.push_back(std::make_pair(i.first - pSec->VirtualAddress, i.second));
		}

		for (auto i : pe.getImports())
		{
			for (auto j : *(i.second))
			{
				for (auto k : b_relocs)
				{
					if (k.second.type == IMAGE_REL_BASED_DIR64 || k.second.type == IMAGE_REL_BASED_HIGHLOW)
						if (*(uintptr_t*)((uintptr_t)get() + k.first + k.second.offset) == j.second)
							imps.push_back(std::make_pair(std::make_pair(i.first, j.first), k.first + k.second.offset));
				}
			}
		}

		for (auto i : pe.getExports())
		{
			if (i.second >= pSec->VirtualAddress && i.second < pSec->VirtualAddress + pSec->SizeOfRawData)
				exps.push_back(std::make_pair(i.first, i.second - pSec->VirtualAddress));
		}


	}

	~Section() {}

public:	/* prevent caching issues */
	Section(const Section&) = delete;
	Section& operator=(const Section&) = delete;

public:
	IMAGE_SECTION_HEADER original() const { return *pSec; }
	size_t vsize() const { return header.Misc.VirtualSize; }

public:
	/* effective immeidiately */
	void extend(size_t szExt) { insert(Relocatable(szExt), size()); }
	virtual void insert(Relocatable& other, int64_t offset)
	{
		Relocatable::insert(other, offset);
		size_t szExt = other.size();
		header.SizeOfRawData += szExt;
		header.Misc.VirtualSize += szExt;

		// apply relocation fixes
		for (auto i = 0; i < b_relocs.size(); i++)
		{
			auto secOff = b_relocs[i].first + b_relocs[i].second.offset;
			if (secOff > offset)
			{
				secOff += szExt;
				b_relocs[i].first = secOff / 0x1000;
				b_relocs[i].second.offset = secOff % 0x1000;
			}
		}

		// imports && exports are rebuilt when producing product
		// imports are always relocated, modify calls when producing
		// exports can be processed as if they are b_relocs, notify new addresses when producing
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
	std::vector<std::pair<uint32_t, relocblk>> b_relocs;
	std::vector<std::pair<std::pair<std::string, std::pair<uint16_t, std::string>>, uintptr_t>> imps;
	std::vector<std::pair<std::string, uintptr_t>> exps;	// dllname(::)[,]functionName, offset-rel-to-sec-base (address to patch)
	IMAGE_SECTION_HEADER header;	// new header

protected:
	IMAGE_SECTION_HEADER* pSec = nullptr;	// original header
	const Wrapper* pWrapper = nullptr;
};



#endif
