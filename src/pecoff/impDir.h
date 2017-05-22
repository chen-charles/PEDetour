#pragma once
#ifndef _PECOFF_IMPDIR_H_
#define _PECOFF_IMPDIR_H_

#include <map>
#include <set>
#include <cstring>
#include "relocatable.h"
#include "section.h"
#include "memblk.h"

class importDirectory : public Relocatable
{
public:
	importDirectory() : Relocatable(0) {}
	
	~importDirectory()
	{
		for (auto i : imps)
			delete i.second;
	}

public:	/* prevent caching issues */
	importDirectory(const importDirectory&) = delete;
	importDirectory& operator=(const importDirectory&) = delete;

public: 
	void add(Section& section)
	{
		for (auto i : section.imps)
		{
			if (imps.find(i.first.first) == imps.end())
				imps.insert({ i.first.first, new std::set<std::pair<uint16_t, std::string>> });
			imps[i.first.first]->insert(i.first.second);
		}
	}

	uintptr_t produce()
	{
		size_t szProduct = 0;
		szProduct += sizeof(IMAGE_IMPORT_DESCRIPTOR) * (imps.size() + 1);
		uintptr_t ilt_offset = szProduct;
		uintptr_t hnt_offset = szProduct;
		size_t szIAT = 0;
		

		for (auto i : imps)
		{
			szProduct += 2 * (sizeof(uintptr_t)*(i.second->size() + 1));	// IDT IAT 
			hnt_offset += 2 * (sizeof(uintptr_t)*(i.second->size() + 1));
			szIAT += (sizeof(uintptr_t)*(i.second->size() + 1));

			szProduct += (i.first.size() + 1);	// dll name
			

			for (auto j : *i.second)	// hint/name table
			{
				auto strl = j.second.size() + 1;
				if (j.second.size() == 0) strl = 0;
				szProduct += 2 + strl + strl%2;	// pad to even
			}
		}
		uintptr_t iat_offset = szProduct;
		resize(szProduct+szIAT);

		void* pCur = get();
		uintptr_t fname_offset = szProduct;
		
#define setRVA(key, val) { key = val; add_reloc_rva(&(key)); }
#define setFO(key, val) { key = val; add_reloc_fo(&(key)); }
		for (auto i : imps)
		{
			IMAGE_IMPORT_DESCRIPTOR* pDesc = (IMAGE_IMPORT_DESCRIPTOR*)pCur;
			setRVA(pDesc->OriginalFirstThunk, ilt_offset);
			pDesc->TimeDateStamp = 0;
			pDesc->ForwarderChain = 0;
			fname_offset -= i.first.size() + 1;	// store from the back
			setRVA(pDesc->Name, fname_offset);
			strcpy((char*)((uintptr_t)get() + fname_offset), i.first.c_str());
			setRVA(pDesc->FirstThunk, iat_offset);

			for (auto j : *i.second)
			{
				uintptr_t* pILT = (uintptr_t*)((uintptr_t)get() + ilt_offset);
				uintptr_t* pIAT = (uintptr_t*)((uintptr_t)get() + iat_offset);

				if (j.second.size() == 0)
				{
#ifdef _M_X64
					*pILT = 0x8000000000000000;
#else
					*pILT = 0x80000000;
#endif
					*pILT += j.first;
					*pIAT = *pILT;
				}
				else
				{
					setRVA(*pILT, hnt_offset);
					setRVA(*pIAT, hnt_offset);

					*(uint16_t*)((uintptr_t)get() + hnt_offset) = j.first;
					if (j.second.size() != 0)
					{
						strcpy((char*)((uintptr_t)get() + hnt_offset + 2), j.second.c_str());
						hnt_offset += 2 + j.second.size() + 1;
					}
					hnt_offset += hnt_offset % 2;
				}
				ilt_offset += sizeof(uintptr_t);
				iat_offset += sizeof(uintptr_t);
			}

			// terminating NULL
			*(uintptr_t*)((uintptr_t)get() + ilt_offset) = 0;
			ilt_offset += sizeof(uintptr_t);
			// terminating NULL
			*(uintptr_t*)((uintptr_t)get() + iat_offset) = 0;
			iat_offset += sizeof(uintptr_t);
			


			pCur = (void*)((uintptr_t)pCur + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}

		// terminating NULL desc
		((IMAGE_IMPORT_DESCRIPTOR*)pCur)->OriginalFirstThunk = 0;
		((IMAGE_IMPORT_DESCRIPTOR*)pCur)->ForwarderChain = 0;
		((IMAGE_IMPORT_DESCRIPTOR*)pCur)->Name = 0;
		((IMAGE_IMPORT_DESCRIPTOR*)pCur)->FirstThunk = 0;
		pCur = (void*)((uintptr_t)pCur + sizeof(IMAGE_IMPORT_DESCRIPTOR));

		this->szIAT = szIAT;
		return szProduct;
	}

public:
	size_t szIAT = 0;

protected:
	std::map<std::string, std::set<std::pair<uint16_t, std::string>>*> imps;

};



#endif
