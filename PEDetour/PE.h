#pragma once

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

#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <windows.h> 
#include <regex>
#include <cstring>
#include <unordered_map>
#include <sstream>

#include "KeystoneAssembler.h"
#include "CapstoneDisassembler.h"

/* 64 bit PEs uses "call qword ptr [rip + offset]" */
/* "call rbx" offseting cannot be handled */

/* additional dependency: cap/keystone dis/assembler */

#ifdef _M_X64

#include "Win64EH.h"

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

#endif


class PE
{
public:
	PE();
	PE(void* pRaw, int length);

	/* buffer const functions */
	std::vector<std::pair<std::string, uintptr_t>>& getExports();
	std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>& getImports();	/* dllname, {name, PointerToFunction(RVA+Base)} / {std::string(""), ordinal} */ /* call dword [PointerToFunction] */
	uintptr_t ParseRVA(uintptr_t RelativeVirtualAddress) const;
	void* ParseRVA(void* RelativeVirtualAddress) const { return (void*)ParseRVA((uintptr_t)RelativeVirtualAddress); }
	uintptr_t toRVA(uintptr_t addressInMemory) const;
	void* toRVA(void* addressInMemory) const { return (void*)toRVA((uintptr_t)addressInMemory); }
	void* get() { return p; }
	int length() const { return len; }
	IMAGE_OPTIONAL_HEADER* getpOpHeader() { return pOpHeader; }
	size_t sectionExtend(std::string name, unsigned int deltaSize, void** output);

	/* buffer modification functions */
	void sectionExtendInPlace(std::string name, unsigned int deltaSize);	/* positive extension only */
	uintptr_t changeExportFunctionEntry(std::string functionName, uintptr_t RVAdesiredEntry);	/* return old entry */
	bool addRelocation(uintptr_t RelativeVirtualAddress);
	bool addImport(std::string dll, std::string functionName);
	std::pair<uint32_t, uint32_t> injectFunction(std::string originalFunctionName, const char* injectionFunction, unsigned int injectionSize);	/* injected RVA, old function entry */
	std::pair<uint32_t, uint32_t> PE::injectFunction(std::string originalFunctionName, std::string strCode);


	~PE();

	static uintptr_t PE::align(uintptr_t value, int alignment) { return value%alignment ? (value + alignment - value%alignment) : value; }
	static uintptr_t PE::aligndown(uintptr_t value, int alignment) { return value - value%alignment; }
	static std::string PE::ParseCString(const unsigned char* c_str) { std::string name; while (*c_str != 0) name += *(c_str++); return name; }
	static std::string PE::ParseCString(const char* c_str) { std::string name; while (*c_str != 0) name += *(c_str++); return name; }
	static void split(const std::string &s, char delim, std::vector<std::string> &elems)
	{
		std::stringstream ss;
		ss.str(s);
		std::string item;
		while (std::getline(ss, item, delim)) {
			elems.push_back(item);
		}
	}

	static std::vector<std::string> split(const std::string &s, char delim)
	{
		std::vector<std::string> elems;
		split(s, delim, elems);
		return elems;
	}

private:
	uintptr_t patchRVA(uintptr_t RelativeVirtualAddress, PE& target);
	void patchResources(IMAGE_RESOURCE_DIRECTORY* pResDir, PE& target);
	void load(void* pRaw, int length);

	std::vector<std::pair<std::string, uintptr_t>>* pvExports;
	std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>* pvImports;

protected:
	void* p;
	int len;

	IMAGE_DOS_HEADER* pDosHeader;
	IMAGE_FILE_HEADER* pHeader;
	IMAGE_OPTIONAL_HEADER* pOpHeader = nullptr;
	IMAGE_SECTION_HEADER* pSectionHeader;

	IMAGE_EXPORT_DIRECTORY* pDirExport = nullptr;
	IMAGE_IMPORT_DESCRIPTOR* pDirImport = nullptr;	// zero for terminating import descriptor @ 0x00

	std::pair<unsigned int, unsigned int> getRVAoffsetFromSectionBase(uintptr_t RelativeVirtualAddress) const;	/* section indx, offset from section-vaddr */

	IMAGE_SECTION_HEADER* getSectionHeader(unsigned int sectionIndx) const;
	IMAGE_SECTION_HEADER* getSectionHeaderByRVA(uintptr_t RelativeVirtualAddress) const;
	IMAGE_SECTION_HEADER* getSectionHeaderByDataDirectory(uint8_t dataDirectoryType) const;

#ifdef _M_X64
	class x64FixRIPReloc : public CapstoneDisassembler
	{
	public:
		x64FixRIPReloc() { throw; }
		x64FixRIPReloc(const IMAGE_SECTION_HEADER* pSec, PE* pOldPE, PE* pNewPE) : CapstoneDisassembler(CS_ARCH_X86, CS_MODE_64)
		{
			px64Asm = new KeystoneAssembler(KS_ARCH_X86, KS_MODE_64);
			this->pSec = pSec;
			this->pNewPE = pNewPE;
			this->pOldPE = pOldPE;
		}

		~x64FixRIPReloc()
		{
			delete px64Asm;
		}

	private:
		KeystoneAssembler* px64Asm;
		const IMAGE_SECTION_HEADER* pSec;
		PE* pOldPE;
		PE* pNewPE;

	protected:
		// reconstruct this
		virtual bool handler(size_t index, uint64_t address, std::string mnemonic, std::string op_str)
		{
			if (op_str.find("rip") != std::string::npos)
			{
				//std::cout << std::hex << index << "\t" << address << "\t" << mnemonic.c_str() << "\t" << op_str.c_str() << std::endl;

				unsigned char* line_compiled;
				auto length = px64Asm->process((mnemonic + " " + op_str).c_str(), &line_compiled);

				if (*(char*)(pNewPE->ParseRVA(pSec->VirtualAddress + address)) == 0x48 && line_compiled[0] != 0x48)
				{
					auto pTmp = new unsigned char[length + 1];
					memcpy(pTmp + 1, line_compiled, length);
					*pTmp = 0x48;
					length++;
				}

				// c6 05 de a9 00 00 01    mov    BYTE PTR [rip+0xa9de], 0x1 
				signed int offset;

				std::smatch sm;
				std::regex_search(op_str, sm, std::regex("\\[(.*?)\\]"));
				if (sm.size() == 0) throw;
				std::string block(sm[0]);
				auto pos = block.find("0x");
				if (pos == std::string::npos) offset = 0;
				else
				{
					std::string svalue;
					for (int i = pos; block[i] != ' ' && block[i] != ']'; i++)
					{
						svalue += block[i];
					}
					if (block[pos - 2] == '+')
						offset = std::stoul(svalue, nullptr, 16);
					else if (block[pos - 2] == '-')
						offset = -1 * std::stoul(svalue, nullptr, 16);
					else throw;
				}

				int64_t realRVA = pSec->VirtualAddress + address + length + (signed int)offset;
				try
				{
					pOldPE->patchRVA(realRVA, *pNewPE);
					int64_t patchedRVA = pOldPE->patchRVA(realRVA, *pNewPE);
					offset = patchedRVA - pSec->VirtualAddress - address - length;

					op_str = std::regex_replace(op_str, std::regex("\\[(.*?)\\]"), "[rip + " + std::to_string(offset) + "]");
					px64Asm->process((mnemonic + " " + op_str).c_str(), &line_compiled);

					// REX prefix is not properly handled by capstone http://wiki.osdev.org/X86-64_Instruction_Encoding#REX_prefix
					// 48 ff 25 1a 0a 00 00    rex.W jmp QWORD PTR [rip+0xa1a]
					// ff 25 1a 0a 00 00       jmp    QWORD PTR [rip+0xa1a]

					if (*(char*)(pNewPE->ParseRVA(pSec->VirtualAddress + address)) == 0x48 && line_compiled[0] != 0x48)
						memcpy((void*)(pNewPE->ParseRVA(pSec->VirtualAddress + address) + 1), line_compiled, length - 1);
					else
						memcpy((void*)pNewPE->ParseRVA(pSec->VirtualAddress + address), line_compiled, length);

					//PrintDisassembler pd;
					//pd.process((char*)line_compiled, length);
				}
				catch (...)
				{
#ifdef _DEBUG
					std::cout << "unable to fix the following rip-reloc" << std::endl;
					std::cout << std::hex << realRVA << index << "\t" << address << "\t" << mnemonic.c_str() << "\t" << op_str.c_str() << std::endl;
#endif
				}

			}

			return true;
		}
	};

	class x64FixImports : public CapstoneDisassembler
	{
	public:
		x64FixImports()
		{
			throw;
		}

		x64FixImports(const IMAGE_SECTION_HEADER* pSec, PE* pPE, std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>& oldImports, std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>& newImports) : CapstoneDisassembler(CS_ARCH_X86, CS_MODE_64)
		{
			px64Asm = new KeystoneAssembler(KS_ARCH_X86, KS_MODE_64);
			this->pSec = pSec;
			this->pOldImports = &oldImports;
			this->pNewImports = &newImports;
			this->pPE = pPE;
		}

		~x64FixImports()
		{
			delete px64Asm;
		}

	private:
		KeystoneAssembler* px64Asm;
		const IMAGE_SECTION_HEADER* pSec;
		PE* pPE;
		std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>* pOldImports;
		std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>* pNewImports;

	protected:
		// FIXME
		virtual bool handler(size_t index, uint64_t address, std::string mnemonic, std::string op_str)
		{
			if (op_str.find("rip") != std::string::npos)
			{
				//std::cout << std::hex << index << "\t" << address << "\t" << mnemonic.c_str() << "\t" << op_str.c_str() << std::endl;

				unsigned char* line_compiled;
				auto length = px64Asm->process((mnemonic + " " + op_str).c_str(), &line_compiled);
				if (*(char*)(pPE->ParseRVA(pSec->VirtualAddress + address)) == 0x48 && line_compiled[0] != 0x48)
				{
					auto pTmp = new unsigned char[length + 1];
					memcpy(pTmp + 1, line_compiled, length);
					*pTmp = 0x48;
					length++;
				}
				// c6 05 de a9 00 00 01    mov    BYTE PTR [rip+0xa9de], 0x1 
				signed int offset;

				std::smatch sm;
				std::regex_search(op_str, sm, std::regex("\\[(.*?)\\]"));
				if (sm.size() == 0) throw;
				std::string block(sm[0]);
				auto pos = block.find("0x");
				if (pos == std::string::npos) offset = 0;
				else
				{
					std::string svalue;
					for (int i = pos; block[i] != ' ' && block[i] != ']'; i++)
					{
						svalue += block[i];
					}
					if (block[pos - 2] == '+')
						offset = std::stoul(svalue, nullptr, 16);
					else if (block[pos - 2] == '-')
						offset = -1 * std::stoul(svalue, nullptr, 16);
					else throw;
				}

				int64_t realRVA = pSec->VirtualAddress + address + length + (signed int)offset;
				std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>& oldImports = *pOldImports;
				std::vector<std::pair<std::string, std::vector<std::pair<std::string, uintptr_t>>*>>& newImports = *pNewImports;
				//try
				//{
					for (int i = 0; i < oldImports.size(); i++)
					{
						for (int j = 0; j < oldImports[i].second->size(); j++)
						{
							if (oldImports[i].second->at(j).second - pPE->pOpHeader->ImageBase == realRVA)
							{
								// matched
								int64_t patchedRVA = newImports[i].second->at(j).second - pPE->pOpHeader->ImageBase;
								offset = patchedRVA - pSec->VirtualAddress - address - length;
								op_str = std::regex_replace(op_str, std::regex("\\[(.*?)\\]"), "[rip + " + std::to_string(offset) + "]");
								px64Asm->process((mnemonic + " " + op_str).c_str(), &line_compiled);

								// REX prefix is not properly handled by capstone http://wiki.osdev.org/X86-64_Instruction_Encoding#REX_prefix
								// 48 ff 25 1a 0a 00 00    rex.W jmp QWORD PTR [rip+0xa1a]
								// ff 25 1a 0a 00 00       jmp    QWORD PTR [rip+0xa1a]
								if (*(char*)(pPE->ParseRVA(pSec->VirtualAddress + address)) == 0x48 && line_compiled[0] != 0x48)
									memcpy((void*)(pPE->ParseRVA(pSec->VirtualAddress + address) + 1), line_compiled, length - 1);
								else
									memcpy((void*)pPE->ParseRVA(pSec->VirtualAddress + address), line_compiled, length);

								break;
							}
						}
					}

				//}
				//catch (...)
				//{
				//	std::cout << std::hex << index << "\t" << address << "\t" << mnemonic.c_str() << "\t" << op_str.c_str() << std::endl;
				//	std::cout << std::hex << realRVA << "\t" << std::hex << address << std::endl;
				//}

			}

			return true;
		}

	};
#endif


};

