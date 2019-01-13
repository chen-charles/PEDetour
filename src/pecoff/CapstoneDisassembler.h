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

#include <string>
#include <capstone/capstone.h>

class CapstoneDisassembler
{
public:
	CapstoneDisassembler() { throw; }
	CapstoneDisassembler(cs_arch Arch, cs_mode Mode)
	{
		if (cs_open(Arch, Mode, &handle) != CS_ERR_OK) throw;
	}

	void changeMode(cs_mode Mode)
	{
		cs_option(handle, CS_OPT_MODE, Mode);
	}

	size_t process(const char* code, size_t code_size, uint64_t address = 0, size_t count = 0)
	{
		size_t result = cs_disasm(handle, (const uint8_t*)code, code_size, address, count, &insn);
		if (result > 0)
		{
			size_t i;
			for (i = 0; i < result; i++)
			{
				if (!handler(i, insn[i].address, insn[i].mnemonic, insn[i].op_str)) return i;
			}

			cs_free(insn, result);

			return i;
		}
		else
			return 0;
	}

	~CapstoneDisassembler()
	{
		cs_close(&handle);
	}

protected:
	csh handle;
	cs_insn *insn;
	virtual bool handler(size_t index, uint64_t address, std::string mnemonic, std::string op_str) { return true; }
};

class PrintDisassembler : public CapstoneDisassembler
{
public:
#ifdef _M_X64
	PrintDisassembler() : CapstoneDisassembler(CS_ARCH_X86, CS_MODE_64) {}
#else
	PrintDisassembler() : CapstoneDisassembler(CS_ARCH_X86, CS_MODE_32) {}
#endif

protected:
	virtual bool handler(size_t index, uint64_t address, std::string mnemonic, std::string op_str)
	{
		std::cout << index << "\t" << address << "\t" << mnemonic.c_str() << "\t" << op_str.c_str() << std::endl;
		return true;
	}
};
