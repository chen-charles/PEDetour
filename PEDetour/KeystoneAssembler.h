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

#include "keystone-win32/include/keystone.h"

#ifdef _M_X64

#ifndef _DEBUG
#pragma comment(lib, "keystone-win32/build/x64/Release/keystone.lib")
#else
#pragma comment(lib, "keystone-win32/build/x64/Debug/keystone.lib")
#endif

#else

#ifndef _DEBUG
#pragma comment(lib, "keystone-win32/build/x86/Release/keystone.lib")
#else
#pragma comment(lib, "keystone-win32/build/x86/Debug/keystone.lib")
#endif

#endif

class KeystoneAssembler
{
public:
	KeystoneAssembler() { throw; }
	KeystoneAssembler(ks_arch Arch, ks_mode Mode)
	{
		if (ks_open(Arch, Mode, &ks) != KS_ERR_OK) throw;
	}

	size_t process(const char* code_c_str, unsigned char** result, uint64_t address = 0)
	{
		size_t count;
		unsigned char *encode;
		size_t size;
		if (ks_asm(ks, code_c_str, address, &encode, &size, &count) != KS_ERR_OK)
		{
			printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
				count, ks_errno(ks));
			throw std::exception("ks_asm() failed");
			return 0;
		}
		else
		{
			*result = encode;
			return size;
		}

		ks_free(encode);
	}

	~KeystoneAssembler()
	{
		ks_close(ks);
	}

protected:
	ks_engine *ks;
};
