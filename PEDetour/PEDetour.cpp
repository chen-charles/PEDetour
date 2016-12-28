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

#include <SDKDDKVer.h>
#include <stdio.h>
#include <tchar.h>

#include <cinttypes>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <regex>

#include "KeystoneAssembler.h"
#include "CapstoneDisassembler.h"
#include "PE.h"

void help()
{
	std::cout <<
		"args for getExports:\n"
		"REQ\tinputfname\n\t\tInput File Name\n"
		<< std::endl;
	std::cout <<
		"args for injection:\n"
		"REQ\tinputfname\n\t\tInput File Name\n"
		"REQ\toutputfname\n\t\tOutput File Name\n"
		"REQ\tfunctionName\n\t\tthe export function name to inject\n"
		"REQ\tinjectionfname\n\t\tInjection File Name (intel assembly)\n"
		"OPT\t...\n\t\tadditional imports in the format of \"dllname(with_extension)::functionName(case_sensitive)\"\n"
		"\nDefault Additional Imports\n"
		"kernel32.dll::GetProcessHeap\n"
		"kernel32.dll::HeapAlloc\n"
		"kernel32.dll::LoadLibraryA\n"
		"kernel32.dll::GetProcAddress\n"
		"kernel32.dll::Beep\n"
		"user32.dll::MessageBoxA\n"
		"inputfname::functionName\n"
		<< std::endl;

	system("pause");
}

int main(int argc, char* argv[])
{
	std::string inputfname, outputfname, functionName, injectionfname;
	std::vector<std::string> vAddImports;
#ifndef _DEBUG
	if (argc == 1)
	{
		help();
		return 0;
	}
	else if (argc == 2)
	{
		inputfname = argv[1];
		std::ifstream in(inputfname, std::ios::in | std::ios::binary);
		if (in)
		{
			in.seekg(0, in.end);
			int length = (int)in.tellg();
			in.seekg(0, in.beg);
			char* raw = new char[length];
			in.read(raw, length);
			in.close();

			PE pe((void*)raw, length);

			std::cout << "Exports:" << std::endl;
			for (auto i : pe.getExports())
				std::cout << i.first << std::endl;
			
		}
		else
		{
			std::cout << "unable to open the specified file" << std::endl;
		}
		system("pause");
		return 0;
	}
	else if (argc < 5) 
	{
		help();
		return 0;
	}
	else
	{
		inputfname = PE::ParseCString(argv[1]);
		outputfname = PE::ParseCString(argv[2]);
		functionName = PE::ParseCString(argv[3]);
		injectionfname = PE::ParseCString(argv[4]);

		if (argc == 5)
		{
			vAddImports.push_back("kernel32.dll::GetProcessHeap");
			vAddImports.push_back("kernel32.dll::HeapAlloc");
			vAddImports.push_back("kernel32.dll::LoadLibraryA");
			vAddImports.push_back("kernel32.dll::GetProcAddress");
			vAddImports.push_back("kernel32.dll::Beep");
			vAddImports.push_back("user32.dll::MessageBoxA");
			vAddImports.push_back(inputfname + "::" + functionName);
		}
		else
		{
			for (int i = 5; i < argc; i++)
				vAddImports.push_back(argv[i]);
			
		}
	}

#else

	inputfname = "TestDLL.bak";
	outputfname = "TestDLL.dll";
	functionName = "?fnTestDLL@@YAHXZ";
	
#ifndef _M_X64
	injectionfname = "inject.asm";
#else
	injectionfname = "inject.x86_64.asm";
#endif

	vAddImports.push_back("kernel32.dll::GetProcessHeap");
	vAddImports.push_back("kernel32.dll::HeapAlloc");
	vAddImports.push_back("kernel32.dll::LoadLibraryA");
	vAddImports.push_back("kernel32.dll::GetProcAddress");
	vAddImports.push_back("kernel32.dll::Beep");
	vAddImports.push_back("user32.dll::MessageBoxA");
	vAddImports.push_back(inputfname + "::" + functionName);

#endif

	PrintDisassembler disasm;

#ifndef _M_X64
	KeystoneAssembler assembler(KS_ARCH_X86, KS_MODE_32);
#else
	KeystoneAssembler assembler(KS_ARCH_X86, KS_MODE_64);
#endif

	std::ifstream in(inputfname, std::ios::in | std::ios::binary);
	if (in)
	{
		in.seekg(0, in.end);
		int length = (int)in.tellg();
		in.seekg(0, in.beg);
		char* raw = new char[length];
		in.read(raw, length);
		in.close();

		PE pe((void*)raw, length);

		for (auto s : vAddImports)
		{
			auto ts = std::regex_replace(s, std::regex("::"), ":");
			auto result = pe.split(ts, ':');
			if (result.size() != 2)
			{
				std::cout << s << " is not a valid import name" << std::endl;
				system("pause");
				return 0;
			}
			else
				pe.addImport(result[0], result[1]);
		}

		std::ifstream codeToInject(injectionfname, std::ios::in);
		std::stringstream ss;
		ss << codeToInject.rdbuf();
		std::string strCode = ss.str();

		pe.injectFunction(functionName, strCode);

		std::ofstream ofs(outputfname, std::ofstream::out | std::ofstream::binary);
		if (ofs) ofs.write((char*)pe.get(), pe.length());
		else throw std::exception("unable to open the output file");
		ofs.close();
	}
	else
	{
		std::cout << "unable to open the specified file" << std::endl;
	}

#ifdef _DEBUG
		system("pause");
#endif
    return 0;
}
