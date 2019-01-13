
#include <stdio.h>
// #include <tchar.h>

#include <cinttypes>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <regex>

#include <pecoff/pe.h>

int main() 
{
	PrintDisassembler disasm;
	disasm.process("\x55\x48\x8b\x05\xb8\x13\x00\x00", 8);

	std::ifstream in("TestDLL.bak", std::ios::in | std::ios::binary);
	if (in)
	{
		in.seekg(0, in.end);
		int length = (int)in.tellg();
		in.seekg(0, in.beg);
		char* raw = new char[length];
		in.read(raw, length);
		in.close();

		PE pe((void*)raw, length);

		auto mblk = pe.produce();
		std::ofstream ofs("TestDLL.dll", std::ofstream::out | std::ofstream::binary);
		if (ofs) ofs.write((char*)mblk.ptr, mblk.size);
		else throw std::exception("unable to open the output file");
		ofs.close();
		delete mblk.ptr;
		delete raw;
	}
	else
	{
		std::cout << "unable to open the specified file" << std::endl;
	}

	system("pause"); 
	return 0; 
}
