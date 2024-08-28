#ifndef ENTRY_CXX
#define ENTRY_CXX

#include <iostream>
#include <thread>
#include <functional>

#include "status.hpp"

#pragma comment(linker, "/GS") 
#pragma comment(linker, "/DYNAMICBASE") 
#pragma comment(linker, "/NXCOMPAT") 
#pragma comment(linker, "/GUARD:CF") 
#pragma comment(linker, "/SAFESEH") 
#pragma comment(linker, "/FORTIFY_SOURCE=2") 
#pragma comment(linker, "/RODATA") 
#pragma comment(linker, "/SSP") 
#pragma comment(linker, "/INTEGRITYCHECK") 
#pragma comment(linker, "/HIGHENTROPYVA")
#pragma comment(linker, "/RELOC") 
#pragma comment(linker, "/LARGEADDRESSAWARE")

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Version.lib")

auto main() noexcept -> std::int32_t
{
	SetConsoleTitleA("JPEG Mafia");
	std::jthread([] { c_status->start(); });

	return 0;
}
#endif
