#ifndef PROCESSES_CXX
#define PROCESSES_CXX

#include "detection.hpp"
#include <tlhelp32.h>

auto ida_pro::process_list::scan() const noexcept -> bool
{
    HANDLE h_process_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h_process_snap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    if (!Process32First(h_process_snap, &pe32))
    {
        CloseHandle(h_process_snap);
        return false;
    }

    const std::unordered_set<std::wstring> ida_executables = 
    {
        L"idaq.exe",
        L"idaq64.exe",
        L"ida64.exe",
        L"ida.exe",
        L"idat64.exe",
        L"idat.exe",
        L"idapyswitch.exe",
        L"qwingraph.exe",
        L"win64_remote64.exe",
        L"win32_remote64.exe"
    };

    do
    {
        if (ida_executables.find(pe32.szExeFile) != ida_executables.end())
        {
            CloseHandle(h_process_snap);
            return true;
        }
    } while (Process32Next(h_process_snap, &pe32));

    CloseHandle(h_process_snap);
    return false;
}
#endif
