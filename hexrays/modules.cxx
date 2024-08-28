#ifndef MODULES_CXX
#define MODULES_CXX

#include "detection.hpp"
#include <psapi.h>
#include <array>

auto ida_pro::module_list::scan() const noexcept -> bool
{
    DWORD a_processes[1024], cb_needed, c_processes;
    if (!K32EnumProcesses(a_processes, sizeof(a_processes), &cb_needed))
        return false;

    c_processes = cb_needed / sizeof(DWORD);
    std::array<const char*, 10> target_processes = 
    { 
        "idaq.exe", 
        "idaq64.exe", 
        "ida64.exe", 
        "ida.exe",
        "idat64.exe",
        "idat.exe",
        "idapyswitch.exe",
        "qwingraph.exe",
        "win64_remote64.exe",
        "win32_remote64.exe"
    };

    for (unsigned int i = 0; i < c_processes; i++)
    {
        if (a_processes[i] != 0)
        {
            HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, a_processes[i]);
            if (h_process)
            {
                HMODULE h_mod;
                DWORD cb_needed;
                if (K32EnumProcessModules(h_process, &h_mod, sizeof(h_mod), &cb_needed))
                {
                    char sz_process_name[MAX_PATH];
                    K32GetModuleBaseNameA(h_process, h_mod, sz_process_name, sizeof(sz_process_name) / sizeof(char));
                    for (const auto& target : target_processes)
                    {
                        if (std::string(sz_process_name) == target)
                        {
                            CloseHandle(h_process);
                            return true;
                        }
                    }
                }
                CloseHandle(h_process);
            }
        }
    }
    return false;
}
#endif
