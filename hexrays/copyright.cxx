#ifndef COPYRIGHT_CXX
#define COPYRIGHT_CXX

#include "detection.hpp"
#include <iostream>
#include <psapi.h>    
#include <tlhelp32.h>
#include <vector>

auto ida_pro::copyright::check_copyright(const std::string& file_path) -> bool
{
    DWORD version_handle;
    DWORD version_size = GetFileVersionInfoSizeA(file_path.c_str(), &version_handle);

    if (version_size == 0)
    {
        return false;
    }

    std::vector<char> version_buffer(version_size);
    if (!GetFileVersionInfoA(file_path.c_str(), version_handle, version_size, version_buffer.data())) 
    {
        return false;
    }

    struct LANGANDCODEPAGE 
    {
        WORD language;
        WORD code_page;
    } *translation;

    UINT translation_size;
    if (!VerQueryValueA(version_buffer.data(), "\\VarFileInfo\\Translation", (LPVOID*)&translation, &translation_size)) 
    {
        return false;
    }

    for (UINT i = 0; i < (translation_size / sizeof(struct LANGANDCODEPAGE)); i++) 
    {
        char sub_block[50];
        void* info;
        UINT info_size;

        sprintf_s(sub_block, "\\StringFileInfo\\%04x%04x\\ProductName", translation[i].language, translation[i].code_page);
        if (VerQueryValueA(version_buffer.data(), sub_block, &info, &info_size) and this->product_name == static_cast<char*>(info)) 
        {
            return true;
        }

        sprintf_s(sub_block, "\\StringFileInfo\\%04x%04x\\FileDescription", translation[i].language, translation[i].code_page);
        if (VerQueryValueA(version_buffer.data(), sub_block, &info, &info_size) and this->file_description == static_cast<char*>(info))
        {
            return true;
        }

        sprintf_s(sub_block, "\\StringFileInfo\\%04x%04x\\OriginalFilename", translation[i].language, translation[i].code_page);
        if (VerQueryValueA(version_buffer.data(), sub_block, &info, &info_size) and (this->original_name == static_cast<char*>(info) or original_name_64 == static_cast<char*>(info))) 
        {
            return true;
        }
    }

    return false;
}

auto ida_pro::copyright::get_running_executables() -> std::vector<std::string> 
{
    std::vector<std::string> running_executables;
    HANDLE process_snapshot;
    PROCESSENTRY32 process_entry;

    process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (process_snapshot == INVALID_HANDLE_VALUE) 
    {
        return running_executables;
    }

    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(process_snapshot, &process_entry)) 
    {
        CloseHandle(process_snapshot);
        return running_executables;
    }

    do 
    {
        HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_entry.th32ProcessID);
        if (process_handle) 
        {
            char file_path[MAX_PATH];
            if (GetModuleFileNameExA(process_handle, NULL, file_path, MAX_PATH))
            {
                running_executables.push_back(file_path);
            }
            CloseHandle(process_handle);
        }
    } while (Process32Next(process_snapshot, &process_entry));

    CloseHandle(process_snapshot);
    return running_executables;
}

auto ida_pro::copyright::scan() -> bool
{
    std::vector<std::string> running_executables = get_running_executables();

    for (const auto& executable : running_executables)
    {
        if (check_copyright(executable))
        {
            return true;
        }
    }
    return false;
}

#endif
