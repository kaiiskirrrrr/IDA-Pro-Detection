#ifndef FILES_CXX
#define FILES_CXX

#include "detection.hpp"
#include <windows.h>

auto ida_pro::file_list::search_directory(const std::string& directory, const std::vector<std::string>& filenames) const noexcept -> bool
{
    WIN32_FIND_DATAA find_file_data;
    HANDLE h_find = FindFirstFileA((directory + "\\*").c_str(), &find_file_data);

    if (h_find == INVALID_HANDLE_VALUE) 
    {
        return false;
    }
    do
    {
        const std::string file_or_dir = find_file_data.cFileName;
        if (file_or_dir == "." or file_or_dir == "..")
            continue;

        const std::string full_path = directory + "\\" + file_or_dir;

        if (find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (full_path == "C:\\Windows")
                continue;

            if (search_directory(full_path, filenames))
            {
                FindClose(h_find);
                return true;
            }
        }
        else
        {
            for (const auto& filename : filenames)
            {
                if (file_or_dir == filename)
                {
                    FindClose(h_find);
                    return true;
                }
            }
        }
    } while (FindNextFileA(h_find, &find_file_data) != 0);

    FindClose(h_find);
    return false;
}

auto ida_pro::file_list::scan() const noexcept -> bool
{
    const std::vector<std::string> ida_filenames =
    {
        "idaq.exe", "idaq64.exe", "ida64.exe", "ida.exe", "idacolor.cf", "ida.key", "ida.idc", "idc.idc"
    };

    const std::vector<std::string> root_directories =
    {
        "C:\\", "D:\\", "E:\\",
    };

    for (const auto& root : root_directories)
    {
        if (search_directory(root, ida_filenames))
        {
            return true;
        }
    }

    return false;
}
#endif 