#ifndef REGISTRY_CXX
#define REGISTRY_CXX

#include "detection.hpp"
#include <windows.h>

auto ida_pro::registry_keys::scan() const noexcept -> bool
{
    const std::vector<std::string> hex_rays_keys =
    {
        "SOFTWARE\\Hex-Rays",
        "SOFTWARE\\Hex-Rays\\IDA",
        "SOFTWARE\\Hex-Rays\\IDA Pro",
        "SOFTWARE\\Hex-Rays\\IDA Freeware",
        "SOFTWARE\\Hex-Rays SA",
        "SOFTWARE\\Hex-Rays SA\\IDA",
        "SOFTWARE\\Hex-Rays SA\\IDA Pro",
        "SOFTWARE\\Hex-Rays SA\\IDA Freeware"
    };

    for (const auto& key : hex_rays_keys)
    {
        HKEY hKey;
        LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey);

        if (result == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}
#endif
