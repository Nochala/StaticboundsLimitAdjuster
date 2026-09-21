#pragma once

#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace GameInfo
{
    bool Initialize();

    bool IsEnhanced();
    const char* ExecutablePath();
    const char* ExecutableName();

    uintptr_t ModuleBase();
    size_t ModuleSize();
    bool IsInsideGameModule(uintptr_t address);
    uintptr_t ToGameRva(uintptr_t address);
    bool IsExecutableAddress(uintptr_t address);
}
