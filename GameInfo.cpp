#include "GameInfo.h"

#include <cstring>

namespace
{
    char g_executablePath[MAX_PATH] = {};
    char g_executableName[MAX_PATH] = {};
    uintptr_t g_moduleBase = 0;
    size_t g_moduleSize = 0;
    bool g_isEnhanced = false;
    bool g_initialized = false;

    const char* BaseName(const char* path)
    {
        if (path == nullptr)
            return "";

        const char* slash = strrchr(path, '\\');
        return slash != nullptr ? slash + 1 : path;
    }

    bool IsExecutableProtection(DWORD protect)
    {
        if ((protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
            return false;

        switch (protect & 0xFF)
        {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }
}

bool GameInfo::Initialize()
{
    if (g_initialized)
        return g_moduleBase != 0;

    const HMODULE gameModule = GetModuleHandleA(nullptr);
    if (gameModule == nullptr)
        return false;

    if (GetModuleFileNameA(gameModule, g_executablePath, MAX_PATH) == 0)
        return false;

    strncpy_s(
        g_executableName,
        BaseName(g_executablePath),
        _TRUNCATE);

    g_isEnhanced =
        _stricmp(g_executableName, "GTA5_Enhanced.exe") == 0;

    const uintptr_t base =
        reinterpret_cast<uintptr_t>(gameModule);

    __try
    {
        const IMAGE_DOS_HEADER* dos =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        const IMAGE_NT_HEADERS64* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                base + static_cast<uintptr_t>(dos->e_lfanew));

        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return false;
        }

        g_moduleBase = base;
        g_moduleSize =
            static_cast<size_t>(nt->OptionalHeader.SizeOfImage);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        g_moduleBase = 0;
        g_moduleSize = 0;
        return false;
    }

    g_initialized = g_moduleBase != 0 && g_moduleSize != 0;
    return g_initialized;
}

bool GameInfo::IsEnhanced()
{
    return g_isEnhanced;
}

const char* GameInfo::ExecutablePath()
{
    return g_executablePath;
}

const char* GameInfo::ExecutableName()
{
    return g_executableName;
}

uintptr_t GameInfo::ModuleBase()
{
    return g_moduleBase;
}

size_t GameInfo::ModuleSize()
{
    return g_moduleSize;
}

bool GameInfo::IsInsideGameModule(uintptr_t address)
{
    return g_moduleBase != 0 &&
        address >= g_moduleBase &&
        address < (g_moduleBase + g_moduleSize);
}

uintptr_t GameInfo::ToGameRva(uintptr_t address)
{
    return IsInsideGameModule(address)
        ? address - g_moduleBase
        : 0;
}

bool GameInfo::IsExecutableAddress(uintptr_t address)
{
    if (address == 0)
        return false;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(
            reinterpret_cast<const void*>(address),
            &mbi,
            sizeof(mbi)) == 0)
    {
        return false;
    }

    return mbi.State == MEM_COMMIT &&
        IsExecutableProtection(mbi.Protect);
}
