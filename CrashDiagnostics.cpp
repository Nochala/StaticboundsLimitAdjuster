#include "CrashDiagnostics.h"

#include "GameInfo.h"
#include "Logger.h"

#include <Windows.h>
#include <winver.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace
{

    constexpr const char* kAdjusterVersion = "1.0.1";
    constexpr uint32_t kStaticBoundsHash = 0x2CDFE406UL;
    constexpr uint32_t kDefaultStaticBoundsLimit = 16000;
    constexpr uint32_t kMaximumStaticBoundsLimit = 100000;
    constexpr uint32_t kExpectedStaticBoundsStride = 16;

    constexpr size_t kCapacityOffset = 0x18;
    constexpr size_t kStrideOffset = 0x1C;

    const unsigned char kEnhancedNamedPoolInitPattern[] =
    {
        0x48, 0x89, 0xC8,
        0x48, 0x8B, 0x4C, 0x24, 0x28,
        0x48, 0x89, 0x08,
        0x44, 0x89, 0x48, 0x1C,
        0x0F, 0x57, 0xC0,
        0x0F, 0x11, 0x40, 0x08,
        0xC7, 0x40, 0x18, 0x00, 0x00, 0x00, 0x00,
        0x81, 0x60, 0x28, 0x00, 0x00, 0x00, 0xC0,
        0xC3
    };
    const char kEnhancedNamedPoolInitMask[] =
        "xxxxxxx?xxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    constexpr size_t kEnhancedNamedPoolInitSemanticSize = 29;

    const unsigned char kEnhancedAtPoolAllocatePattern[] =
    {
        0x56, 0x57, 0x48, 0x83, 0xEC, 0x28,
        0x48, 0x89, 0xCE,
        0x48, 0x63, 0x51, 0x18,
        0x48, 0x63, 0x79, 0x1C,
        0x48, 0x0F, 0xAF, 0xFA,
        0x48, 0x83, 0xC7, 0x07,
        0x48, 0x83, 0xE7, 0xF8,
        0x48, 0x8B, 0x09,
        0x48, 0x01, 0xFA,
        0x48, 0x8B, 0x01,
        0xFF, 0x50, 0x08
    };
    const char kEnhancedAtPoolAllocateMask[] =
        "xxxxx?xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    constexpr size_t kEnhancedAtPoolAllocateSemanticSize = 29;

    const unsigned char kGetSizeOfPoolBodyPattern[] =
    {
        0x45, 0x33, 0xDB, 0x44, 0x8B, 0xD2, 0x66, 0x44,
        0x39, 0x59, 0x00, 0x74, 0x00, 0x44, 0x0F, 0xB7,
        0x49, 0x00, 0x33, 0xD2, 0x41, 0x8B, 0xC2, 0x41,
        0xF7, 0xF1, 0x48, 0x8B, 0x41, 0x00, 0x48, 0x8B,
        0x0C, 0xD0, 0xEB, 0x00, 0x44, 0x3B, 0x11, 0x74,
        0x00, 0x48, 0x8B, 0x49
    };
    const char kGetSizeOfPoolBodyMask[] =
        "xxxxxxxxxx?x?xxxx?xxxxxxxxxxx?xxxxx?xxxx?xxx";
    constexpr size_t kGetSizeOfPoolBodySemanticSize = 26;

    // PoolManager Legacy callsite.
    const unsigned char kGetSizeCallPatternPoolManager[] =
    {
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8D, 0x4F, 0x38, 0x41, 0xB0, 0x01
    };
    const char kGetSizeCallMaskPoolManager[] = "x????xxxxxxx";

    // RagePoolExtender Legacy callsite.
    const unsigned char kGetSizeCallPatternRagePoolExtender[] =
    {
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x8D, 0x78, 0x11
    };
    const char kGetSizeCallMaskRagePoolExtender[] = "x????xxx";

    const unsigned char kGetSizeCallPatternRoadBlock[] =
    {
        0xBA, 0x01, 0xC7, 0x2C, 0xF7,
        0x41, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xE8, 0x00, 0x00, 0x00, 0x00
    };
    const char kGetSizeCallMaskRoadBlock[] = "xxxxxx?xxxxx????";
    constexpr size_t kGetSizeRoadBlockCallOffset = 11;

    static_assert(
        sizeof(kEnhancedNamedPoolInitPattern) == sizeof(kEnhancedNamedPoolInitMask) - 1,
        "Enhanced named-pool pattern/mask length mismatch");
    static_assert(
        sizeof(kEnhancedAtPoolAllocatePattern) == sizeof(kEnhancedAtPoolAllocateMask) - 1,
        "Enhanced allocator pattern/mask length mismatch");
    static_assert(
        sizeof(kGetSizeOfPoolBodyPattern) == sizeof(kGetSizeOfPoolBodyMask) - 1,
        "GetSizeOfPool body pattern/mask length mismatch");
    static_assert(
        sizeof(kGetSizeCallPatternPoolManager) == sizeof(kGetSizeCallMaskPoolManager) - 1,
        "PoolManager callsite pattern/mask length mismatch");
    static_assert(
        sizeof(kGetSizeCallPatternRagePoolExtender) == sizeof(kGetSizeCallMaskRagePoolExtender) - 1,
        "RagePoolExtender callsite pattern/mask length mismatch");
    static_assert(
        sizeof(kGetSizeCallPatternRoadBlock) == sizeof(kGetSizeCallMaskRoadBlock) - 1,
        "RoadBlock callsite pattern/mask length mismatch");

    struct InlineHook
    {
        unsigned char* target = nullptr;
        unsigned char* relay = nullptr;
        unsigned char* trampoline = nullptr;
        unsigned char* atomicWindow = nullptr;
        size_t patchLength = 0;
        unsigned char original[16] = {};
        uint64_t atomicOriginal = 0;
        uint64_t atomicPatched = 0;
        bool atomicWrite = false;
        bool installed = false;
    };

    struct CallRedirect
    {
        unsigned char* callsite = nullptr;
        unsigned char* relay = nullptr;
        unsigned char* atomicWindow = nullptr;
        unsigned char original[5] = {};
        uint64_t atomicOriginal = 0;
        uint64_t atomicPatched = 0;
        bool atomicWrite = false;
        bool installed = false;
    };

    // Enhanced validated function entry 
    constexpr size_t kNamedPoolInitPatchLength = 8; 
    constexpr size_t kAtPoolAllocatePatchLength = 6; 

    using NamedPoolInitFn = uintptr_t(*)(
        void* pool,
        const char* name,
        uintptr_t arg3,
        uint32_t stride,
        void* allocator);

    using AtPoolAllocateFn = uintptr_t(*)(void* pool);
    using GetSizeOfPoolFn = int64_t(*)(void* configManager, uint32_t poolHash, int defaultSize);

    InlineHook g_namedPoolInitHook;
    InlineHook g_atPoolAllocateHook;
    InlineHook g_getSizeOfPoolInlineHook;
    CallRedirect g_getSizeCallRedirect;
    NamedPoolInitFn g_originalNamedPoolInit = nullptr;
    AtPoolAllocateFn g_originalAtPoolAllocate = nullptr;
    GetSizeOfPoolFn g_originalGetSizeOfPool = nullptr;

    void* g_staticBoundsPool = nullptr;
    uint32_t g_configuredLimit = kDefaultStaticBoundsLimit;
    uint32_t g_originalCapacity = 0;
    uint32_t g_appliedCapacity = 0;
    volatile LONG g_staticBoundsSeen = 0;
    volatile LONG g_staticBoundsAllocated = 0;
    volatile LONG g_configLoadState = 0;
    volatile LONG g_loggingReady = 0;
    volatile LONG g_runtimeLogEmitted = 0;
    volatile LONG g_staticBoundsLogEmitted = 0;
    volatile LONG g_earlyEnhancedBootstrap = 0;
    bool g_installed = false;

    void ReadGameVersion(char* output, size_t outputSize)
    {
        if (output == nullptr || outputSize == 0)
            return;

        strncpy_s(output, outputSize, "unknown", _TRUNCATE);

        HMODULE module = GetModuleHandleA(nullptr);
        if (module == nullptr)
            return;

        HRSRC resource = FindResourceA(
            module,
            MAKEINTRESOURCEA(1),
            MAKEINTRESOURCEA(16));
        if (resource == nullptr)
            return;

        HGLOBAL loaded = LoadResource(module, resource);
        const DWORD resourceSize = SizeofResource(module, resource);
        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(
            loaded != nullptr ? LockResource(loaded) : nullptr);
        if (bytes == nullptr || resourceSize < sizeof(VS_FIXEDFILEINFO))
            return;

        for (DWORD i = 0; i + sizeof(VS_FIXEDFILEINFO) <= resourceSize; i += 2)
        {
            const VS_FIXEDFILEINFO* info =
                reinterpret_cast<const VS_FIXEDFILEINFO*>(bytes + i);
            if (info->dwSignature != 0xFEEF04BD)
                continue;

            std::snprintf(
                output,
                outputSize,
                "%u.%u.%u.%u",
                HIWORD(info->dwFileVersionMS),
                LOWORD(info->dwFileVersionMS),
                HIWORD(info->dwFileVersionLS),
                LOWORD(info->dwFileVersionLS));
            output[outputSize - 1] = '\0';
            return;
        }
    }

    void LogStartupSummary()
    {
        char version[64] = {};
        ReadGameVersion(version, sizeof(version));

        Logger::Format("StaticBoundLimitAdjuster v%s", kAdjusterVersion);
        Logger::WriteLine("------------------------------------------------------------");
        Logger::Format("Executable : %s", GameInfo::ExecutableName());
        Logger::Format("Edition    : %s", GameInfo::IsEnhanced() ? "Enhanced" : "Legacy");
        Logger::Format("Version    : %s", version);
        Logger::Format(
            "Image      : base=0x%016llX size=0x%llX",
            static_cast<unsigned long long>(GameInfo::ModuleBase()),
            static_cast<unsigned long long>(GameInfo::ModuleSize()));
        Logger::Format("Limit floor: %u", g_configuredLimit);
        Logger::WriteLine("Resolver   : signature-based multi-build compatibility");
    }

    void LogFailure(
        const char* stage,
        const char* reason,
        const char* details,
        bool rolledBack)
    {
        Logger::WriteLine("");
        Logger::WriteLine("[FAILURE]");
        Logger::Format("Stage  : %s", stage != nullptr ? stage : "unknown");
        Logger::Format("Reason : %s", reason != nullptr ? reason : "unknown failure");
        if (details != nullptr && *details != '\0')
            Logger::Format("Details: %s", details);
        Logger::Format(
            "Memory : %s",
            rolledBack
                ? "no patch remains installed"
                : "no memory was modified");
        Logger::WriteLine("Possible causes:");
        Logger::WriteLine("  - This GTA V build changed one or more code signatures.");
        Logger::WriteLine("  - Another ASI/mod patched the same code before this adjuster loaded.");
        Logger::WriteLine("  - The executable code was not ready/unpacked when the adjuster initialized.");
        Logger::WriteLine("Keep this log and report the GTA edition/version when requesting an update.");
        Logger::Flush();
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

    bool IsReadableRange(const void* address, size_t size)
    {
        if (address == nullptr || size == 0)
            return false;

        const uintptr_t start = reinterpret_cast<uintptr_t>(address);
        const uintptr_t end = start + size;
        if (end < start)
            return false;

        uintptr_t cursor = start;
        while (cursor < end)
        {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) == 0)
                return false;

            if (mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
            {
                return false;
            }

            const uintptr_t regionEnd =
                reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (regionEnd <= cursor)
                return false;

            cursor = regionEnd < end ? regionEnd : end;
        }

        return true;
    }

    bool MatchesPatternBytes(
        const unsigned char* bytes,
        const unsigned char* pattern,
        const char* mask,
        size_t size)
    {
        if (bytes == nullptr || pattern == nullptr || mask == nullptr || size == 0)
            return false;

        for (size_t i = 0; i < size; ++i)
        {
            if (mask[i] != '?' && bytes[i] != pattern[i])
                return false;
        }

        return true;
    }

    bool FitsAtomicWindow8(
        const void* address,
        size_t size)
    {
        if (address == nullptr || size == 0 || size > sizeof(uint64_t))
            return false;

        const uintptr_t value = reinterpret_cast<uintptr_t>(address);
        const size_t offset = static_cast<size_t>(value & 7);
        return offset + size <= sizeof(uint64_t);
    }

    bool TryAtomicPatchWindow8(
        unsigned char* address,
        const unsigned char* replacement,
        size_t replacementSize,
        const unsigned char* expectedOriginal,
        unsigned char*& window,
        uint64_t& originalWord,
        uint64_t& patchedWord)
    {
        window = nullptr;
        originalWord = 0;
        patchedWord = 0;

        if (address == nullptr || replacement == nullptr ||
            replacementSize == 0 || replacementSize > sizeof(uint64_t))
        {
            return false;
        }

        const uintptr_t addressValue = reinterpret_cast<uintptr_t>(address);
        const uintptr_t windowValue = addressValue & ~static_cast<uintptr_t>(7);
        const size_t offset = static_cast<size_t>(addressValue - windowValue);
        if (offset + replacementSize > sizeof(uint64_t))
            return false;

        unsigned char* candidateWindow =
            reinterpret_cast<unsigned char*>(windowValue);
        if (!IsReadableRange(candidateWindow, sizeof(uint64_t)))
            return false;

        uint64_t expected = 0;
        memcpy(&expected, candidateWindow, sizeof(expected));

        if (expectedOriginal != nullptr)
        {
            unsigned char expectedBytes[sizeof(uint64_t)] = {};
            memcpy(expectedBytes, &expected, sizeof(expectedBytes));
            if (memcmp(
                    expectedBytes + offset,
                    expectedOriginal,
                    replacementSize) != 0)
            {
                return false;
            }
        }

        unsigned char desiredBytes[sizeof(uint64_t)] = {};
        memcpy(desiredBytes, &expected, sizeof(desiredBytes));
        memcpy(desiredBytes + offset, replacement, replacementSize);

        uint64_t desired = 0;
        memcpy(&desired, desiredBytes, sizeof(desired));

        DWORD oldProtect = 0;
        if (!VirtualProtect(
                candidateWindow,
                sizeof(uint64_t),
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            return false;
        }

        const LONG64 observed = InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(candidateWindow),
            static_cast<LONG64>(desired),
            static_cast<LONG64>(expected));

        DWORD ignored = 0;
        VirtualProtect(
            candidateWindow,
            sizeof(uint64_t),
            oldProtect,
            &ignored);

        if (static_cast<uint64_t>(observed) != expected)
            return false;

        FlushInstructionCache(
            GetCurrentProcess(),
            candidateWindow,
            sizeof(uint64_t));

        window = candidateWindow;
        originalWord = expected;
        patchedWord = desired;
        return true;
    }

    bool TryAtomicRestoreWindow8(
        unsigned char* window,
        uint64_t patchedWord,
        uint64_t originalWord)
    {
        if (window == nullptr ||
            (reinterpret_cast<uintptr_t>(window) & 7) != 0 ||
            !IsReadableRange(window, sizeof(uint64_t)))
        {
            return false;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(
                window,
                sizeof(uint64_t),
                PAGE_EXECUTE_READWRITE,
                &oldProtect))
        {
            return false;
        }

        const LONG64 observed = InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(window),
            static_cast<LONG64>(originalWord),
            static_cast<LONG64>(patchedWord));

        DWORD ignored = 0;
        VirtualProtect(
            window,
            sizeof(uint64_t),
            oldProtect,
            &ignored);

        if (static_cast<uint64_t>(observed) != patchedWord)
            return false;

        FlushInstructionCache(
            GetCurrentProcess(),
            window,
            sizeof(uint64_t));
        return true;
    }

    uint32_t ReadConfiguredLimit()
    {
        char iniPath[MAX_PATH] = {};
        const char* executablePath = GameInfo::ExecutablePath();

        if (executablePath == nullptr || *executablePath == '\0')
            return kDefaultStaticBoundsLimit;

        const char* slash = strrchr(executablePath, '\\');
        if (slash == nullptr)
            return kDefaultStaticBoundsLimit;

        static const char kIniFileName[] = "StaticBoundLimitAdjuster.ini";
        const size_t directoryLength = static_cast<size_t>(slash - executablePath) + 1;

        if (directoryLength + sizeof(kIniFileName) > sizeof(iniPath))
            return kDefaultStaticBoundsLimit;

        memcpy(iniPath, executablePath, directoryLength);
        memcpy(iniPath + directoryLength, kIniFileName, sizeof(kIniFileName));

        UINT requested = GetPrivateProfileIntA(
            "STATICBOUNDS_SETTINGS",
            "STATICBOUNDS_SIZE",
            kDefaultStaticBoundsLimit,
            iniPath);

        if (requested == 0)
            requested = kDefaultStaticBoundsLimit;
        if (requested > kMaximumStaticBoundsLimit)
            requested = kMaximumStaticBoundsLimit;

        return static_cast<uint32_t>(requested);
    }

    uint32_t EnsureConfiguredLimitLoaded()
    {
        LONG state = InterlockedCompareExchange(&g_configLoadState, 0, 0);
        if (state == 2)
            return g_configuredLimit;

        if (InterlockedCompareExchange(&g_configLoadState, 1, 0) == 0)
        {
            g_configuredLimit = ReadConfiguredLimit();
            InterlockedExchange(&g_configLoadState, 2);
            return g_configuredLimit;
        }

        while (InterlockedCompareExchange(&g_configLoadState, 0, 0) != 2)
        {

            // reachable during startup 
        }

        return g_configuredLimit;
    }

    unsigned char* FindUniqueExecutablePatternMasked(
        const unsigned char* pattern,
        const char* mask,
        size_t patternSize,
        size_t& matchCount)
    {
        matchCount = 0;
        unsigned char* unique = nullptr;

        const uintptr_t imageStart = GameInfo::ModuleBase();
        const uintptr_t imageEnd = imageStart + GameInfo::ModuleSize();
        if (imageStart == 0 || imageEnd <= imageStart || pattern == nullptr ||
            mask == nullptr || patternSize == 0)
        {
            return nullptr;
        }

        uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &mbi, sizeof(mbi)) == 0)
                break;

            const uintptr_t regionStart =
                reinterpret_cast<uintptr_t>(mbi.BaseAddress) < imageStart
                    ? imageStart
                    : reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (regionEnd > imageEnd)
                regionEnd = imageEnd;

            if (mbi.State == MEM_COMMIT &&
                IsExecutableProtection(mbi.Protect) &&
                regionEnd > regionStart &&
                static_cast<size_t>(regionEnd - regionStart) >= patternSize)
            {
                const unsigned char* bytes = reinterpret_cast<const unsigned char*>(regionStart);
                const size_t regionSize = static_cast<size_t>(regionEnd - regionStart);

                for (size_t i = 0; i + patternSize <= regionSize; ++i)
                {
                    bool matched = true;
                    for (size_t j = 0; j < patternSize; ++j)
                    {
                        if (mask[j] != '?' && bytes[i + j] != pattern[j])
                        {
                            matched = false;
                            break;
                        }
                    }

                    if (!matched)
                        continue;

                    ++matchCount;
                    if (matchCount == 1)
                        unique = const_cast<unsigned char*>(bytes + i);
                    else
                        unique = nullptr;
                }
            }

            if (regionEnd <= cursor)
                break;
            cursor = regionEnd;
        }

        return matchCount == 1 ? unique : nullptr;
    }

    unsigned char* ResolveRel32Call(unsigned char* callsite)
    {
        if (callsite == nullptr || !IsReadableRange(callsite, 5) || callsite[0] != 0xE8)
            return nullptr;

        int32_t rel = 0;
        memcpy(&rel, callsite + 1, sizeof(rel));
        unsigned char* target = callsite + 5 + rel;

        const uintptr_t imageStart = GameInfo::ModuleBase();
        const uintptr_t imageEnd = imageStart + GameInfo::ModuleSize();
        const uintptr_t targetAddress = reinterpret_cast<uintptr_t>(target);
        if (targetAddress < imageStart || targetAddress >= imageEnd)
            return nullptr;

        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(target, &mbi, sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT || !IsExecutableProtection(mbi.Protect))
        {
            return nullptr;
        }

        return target;
    }

    unsigned char* FindUniqueStaticBoundsGetSizeCallsite(
        unsigned char* getSizeOfPool,
        size_t& matchCount)
    {
        matchCount = 0;
        unsigned char* unique = nullptr;

        if (getSizeOfPool == nullptr)
            return nullptr;

        const uintptr_t imageStart = GameInfo::ModuleBase();
        const uintptr_t imageEnd = imageStart + GameInfo::ModuleSize();
        if (imageStart == 0 || imageEnd <= imageStart)
            return nullptr;

        const unsigned char hashLoad[] =
        {
            0xBA,
            static_cast<unsigned char>(kStaticBoundsHash & 0xFF),
            static_cast<unsigned char>((kStaticBoundsHash >> 8) & 0xFF),
            static_cast<unsigned char>((kStaticBoundsHash >> 16) & 0xFF),
            static_cast<unsigned char>((kStaticBoundsHash >> 24) & 0xFF)
        };

        constexpr size_t kMaximumCallDistance = 64;

        uintptr_t cursor = imageStart;
        while (cursor < imageEnd)
        {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(
                    reinterpret_cast<const void*>(cursor),
                    &mbi,
                    sizeof(mbi)) == 0)
            {
                break;
            }

            const uintptr_t regionStart =
                reinterpret_cast<uintptr_t>(mbi.BaseAddress) < imageStart
                    ? imageStart
                    : reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t regionEnd =
                reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (regionEnd > imageEnd)
                regionEnd = imageEnd;

            if (mbi.State == MEM_COMMIT &&
                IsExecutableProtection(mbi.Protect) &&
                regionEnd > regionStart &&
                static_cast<size_t>(regionEnd - regionStart) >= sizeof(hashLoad) + 5)
            {
                unsigned char* bytes =
                    reinterpret_cast<unsigned char*>(regionStart);
                const size_t regionSize =
                    static_cast<size_t>(regionEnd - regionStart);

                for (size_t i = 0; i + sizeof(hashLoad) + 5 <= regionSize; ++i)
                {
                    if (memcmp(bytes + i, hashLoad, sizeof(hashLoad)) != 0)
                        continue;

                    const size_t searchStart = i + sizeof(hashLoad);
                    const size_t searchEnd =
                        (searchStart + kMaximumCallDistance < regionSize)
                            ? searchStart + kMaximumCallDistance
                            : regionSize;

                    for (size_t j = searchStart; j + 5 <= searchEnd; ++j)
                    {
                        if (bytes[j] != 0xE8)
                            continue;

                        unsigned char* callsite = bytes + j;
                        if (ResolveRel32Call(callsite) != getSizeOfPool)
                            continue;

                        ++matchCount;
                        if (matchCount == 1)
                            unique = callsite;
                        else
                            unique = nullptr;

                        break;
                    }
                }
            }

            if (regionEnd <= cursor)
                break;
            cursor = regionEnd;
        }

        return matchCount == 1 ? unique : nullptr;
    }

    struct GetSizeResolverStats
    {
        size_t bodyFull = 0;
        size_t bodySemantic = 0;
        size_t poolManagerCall = 0;
        size_t ragePoolExtenderCall = 0;
        size_t roadBlockCall = 0;
        size_t staticBoundsCall = 0;
        bool disagreement = false;
    };

    struct EnhancedResolverStats
    {
        size_t namedFull = 0;
        size_t namedSemantic = 0;
        size_t allocateFull = 0;
        size_t allocateSemantic = 0;
        bool disagreement = false;
    };

    EnhancedResolverStats g_earlyEnhancedStats;
    unsigned char* g_earlyEnhancedNamedPoolInit = nullptr;
    unsigned char* g_earlyEnhancedAtPoolAllocate = nullptr;
    const char* g_earlyEnhancedNamedLocator = nullptr;
    const char* g_earlyEnhancedAllocateLocator = nullptr;

    bool MergeTargetCandidate(
        unsigned char*& selected,
        unsigned char* candidate,
        const char* locator,
        const char*& selectedLocator,
        bool& disagreement)
    {
        if (candidate == nullptr)
            return true;

        if (selected == nullptr)
        {
            selected = candidate;
            selectedLocator = locator;
            return true;
        }

        if (selected != candidate)
        {
            disagreement = true;
            return false;
        }

        return true;
    }

    unsigned char* ResolveEnhancedNamedPoolInit(
        const char*& locatorUsed,
        EnhancedResolverStats& stats)
    {
        locatorUsed = nullptr;
        unsigned char* selected = nullptr;

        unsigned char* full = FindUniqueExecutablePatternMasked(
            kEnhancedNamedPoolInitPattern,
            kEnhancedNamedPoolInitMask,
            sizeof(kEnhancedNamedPoolInitPattern),
            stats.namedFull);
        if (full != nullptr && stats.namedFull == 1 &&
            !MergeTargetCandidate(
                selected,
                full,
                "Enhanced named pool full signature",
                locatorUsed,
                stats.disagreement))
        {
            return nullptr;
        }

        unsigned char* semantic = FindUniqueExecutablePatternMasked(
            kEnhancedNamedPoolInitPattern,
            kEnhancedNamedPoolInitMask,
            kEnhancedNamedPoolInitSemanticSize,
            stats.namedSemantic);
        if (semantic != nullptr && stats.namedSemantic == 1 &&
            !MergeTargetCandidate(
                selected,
                semantic,
                "Enhanced named pool semantic signature",
                locatorUsed,
                stats.disagreement))
        {
            return nullptr;
        }

        return selected;
    }

    unsigned char* ResolveEnhancedAtPoolAllocate(
        const char*& locatorUsed,
        EnhancedResolverStats& stats)
    {
        locatorUsed = nullptr;
        unsigned char* selected = nullptr;

        unsigned char* full = FindUniqueExecutablePatternMasked(
            kEnhancedAtPoolAllocatePattern,
            kEnhancedAtPoolAllocateMask,
            sizeof(kEnhancedAtPoolAllocatePattern),
            stats.allocateFull);
        if (full != nullptr && stats.allocateFull == 1 &&
            !MergeTargetCandidate(
                selected,
                full,
                "Enhanced allocator full signature",
                locatorUsed,
                stats.disagreement))
        {
            return nullptr;
        }

        unsigned char* semantic = FindUniqueExecutablePatternMasked(
            kEnhancedAtPoolAllocatePattern,
            kEnhancedAtPoolAllocateMask,
            kEnhancedAtPoolAllocateSemanticSize,
            stats.allocateSemantic);
        if (semantic != nullptr && stats.allocateSemantic == 1 &&
            !MergeTargetCandidate(
                selected,
                semantic,
                "Enhanced allocator semantic signature",
                locatorUsed,
                stats.disagreement))
        {
            return nullptr;
        }

        return selected;
    }

    unsigned char* ResolveGetSizeOfPool(
        bool includeLegacyCallsites,
        const char*& locatorUsed,
        GetSizeResolverStats& stats,
        unsigned char*& safeRedirectCallsite,
        const char*& safeRedirectLocator)
    {
        locatorUsed = nullptr;
        safeRedirectCallsite = nullptr;
        safeRedirectLocator = nullptr;
        unsigned char* selected = nullptr;

        unsigned char* bodyFull = FindUniqueExecutablePatternMasked(
            kGetSizeOfPoolBodyPattern,
            kGetSizeOfPoolBodyMask,
            sizeof(kGetSizeOfPoolBodyPattern),
            stats.bodyFull);
        if (bodyFull != nullptr && stats.bodyFull == 1 &&
            !MergeTargetCandidate(
                selected,
                bodyFull,
                "GetSizeOfPool full body",
                locatorUsed,
                stats.disagreement))
        {
            return nullptr;
        }

        unsigned char* bodySemantic = FindUniqueExecutablePatternMasked(
            kGetSizeOfPoolBodyPattern,
            kGetSizeOfPoolBodyMask,
            kGetSizeOfPoolBodySemanticSize,
            stats.bodySemantic);
        if (bodySemantic != nullptr && stats.bodySemantic == 1 &&
            !MergeTargetCandidate(
                selected,
                bodySemantic,
                "GetSizeOfPool semantic body",
                locatorUsed,
                stats.disagreement))
        {
            return nullptr;
        }

        if (includeLegacyCallsites)
        {
            unsigned char* poolManagerCall = FindUniqueExecutablePatternMasked(
                kGetSizeCallPatternPoolManager,
                kGetSizeCallMaskPoolManager,
                sizeof(kGetSizeCallPatternPoolManager),
                stats.poolManagerCall);
            if (poolManagerCall != nullptr && stats.poolManagerCall == 1)
            {
                unsigned char* target = ResolveRel32Call(poolManagerCall);
                if (target == nullptr ||
                    !MergeTargetCandidate(
                        selected,
                        target,
                        "PoolManager callsite",
                        locatorUsed,
                        stats.disagreement))
                {
                    return nullptr;
                }

                safeRedirectCallsite = poolManagerCall;
                safeRedirectLocator = "PoolManager callsite";
            }

            unsigned char* rageCall = FindUniqueExecutablePatternMasked(
                kGetSizeCallPatternRagePoolExtender,
                kGetSizeCallMaskRagePoolExtender,
                sizeof(kGetSizeCallPatternRagePoolExtender),
                stats.ragePoolExtenderCall);
            if (rageCall != nullptr && stats.ragePoolExtenderCall == 1)
            {
                unsigned char* target = ResolveRel32Call(rageCall);
                if (target == nullptr ||
                    !MergeTargetCandidate(
                        selected,
                        target,
                        "RagePoolExtender callsite",
                        locatorUsed,
                        stats.disagreement))
                {
                    return nullptr;
                }

            }
        }

        unsigned char* roadBlock = FindUniqueExecutablePatternMasked(
            kGetSizeCallPatternRoadBlock,
            kGetSizeCallMaskRoadBlock,
            sizeof(kGetSizeCallPatternRoadBlock),
            stats.roadBlockCall);
        if (roadBlock != nullptr && stats.roadBlockCall == 1)
        {
            unsigned char* target = ResolveRel32Call(
                roadBlock + kGetSizeRoadBlockCallOffset);
            if (target == nullptr)
                return nullptr;

            if (!includeLegacyCallsites || selected == nullptr)
            {
                if (!MergeTargetCandidate(
                        selected,
                        target,
                        "CRoadBlock::InitPool callsite",
                        locatorUsed,
                        stats.disagreement))
                {
                    return nullptr;
                }
            }
        }

        if (selected != nullptr && !stats.disagreement)
        {
            unsigned char* staticBoundsCall =
                FindUniqueStaticBoundsGetSizeCallsite(
                    selected,
                    stats.staticBoundsCall);


            if (staticBoundsCall != nullptr &&
                stats.staticBoundsCall == 1)
            {
                safeRedirectCallsite = staticBoundsCall;
                safeRedirectLocator = "StaticBounds hash anchored callsite";
            }
        }

        return selected;
    }

    bool FitsRel32(const void* fromAfterInstruction, const void* target)
    {
        const intptr_t delta =
            reinterpret_cast<intptr_t>(target) -
            reinterpret_cast<intptr_t>(fromAfterInstruction);
        return delta >= std::numeric_limits<int32_t>::min() &&
            delta <= std::numeric_limits<int32_t>::max();
    }

    unsigned char* AllocateNear(const void* target, size_t size)
    {
        SYSTEM_INFO si = {};
        GetSystemInfo(&si);

        const uintptr_t granularity = static_cast<uintptr_t>(si.dwAllocationGranularity);
        const uintptr_t targetAddress = reinterpret_cast<uintptr_t>(target);
        const uintptr_t maxDistance = 0x70000000ULL;

        uintptr_t minimum = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
        uintptr_t maximum = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

        if (targetAddress > maxDistance && minimum < targetAddress - maxDistance)
            minimum = targetAddress - maxDistance;
        if (maximum > targetAddress + maxDistance)
            maximum = targetAddress + maxDistance;

        const uintptr_t alignedTarget = targetAddress - (targetAddress % granularity);

        for (uintptr_t distance = 0; distance <= maxDistance; distance += granularity)
        {
            const uintptr_t candidates[2] =
            {
                alignedTarget >= distance ? alignedTarget - distance : 0,
                alignedTarget <= maximum - distance ? alignedTarget + distance : 0
            };

            for (size_t i = 0; i < 2; ++i)
            {
                const uintptr_t candidate = candidates[i];
                if (candidate < minimum || candidate > maximum || candidate == 0)
                    continue;

                MEMORY_BASIC_INFORMATION mbi = {};
                if (VirtualQuery(reinterpret_cast<const void*>(candidate), &mbi, sizeof(mbi)) == 0)
                    continue;

                if (mbi.State != MEM_FREE)
                    continue;

                unsigned char* memory = reinterpret_cast<unsigned char*>(
                    VirtualAlloc(
                        reinterpret_cast<void*>(candidate),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE));

                if (memory != nullptr)
                    return memory;
            }
        }

        return nullptr;
    }

    bool WriteRel32Jump(unsigned char* instruction, const void* target)
    {
        if (instruction == nullptr || target == nullptr)
            return false;

        unsigned char* after = instruction + 5;
        if (!FitsRel32(after, target))
            return false;

        const intptr_t delta =
            reinterpret_cast<intptr_t>(target) - reinterpret_cast<intptr_t>(after);
        const int32_t rel = static_cast<int32_t>(delta);

        instruction[0] = 0xE9;
        memcpy(instruction + 1, &rel, sizeof(rel));
        return true;
    }

    bool IsRel32BranchTo(
        const unsigned char* instruction,
        unsigned char opcode,
        const void* target)
    {
        if (instruction == nullptr || target == nullptr ||
            !IsReadableRange(instruction, 5) || instruction[0] != opcode)
        {
            return false;
        }

        int32_t rel = 0;
        memcpy(&rel, instruction + 1, sizeof(rel));
        const unsigned char* resolved = instruction + 5 + rel;
        return resolved == target;
    }

    bool InstallCallRedirect(
        CallRedirect& redirect,
        unsigned char* callsite,
        const void* replacement,
        bool requireAtomic = false)
    {
        if (callsite == nullptr || replacement == nullptr ||
            !IsReadableRange(callsite, 5) || callsite[0] != 0xE8)
        {
            return false;
        }

        unsigned char* relay = AllocateNear(callsite, 0x1000);
        if (relay == nullptr)
            return false;

        relay[0] = 0x48;
        relay[1] = 0xB8;
        const uint64_t replacementAddress = reinterpret_cast<uint64_t>(replacement);
        memcpy(relay + 2, &replacementAddress, sizeof(replacementAddress));
        relay[10] = 0xFF;
        relay[11] = 0xE0;

        if (!FitsRel32(callsite + 5, relay))
        {
            VirtualFree(relay, 0, MEM_RELEASE);
            return false;
        }

        memcpy(redirect.original, callsite, sizeof(redirect.original));

        const intptr_t delta =
            reinterpret_cast<intptr_t>(relay) -
            reinterpret_cast<intptr_t>(callsite + 5);
        const int32_t rel = static_cast<int32_t>(delta);

        unsigned char patch[5] = { 0xE8, 0, 0, 0, 0 };
        memcpy(patch + 1, &rel, sizeof(rel));

        bool patched = false;
        unsigned char* atomicWindow = nullptr;
        uint64_t atomicOriginal = 0;
        uint64_t atomicPatched = 0;

        if (TryAtomicPatchWindow8(
                callsite,
                patch,
                sizeof(patch),
                redirect.original,
                atomicWindow,
                atomicOriginal,
                atomicPatched))
        {
            patched = true;
            redirect.atomicWindow = atomicWindow;
            redirect.atomicOriginal = atomicOriginal;
            redirect.atomicPatched = atomicPatched;
            redirect.atomicWrite = true;
        }
        else if (!requireAtomic)
        {

            if (memcmp(callsite, redirect.original, sizeof(redirect.original)) == 0)
            {
                DWORD oldProtect = 0;
                if (VirtualProtect(
                        callsite,
                        sizeof(patch),
                        PAGE_EXECUTE_READWRITE,
                        &oldProtect))
                {
                    memcpy(callsite, patch, sizeof(patch));

                    DWORD ignored = 0;
                    VirtualProtect(
                        callsite,
                        sizeof(patch),
                        oldProtect,
                        &ignored);
                    FlushInstructionCache(
                        GetCurrentProcess(),
                        callsite,
                        sizeof(patch));

                    patched = IsRel32BranchTo(callsite, 0xE8, relay);
                }
            }
        }

        FlushInstructionCache(GetCurrentProcess(), relay, 0x1000);

        if (!patched)
        {
            VirtualFree(relay, 0, MEM_RELEASE);
            return false;
        }

        redirect.callsite = callsite;
        redirect.relay = relay;
        redirect.installed = true;
        return true;
    }

    void RemoveCallRedirect(CallRedirect& redirect)
    {
        if (!redirect.installed || redirect.callsite == nullptr)
            return;

        bool restored = false;

        if (redirect.atomicWrite)
        {
            restored = TryAtomicRestoreWindow8(
                redirect.atomicWindow,
                redirect.atomicPatched,
                redirect.atomicOriginal);
        }
        else if (IsRel32BranchTo(
                     redirect.callsite,
                     0xE8,
                     redirect.relay))
        {
            DWORD oldProtect = 0;
            if (VirtualProtect(
                    redirect.callsite,
                    sizeof(redirect.original),
                    PAGE_EXECUTE_READWRITE,
                    &oldProtect))
            {
                memcpy(
                    redirect.callsite,
                    redirect.original,
                    sizeof(redirect.original));

                DWORD ignored = 0;
                VirtualProtect(
                    redirect.callsite,
                    sizeof(redirect.original),
                    oldProtect,
                    &ignored);
                FlushInstructionCache(
                    GetCurrentProcess(),
                    redirect.callsite,
                    sizeof(redirect.original));
                restored = true;
            }
        }

        if (restored ||
            !IsRel32BranchTo(
                redirect.callsite,
                0xE8,
                redirect.relay))
        {
            redirect = CallRedirect{};
        }
    }

    template <typename TFunction>
    bool InstallInlineHook(
        InlineHook& hook,
        unsigned char* target,
        size_t patchLength,
        const void* replacement,
        TFunction& originalFunction,
        const unsigned char* expectedPattern = nullptr,
        const char* expectedMask = nullptr,
        bool requireAtomic = false)
    {
        if (target == nullptr || replacement == nullptr ||
            patchLength < 5 || patchLength > sizeof(hook.original))
        {
            return false;
        }

        if (!IsReadableRange(target, patchLength))
            return false;

        unsigned char* block = AllocateNear(target, 0x1000);
        if (block == nullptr)
            return false;

        unsigned char* relay = block;
        unsigned char* trampoline = block + 0x40;

        relay[0] = 0x48;
        relay[1] = 0xB8;
        const uint64_t replacementAddress = reinterpret_cast<uint64_t>(replacement);
        memcpy(relay + 2, &replacementAddress, sizeof(replacementAddress));
        relay[10] = 0xFF;
        relay[11] = 0xE0;

        memcpy(hook.original, target, patchLength);

        if (expectedPattern != nullptr && expectedMask != nullptr &&
            !MatchesPatternBytes(
                hook.original,
                expectedPattern,
                expectedMask,
                patchLength))
        {
            VirtualFree(block, 0, MEM_RELEASE);
            return false;
        }

        memcpy(trampoline, hook.original, patchLength);
        if (!WriteRel32Jump(trampoline + patchLength, target + patchLength))
        {
            VirtualFree(block, 0, MEM_RELEASE);
            return false;
        }

        unsigned char patch[sizeof(hook.original)] = {};
        patch[0] = 0xE9;
        if (!FitsRel32(target + 5, relay))
        {
            VirtualFree(block, 0, MEM_RELEASE);
            return false;
        }

        const intptr_t delta =
            reinterpret_cast<intptr_t>(relay) -
            reinterpret_cast<intptr_t>(target + 5);
        const int32_t rel = static_cast<int32_t>(delta);
        memcpy(patch + 1, &rel, sizeof(rel));
        for (size_t i = 5; i < patchLength; ++i)
            patch[i] = 0x90;

        originalFunction = reinterpret_cast<TFunction>(trampoline);

        bool patched = false;
        unsigned char* atomicWindow = nullptr;
        uint64_t atomicOriginal = 0;
        uint64_t atomicPatched = 0;

        if (TryAtomicPatchWindow8(
                target,
                patch,
                patchLength,
                hook.original,
                atomicWindow,
                atomicOriginal,
                atomicPatched))
        {
            patched = true;
            hook.atomicWindow = atomicWindow;
            hook.atomicOriginal = atomicOriginal;
            hook.atomicPatched = atomicPatched;
            hook.atomicWrite = true;
        }
        else if (!requireAtomic)
        {

            if (memcmp(target, hook.original, patchLength) == 0)
            {
                DWORD oldProtect = 0;
                if (VirtualProtect(
                        target,
                        patchLength,
                        PAGE_EXECUTE_READWRITE,
                        &oldProtect))
                {
                    memcpy(target, patch, patchLength);

                    DWORD ignored = 0;
                    VirtualProtect(
                        target,
                        patchLength,
                        oldProtect,
                        &ignored);
                    FlushInstructionCache(
                        GetCurrentProcess(),
                        target,
                        patchLength);

                    patched = IsRel32BranchTo(target, 0xE9, relay);
                }
            }
        }

        FlushInstructionCache(GetCurrentProcess(), block, 0x1000);

        if (!patched)
        {

            originalFunction = nullptr;
            VirtualFree(block, 0, MEM_RELEASE);
            return false;
        }

        hook.target = target;
        hook.relay = relay;
        hook.trampoline = trampoline;
        hook.patchLength = patchLength;
        hook.installed = true;
        return true;
    }

    void RemoveInlineHook(InlineHook& hook)
    {
        if (!hook.installed || hook.target == nullptr || hook.patchLength == 0)
            return;

        bool restored = false;

        if (hook.atomicWrite)
        {
            restored = TryAtomicRestoreWindow8(
                hook.atomicWindow,
                hook.atomicPatched,
                hook.atomicOriginal);
        }
        else if (IsRel32BranchTo(
                     hook.target,
                     0xE9,
                     hook.relay))
        {
            DWORD oldProtect = 0;
            if (VirtualProtect(
                    hook.target,
                    hook.patchLength,
                    PAGE_EXECUTE_READWRITE,
                    &oldProtect))
            {
                memcpy(hook.target, hook.original, hook.patchLength);

                DWORD ignored = 0;
                VirtualProtect(
                    hook.target,
                    hook.patchLength,
                    oldProtect,
                    &ignored);
                FlushInstructionCache(
                    GetCurrentProcess(),
                    hook.target,
                    hook.patchLength);
                restored = true;
            }
        }


        if (restored ||
            !IsRel32BranchTo(
                hook.target,
                0xE9,
                hook.relay))
        {
            hook = InlineHook{};
        }
    }

    void LogEnhancedRuntimeStateIfNeeded()
    {
        if (InterlockedCompareExchange(&g_loggingReady, 0, 0) == 0 ||
            InterlockedCompareExchange(&g_staticBoundsSeen, 0, 0) == 0 ||
            g_staticBoundsPool == nullptr)
        {
            return;
        }

        if (InterlockedCompareExchange(&g_runtimeLogEmitted, 1, 0) != 0)
            return;

        Logger::WriteLine("");
        Logger::WriteLine("[Runtime]");
        Logger::Format(
            "StaticBounds pool identified: 0x%016llX (stride=%u)",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(g_staticBoundsPool)),
            kExpectedStaticBoundsStride);
        Logger::Flush();
    }

    void LogEnhancedStaticBoundsStateIfNeeded()
    {
        if (InterlockedCompareExchange(&g_loggingReady, 0, 0) == 0 ||
            InterlockedCompareExchange(&g_staticBoundsAllocated, 0, 0) == 0)
        {
            return;
        }

        if (InterlockedCompareExchange(&g_staticBoundsLogEmitted, 1, 0) != 0)
            return;

        const bool detached =
            !g_atPoolAllocateHook.installed &&
            !g_namedPoolInitHook.installed;

        Logger::WriteLine("");
        Logger::WriteLine("[StaticBounds]");
        Logger::Format("Original capacity : %u", g_originalCapacity);
        Logger::Format("Configured floor  : %u", g_configuredLimit);
        Logger::Format("Applied capacity  : %u", g_appliedCapacity);
        Logger::Format(
            "Result            : %s",
            g_appliedCapacity == g_originalCapacity
                ? "unchanged (already high enough)"
                : "pool size adjusted");
        Logger::Format(
            "Hook state        : %s",
            detached
                ? "detached after StaticBounds allocation"
                : "restore deferred; guarded hooks remain active");
        Logger::Flush();
    }

    bool IsStaticBoundsName(const char* name)
    {
        if (name == nullptr || !IsReadableRange(name, sizeof("StaticBounds")))
            return false;

        return memcmp(name, "StaticBounds", sizeof("StaticBounds")) == 0;
    }

    uintptr_t NamedPoolInitHook(
        void* pool,
        const char* name,
        uintptr_t arg3,
        uint32_t stride,
        void* allocator)
    {
        if (IsStaticBoundsName(name) && stride == kExpectedStaticBoundsStride)
        {
            EnsureConfiguredLimitLoaded();
            g_staticBoundsPool = pool;
            InterlockedCompareExchange(&g_staticBoundsSeen, 1, 0);
            LogEnhancedRuntimeStateIfNeeded();
        }

        return g_originalNamedPoolInit(pool, name, arg3, stride, allocator);
    }

    uintptr_t AtPoolAllocateHook(void* pool)
    {
        bool handledStaticBounds = false;

        if (pool != nullptr && pool == g_staticBoundsPool &&
            IsReadableRange(pool, kStrideOffset + sizeof(uint32_t)))
        {
            unsigned char* bytes = reinterpret_cast<unsigned char*>(pool);
            uint32_t capacity = 0;
            uint32_t stride = 0;
            memcpy(&capacity, bytes + kCapacityOffset, sizeof(capacity));
            memcpy(&stride, bytes + kStrideOffset, sizeof(stride));

            if (stride == kExpectedStaticBoundsStride)
            {
                EnsureConfiguredLimitLoaded();

                const uint32_t applied =
                    capacity < g_configuredLimit ? g_configuredLimit : capacity;

                if (applied != capacity)
                    memcpy(bytes + kCapacityOffset, &applied, sizeof(applied));

                g_originalCapacity = capacity;
                g_appliedCapacity = applied;
                handledStaticBounds = true;
                InterlockedCompareExchange(&g_staticBoundsAllocated, 1, 0);
            }
        }

        const uintptr_t result = g_originalAtPoolAllocate(pool);

        if (handledStaticBounds)
        {
            RemoveInlineHook(g_atPoolAllocateHook);
            RemoveInlineHook(g_namedPoolInitHook);
            LogEnhancedRuntimeStateIfNeeded();
            LogEnhancedStaticBoundsStateIfNeeded();
        }

        return result;
    }

    int64_t GetSizeOfPoolHook(
        void* configManager,
        uint32_t poolHash,
        int defaultSize)
    {
        const int64_t originalSize =
            g_originalGetSizeOfPool(configManager, poolHash, defaultSize);

        if (poolHash != kStaticBoundsHash)
            return originalSize;

        EnsureConfiguredLimitLoaded();

        int64_t appliedSize = originalSize;
        if (originalSize >= 0 &&
            originalSize < static_cast<int64_t>(g_configuredLimit))
        {
            appliedSize = static_cast<int64_t>(g_configuredLimit);
        }

        g_originalCapacity =
            originalSize >= 0 && originalSize <= UINT32_MAX
                ? static_cast<uint32_t>(originalSize)
                : 0;
        g_appliedCapacity =
            appliedSize >= 0 && appliedSize <= UINT32_MAX
                ? static_cast<uint32_t>(appliedSize)
                : 0;

        const bool firstStaticBoundsQuery =
            InterlockedCompareExchange(&g_staticBoundsSeen, 1, 0) == 0;

        if (firstStaticBoundsQuery)
        {
            InterlockedExchange(&g_staticBoundsLogEmitted, 1);

            RemoveCallRedirect(g_getSizeCallRedirect);
            RemoveInlineHook(g_getSizeOfPoolInlineHook);

            const bool detached =
                !g_getSizeCallRedirect.installed &&
                !g_getSizeOfPoolInlineHook.installed;

            Logger::WriteLine("");
            Logger::WriteLine("[StaticBounds]");
            Logger::Format("Original capacity : %lld", static_cast<long long>(originalSize));
            Logger::Format("Configured floor  : %u", g_configuredLimit);
            Logger::Format("Applied capacity  : %lld", static_cast<long long>(appliedSize));
            Logger::Format(
                "Result            : %s",
                appliedSize == originalSize ? "unchanged (already high enough)" : "pool size adjusted");
            Logger::Format(
                "Hook state        : %s",
                detached
                    ? "detached after one StaticBounds query"
                    : "restore deferred; guarded hook remains active");
            Logger::Flush();
        }

        return appliedSize;
    }

    bool InstallGetSizeRedirectPath(
        unsigned char* getSizeOfPool,
        unsigned char* safeRedirectCallsite,
        const char* safeRedirectLocator,
        const char* edition,
        const char* mode,
        const char* locatorUsed,
        const GetSizeResolverStats& stats)
    {
        if (getSizeOfPool == nullptr)
            return false;

        const bool requireAtomicLivePatch =
            edition != nullptr && _stricmp(edition, "Enhanced") == 0;

        const bool canUseCallsite =
            safeRedirectCallsite != nullptr &&
            ResolveRel32Call(safeRedirectCallsite) == getSizeOfPool;

        g_originalGetSizeOfPool = nullptr;

        const char* installedMode = nullptr;
        const char* installedLocator = nullptr;

        if (canUseCallsite)
        {
            g_originalGetSizeOfPool =
                reinterpret_cast<GetSizeOfPoolFn>(getSizeOfPool);

            if (!InstallCallRedirect(
                    g_getSizeCallRedirect,
                    safeRedirectCallsite,
                    reinterpret_cast<const void*>(&GetSizeOfPoolHook),
                    requireAtomicLivePatch))
            {
                g_originalGetSizeOfPool = nullptr;
                LogFailure(
                    "GetSizeOfPool hook installation",
                    "validated GTA callsite could not be redirected",
                    "No executable wide caller scan was attempted.",
                    false);
                return false;
            }

            installedMode = mode != nullptr
                ? mode
                : "validated single callsite redirect";
            installedLocator = safeRedirectLocator != nullptr
                ? safeRedirectLocator
                : "validated GTA callsite";
        }
        else
        {

            constexpr size_t kGetSizeOfPoolPatchLength = 6;
            if (!IsReadableRange(getSizeOfPool, kGetSizeOfPoolPatchLength) ||
                memcmp(
                    getSizeOfPool,
                    kGetSizeOfPoolBodyPattern,
                    kGetSizeOfPoolPatchLength) != 0)
            {
                LogFailure(
                    "GetSizeOfPool hook installation",
                    "no isolated hook point was safe to patch",
                    "The validated single callsite locator was unavailable and the function entry was not pristine. "
                    "The adjuster was left disabled instead of patching unrelated callers.",
                    false);
                return false;
            }

            if (!InstallInlineHook(
                    g_getSizeOfPoolInlineHook,
                    getSizeOfPool,
                    kGetSizeOfPoolPatchLength,
                    reinterpret_cast<const void*>(&GetSizeOfPoolHook),
                    g_originalGetSizeOfPool,
                    kGetSizeOfPoolBodyPattern,
                    kGetSizeOfPoolBodyMask,
                    requireAtomicLivePatch))
            {
                LogFailure(
                    "GetSizeOfPool hook installation",
                    "guarded function entry hook could not be installed",
                    "No executable wide caller scan was attempted.",
                    false);
                return false;
            }

            installedMode = "guarded single-function fallback";
            installedLocator = locatorUsed != nullptr
                ? locatorUsed
                : "validated GetSizeOfPool body";
        }

        g_installed = true;

        Logger::WriteLine("");
        Logger::WriteLine("[Install]");
        Logger::WriteLine("Status     : SUCCESS");
        Logger::Format("Edition    : %s", edition != nullptr ? edition : "unknown");
        Logger::Format("Mode       : %s", installedMode);
        Logger::Format(
            "Target     : GTA+0x%llX",
            static_cast<unsigned long long>(
                getSizeOfPool - reinterpret_cast<unsigned char*>(GameInfo::ModuleBase())));
        Logger::Format("Locator    : %s", installedLocator);
        Logger::Format(
            "Matches    : body=%llu/%llu poolmgr=%llu rage=%llu roadblock=%llu static=%llu",
            static_cast<unsigned long long>(stats.bodyFull),
            static_cast<unsigned long long>(stats.bodySemantic),
            static_cast<unsigned long long>(stats.poolManagerCall),
            static_cast<unsigned long long>(stats.ragePoolExtenderCall),
            static_cast<unsigned long long>(stats.roadBlockCall),
            static_cast<unsigned long long>(stats.staticBoundsCall));
        Logger::WriteLine(
            canUseCallsite
                ? "Callsites  : 1 redirected (signature-validated; no executable-wide caller scan)"
                : "Callsites  : 0 redirected (single guarded function-entry hook)");
        Logger::WriteLine(
            requireAtomicLivePatch
                ? "Safety     : atomic isolated one-shot patch; automatically detached after the StaticBounds query"
                : "Safety     : isolated one shot patch; automatically detached after the StaticBounds query");
        Logger::Flush();
        return true;
    }

    void LogEarlyEnhancedInstallSummary()
    {
        Logger::WriteLine("");
        Logger::WriteLine("[Install]");
        Logger::WriteLine("Status     : SUCCESS");
        Logger::WriteLine("Edition    : Enhanced");
        Logger::WriteLine("Mode       : early atomic one shot pre-allocation StaticBounds hook");
        Logger::Format(
            "Named pool : GTA+0x%llX (%s)",
            static_cast<unsigned long long>(
                g_earlyEnhancedNamedPoolInit -
                reinterpret_cast<unsigned char*>(GameInfo::ModuleBase())),
            g_earlyEnhancedNamedLocator != nullptr
                ? g_earlyEnhancedNamedLocator
                : "validated signature family");
        Logger::Format(
            "Allocator  : GTA+0x%llX (%s)",
            static_cast<unsigned long long>(
                g_earlyEnhancedAtPoolAllocate -
                reinterpret_cast<unsigned char*>(GameInfo::ModuleBase())),
            g_earlyEnhancedAllocateLocator != nullptr
                ? g_earlyEnhancedAllocateLocator
                : "validated signature family");
        Logger::Format(
            "Matches    : named=%llu/%llu allocator=%llu/%llu",
            static_cast<unsigned long long>(g_earlyEnhancedStats.namedFull),
            static_cast<unsigned long long>(g_earlyEnhancedStats.namedSemantic),
            static_cast<unsigned long long>(g_earlyEnhancedStats.allocateFull),
            static_cast<unsigned long long>(g_earlyEnhancedStats.allocateSemantic));
        Logger::WriteLine(
            "Safety     : Enhanced installed during DLL attach before the one time pool bootstrap; INI and logging remain deferred");
        Logger::Flush();
    }

}

namespace StaticBoundsLimitPatch
{
    bool PrepareEnhancedBootstrap()
    {
        if (InterlockedCompareExchange(&g_earlyEnhancedBootstrap, 0, 0) != 0)
            return g_installed;

        if (!GameInfo::Initialize() || !GameInfo::IsEnhanced())
            return false;

        EnhancedResolverStats stats;
        const char* namedLocator = nullptr;
        const char* allocateLocator = nullptr;

        unsigned char* namedPoolInit = ResolveEnhancedNamedPoolInit(
            namedLocator,
            stats);
        unsigned char* atPoolAllocate = ResolveEnhancedAtPoolAllocate(
            allocateLocator,
            stats);

        if (namedPoolInit == nullptr ||
            atPoolAllocate == nullptr ||
            stats.disagreement ||
            !FitsAtomicWindow8(namedPoolInit, kNamedPoolInitPatchLength) ||
            !FitsAtomicWindow8(atPoolAllocate, kAtPoolAllocatePatchLength))
        {
            return false;
        }

        if (!InstallInlineHook(
                g_namedPoolInitHook,
                namedPoolInit,
                kNamedPoolInitPatchLength,
                reinterpret_cast<const void*>(&NamedPoolInitHook),
                g_originalNamedPoolInit,
                kEnhancedNamedPoolInitPattern,
                kEnhancedNamedPoolInitMask,
                true))
        {
            return false;
        }

        if (!InstallInlineHook(
                g_atPoolAllocateHook,
                atPoolAllocate,
                kAtPoolAllocatePatchLength,
                reinterpret_cast<const void*>(&AtPoolAllocateHook),
                g_originalAtPoolAllocate,
                kEnhancedAtPoolAllocatePattern,
                kEnhancedAtPoolAllocateMask,
                true))
        {
            RemoveInlineHook(g_namedPoolInitHook);
            return false;
        }

        g_earlyEnhancedStats = stats;
        g_earlyEnhancedNamedPoolInit = namedPoolInit;
        g_earlyEnhancedAtPoolAllocate = atPoolAllocate;
        g_earlyEnhancedNamedLocator = namedLocator;
        g_earlyEnhancedAllocateLocator = allocateLocator;
        g_installed = true;
        InterlockedExchange(&g_earlyEnhancedBootstrap, 1);
        return true;
    }
}

bool StaticBoundsLimitPatch::Install()
{
    if (!GameInfo::Initialize())
    {
        LogFailure(
            "game initialization",
            "GTA executable image could not be resolved",
            "The main module did not expose a valid 64-bit PE image.",
            false);
        return false;
    }

    EnsureConfiguredLimitLoaded();
    LogStartupSummary();

    if (g_installed &&
        InterlockedCompareExchange(&g_earlyEnhancedBootstrap, 0, 0) != 0)
    {
        LogEarlyEnhancedInstallSummary();
        InterlockedExchange(&g_loggingReady, 1);
        LogEnhancedRuntimeStateIfNeeded();
        LogEnhancedStaticBoundsStateIfNeeded();
        return true;
    }

    if (g_installed)
        return true;

    InterlockedExchange(&g_loggingReady, 1);

    const bool isEnhanced = GameInfo::IsEnhanced();
    const bool isLegacy = _stricmp(GameInfo::ExecutableName(), "GTA5.exe") == 0;
    if (!isEnhanced && !isLegacy)
    {
        char details[256] = {};
        std::snprintf(
            details,
            sizeof(details),
            "Executable '%s' is not GTA5_Enhanced.exe or GTA5.exe.",
            GameInfo::ExecutableName());
        LogFailure("edition detection", "unsupported executable", details, false);
        return false;
    }

    if (isEnhanced)
    {

        GetSizeResolverStats getSizeStats;
        const char* getSizeLocator = nullptr;
        unsigned char* safeRedirectCallsite = nullptr;
        const char* safeRedirectLocator = nullptr;
        unsigned char* getSizeOfPool = ResolveGetSizeOfPool(
            false,
            getSizeLocator,
            getSizeStats,
            safeRedirectCallsite,
            safeRedirectLocator);

        if (getSizeOfPool != nullptr &&
            !getSizeStats.disagreement &&
            safeRedirectCallsite != nullptr &&
            FitsAtomicWindow8(safeRedirectCallsite, 5))
        {
            return InstallGetSizeRedirectPath(
                getSizeOfPool,
                safeRedirectCallsite,
                safeRedirectLocator,
                "Enhanced",
                "atomic one-shot StaticBounds query redirect",
                getSizeLocator,
                getSizeStats);
        }


        EnhancedResolverStats enhancedStats;
        const char* namedLocator = nullptr;
        const char* allocateLocator = nullptr;

        unsigned char* namedPoolInit = ResolveEnhancedNamedPoolInit(
            namedLocator,
            enhancedStats);
        unsigned char* atPoolAllocate = ResolveEnhancedAtPoolAllocate(
            allocateLocator,
            enhancedStats);

        bool directHookAttempted = false;
        if (namedPoolInit != nullptr &&
            atPoolAllocate != nullptr &&
            !enhancedStats.disagreement &&
            FitsAtomicWindow8(namedPoolInit, kNamedPoolInitPatchLength) &&
            FitsAtomicWindow8(atPoolAllocate, kAtPoolAllocatePatchLength))
        {
            directHookAttempted = true;

            if (InstallInlineHook(
                    g_namedPoolInitHook,
                    namedPoolInit,
                    kNamedPoolInitPatchLength,
                    reinterpret_cast<const void*>(&NamedPoolInitHook),
                    g_originalNamedPoolInit,
                    kEnhancedNamedPoolInitPattern,
                    kEnhancedNamedPoolInitMask,
                    true))
            {
                if (InstallInlineHook(
                        g_atPoolAllocateHook,
                        atPoolAllocate,
                        kAtPoolAllocatePatchLength,
                        reinterpret_cast<const void*>(&AtPoolAllocateHook),
                        g_originalAtPoolAllocate,
                        kEnhancedAtPoolAllocatePattern,
                        kEnhancedAtPoolAllocateMask,
                        true))
                {
                    g_installed = true;

                    Logger::WriteLine("");
                    Logger::WriteLine("[Install]");
                    Logger::WriteLine("Status     : SUCCESS");
                    Logger::WriteLine("Edition    : Enhanced");
                    Logger::WriteLine("Mode       : atomic one shot pre-allocation StaticBounds hook");
                    Logger::Format(
                        "Named pool : GTA+0x%llX (%s)",
                        static_cast<unsigned long long>(
                            namedPoolInit - reinterpret_cast<unsigned char*>(GameInfo::ModuleBase())),
                        namedLocator != nullptr
                            ? namedLocator
                            : "validated signature family");
                    Logger::Format(
                        "Allocator  : GTA+0x%llX (%s)",
                        static_cast<unsigned long long>(
                            atPoolAllocate - reinterpret_cast<unsigned char*>(GameInfo::ModuleBase())),
                        allocateLocator != nullptr
                            ? allocateLocator
                            : "validated signature family");
                    Logger::Format(
                        "Matches    : named=%llu/%llu allocator=%llu/%llu",
                        static_cast<unsigned long long>(enhancedStats.namedFull),
                        static_cast<unsigned long long>(enhancedStats.namedSemantic),
                        static_cast<unsigned long long>(enhancedStats.allocateFull),
                        static_cast<unsigned long long>(enhancedStats.allocateSemantic));
                    Logger::WriteLine(
                        "Safety     : pristineentry atomic hooks; both are detached after StaticBounds allocation");
                    Logger::Flush();
                    return true;
                }


                RemoveInlineHook(g_namedPoolInitHook);
                if (g_namedPoolInitHook.installed)
                {
                    LogFailure(
                        "Enhanced hook rollback",
                        "the first atomic hook could not be restored safely",
                        "The adjuster refused to install an additional fallback hook while its previous entry patch was still active.",
                        false);
                    return false;
                }
            }
        }

        if (getSizeOfPool != nullptr && !getSizeStats.disagreement)
        {
            return InstallGetSizeRedirectPath(
                getSizeOfPool,
                nullptr,
                nullptr,
                "Enhanced",
                "atomic one shot GetSizeOfPool fallback",
                getSizeLocator,
                getSizeStats);
        }

        char details[896] = {};
        std::snprintf(
            details,
            sizeof(details),
            "Enhanced locators: named=%llu/%llu allocator=%llu/%llu disagreement=%s; "
            "GetSizeOfPool: body=%llu/%llu roadblock=%llu static=%llu disagreement=%s."
            "%s",
            static_cast<unsigned long long>(enhancedStats.namedFull),
            static_cast<unsigned long long>(enhancedStats.namedSemantic),
            static_cast<unsigned long long>(enhancedStats.allocateFull),
            static_cast<unsigned long long>(enhancedStats.allocateSemantic),
            enhancedStats.disagreement ? "yes" : "no",
            static_cast<unsigned long long>(getSizeStats.bodyFull),
            static_cast<unsigned long long>(getSizeStats.bodySemantic),
            static_cast<unsigned long long>(getSizeStats.roadBlockCall),
            static_cast<unsigned long long>(getSizeStats.staticBoundsCall),
            getSizeStats.disagreement ? "yes" : "no",
            directHookAttempted
                ? " Atomic Enhanced entry hooks were attempted and rolled back."
                : "");
        LogFailure(
            "Enhanced compatibility resolver",
            "no validated atomic patch path was available for this build",
            details,
            directHookAttempted);
        return false;
    }

    GetSizeResolverStats legacyStats;
    const char* locatorUsed = nullptr;
    unsigned char* safeRedirectCallsite = nullptr;
    const char* safeRedirectLocator = nullptr;
    unsigned char* getSizeOfPool = ResolveGetSizeOfPool(
        true,
        locatorUsed,
        legacyStats,
        safeRedirectCallsite,
        safeRedirectLocator);

    if (getSizeOfPool == nullptr || legacyStats.disagreement)
    {
        char details[768] = {};
        std::snprintf(
            details,
            sizeof(details),
            "Legacy locators: body=%llu/%llu poolmanager=%llu rage=%llu roadblock=%llu disagreement=%s.",
            static_cast<unsigned long long>(legacyStats.bodyFull),
            static_cast<unsigned long long>(legacyStats.bodySemantic),
            static_cast<unsigned long long>(legacyStats.poolManagerCall),
            static_cast<unsigned long long>(legacyStats.ragePoolExtenderCall),
            static_cast<unsigned long long>(legacyStats.roadBlockCall),
            legacyStats.disagreement ? "yes" : "no");
        LogFailure(
            "Legacy compatibility resolver",
            "GetSizeOfPool could not be resolved safely",
            details,
            false);
        return false;
    }

    return InstallGetSizeRedirectPath(
        getSizeOfPool,
        safeRedirectCallsite,
        safeRedirectLocator,
        "Legacy",
        safeRedirectLocator != nullptr &&
            strcmp(safeRedirectLocator, "StaticBounds hash-anchored callsite") == 0
                ? "one shot StaticBounds query redirect"
                : "one shot validated pool-size redirect",
        locatorUsed,
        legacyStats);
}

void StaticBoundsLimitPatch::Uninstall()
{
    RemoveCallRedirect(g_getSizeCallRedirect);
    RemoveInlineHook(g_getSizeOfPoolInlineHook);
    RemoveInlineHook(g_atPoolAllocateHook);
    RemoveInlineHook(g_namedPoolInitHook);

    g_staticBoundsPool = nullptr;
    g_originalCapacity = 0;
    g_appliedCapacity = 0;
    g_staticBoundsSeen = 0;
    g_staticBoundsAllocated = 0;
    g_configLoadState = 0;
    g_loggingReady = 0;
    g_runtimeLogEmitted = 0;
    g_staticBoundsLogEmitted = 0;
    g_earlyEnhancedBootstrap = 0;
    g_earlyEnhancedStats = EnhancedResolverStats{};
    g_earlyEnhancedNamedPoolInit = nullptr;
    g_earlyEnhancedAtPoolAllocate = nullptr;
    g_earlyEnhancedNamedLocator = nullptr;
    g_earlyEnhancedAllocateLocator = nullptr;
    g_installed = false;
}

bool StaticBoundsLimitPatch::IsInstalled()
{
    return g_installed;
}

uint32_t StaticBoundsLimitPatch::ConfiguredLimit()
{
    return g_configuredLimit;
}
