#include <Windows.h>

#include "CrashDiagnostics.h"
#include "Logger.h"

#include <cstring>

namespace
{
    void BuildLogPath(char* output, size_t outputCapacity)
    {
        if (output == nullptr || outputCapacity == 0)
            return;

        output[0] = '\0';

        char executablePath[MAX_PATH] = {};
        if (GetModuleFileNameA(nullptr, executablePath, MAX_PATH) == 0)
            return;

        char* slash = strrchr(executablePath, '\\');
        if (slash != nullptr)
            *(slash + 1) = '\0';

        static const char kLogFileName[] = "StaticBoundLimitAdjuster.log";
        const size_t directoryLength = strlen(executablePath);
        if (directoryLength + sizeof(kLogFileName) > outputCapacity)
            return;

        memcpy(output, executablePath, directoryLength);
        memcpy(output + directoryLength, kLogFileName, sizeof(kLogFileName));
    }
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        char logPath[MAX_PATH] = {};
        BuildLogPath(logPath, sizeof(logPath));
        if (logPath[0] != '\0')
            Logger::Initialize(logPath, true);

        StaticBoundsLimitPatch::Install();
        Logger::Flush();
        break;
    }

    case DLL_PROCESS_DETACH:
        StaticBoundsLimitPatch::Uninstall();
        Logger::Shutdown();
        break;
    }

    return TRUE;
}
