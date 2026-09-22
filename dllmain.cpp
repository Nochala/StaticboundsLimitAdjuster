#include <Windows.h>

#include "CrashDiagnostics.h"
#include "Logger.h"

#include <cstring>

namespace StaticBoundsLimitPatch
{
    bool PrepareEnhancedBootstrap();
}

namespace
{
    volatile LONG g_installWorkerStarted = 0;
    volatile LONG g_installWorkerFinished = 0;

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

    DWORD WINAPI InstallWorker(LPVOID)
    {
        char logPath[MAX_PATH] = {};
        BuildLogPath(logPath, sizeof(logPath));
        if (logPath[0] != '\0')
            Logger::Initialize(logPath, true);

        Logger::WriteLine("Loader     : deferred initialization outside DllMain");

        __try
        {
            StaticBoundsLimitPatch::Install();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Logger::WriteLine("");
            Logger::WriteLine("[FAILURE]");
            Logger::WriteLine("Stage  : deferred installation");
            Logger::WriteLine("Reason : unexpected structured exception while resolving or installing the patch");
            Logger::WriteLine("Action : rolling back any patch state instead of allowing the ASI to terminate GTA V");
            StaticBoundsLimitPatch::Uninstall();
        }

        Logger::Flush();
        InterlockedExchange(&g_installWorkerFinished, 1);
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(module);

        __try
        {
            StaticBoundsLimitPatch::PrepareEnhancedBootstrap();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // The deferred installer will report/handle unsupported builds.
        }

        if (InterlockedCompareExchange(&g_installWorkerStarted, 1, 0) == 0)
        {
            HANDLE worker = CreateThread(
                nullptr,
                0,
                &InstallWorker,
                nullptr,
                0,
                nullptr);

            if (worker != nullptr)
            {
                CloseHandle(worker);
            }
            else
            {

                InterlockedExchange(&g_installWorkerFinished, 1);
            }
        }
        break;
    }

    case DLL_PROCESS_DETACH:

        if (reserved == nullptr &&
            (InterlockedCompareExchange(&g_installWorkerFinished, 0, 0) != 0 ||
             StaticBoundsLimitPatch::IsInstalled()))
        {
            StaticBoundsLimitPatch::Uninstall();
            Logger::Shutdown();
        }
        break;
    }

    return TRUE;
}
