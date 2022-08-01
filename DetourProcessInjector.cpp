// DetourProcessInjector.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

#include <iostream>
#include <Windows.h>
#include <detours.h>
#include <tlhelp32.h>

DWORD GetProcessMainThread(DWORD dwProcID)
{
  DWORD dwMainThreadID = 0;
  ULONGLONG ullMinCreateTime = MAXULONGLONG;

  HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hThreadSnap != INVALID_HANDLE_VALUE) {
    THREADENTRY32 th32;
    th32.dwSize = sizeof(THREADENTRY32);
    BOOL bOK = TRUE;
    for (bOK = Thread32First(hThreadSnap, &th32); bOK;
         bOK = Thread32Next(hThreadSnap, &th32)) {
      if (th32.th32OwnerProcessID == dwProcID) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
                                    TRUE, th32.th32ThreadID);
        if (hThread) {
          FILETIME afTimes[4] = {0};
          if (GetThreadTimes(hThread,
                             &afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) {
            ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime,
                                              afTimes[0].dwHighDateTime);
            if (ullTest && ullTest < ullMinCreateTime) {
              ullMinCreateTime = ullTest;
              dwMainThreadID = th32.th32ThreadID; // let it be main... :)
            }
          }
          CloseHandle(hThread);
        }
      }
    }
#ifndef UNDER_CE
    CloseHandle(hThreadSnap);
#else
    CloseToolhelp32Snapshot(hThreadSnap);
#endif
  }

  if (dwMainThreadID) {
    return dwMainThreadID;
  }
  else
    return NULL;
}

int main()
{
    std::wcout << L"Detours Process Injector" << std::endl;
    std::wcout << L"Insert Process ID: ";
    DWORD processId;
    std::cin >> processId;
    auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        auto error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL );
        std::wcout << (LPTSTR)lpMsgBuf << std::endl;
    }
    else
    {
        auto threadId = GetProcessMainThread(processId);
        if (threadId == NULL)
        {
            return 1;
        }
        auto hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, threadId);
        if (hThread == NULL)
        {
            auto error = GetLastError();
            LPVOID lpMsgBuf;
            FormatMessage(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                error,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR) &lpMsgBuf,
                0, NULL );
            std::wcout << (LPTSTR)lpMsgBuf << std::endl;
        }
        else
        {
            SuspendThread(hThread);
            std::wcout << L"Thread suspended. Press enter, to run. ";
            std::wstring buff;
            std::wcin >> buff;
            LPCSTR pathToLib = ".\\PriDLL32.dll";
            if (!DetourUpdateProcessWithDll(hProcess, &pathToLib, 1) &&
                !DetourProcessViaHelperW(processId,
                                         pathToLib,
                                         CreateProcessW)) 
            {

                TerminateProcess(hProcess, ~0u);
                CloseHandle(hProcess);
                return FALSE;
            }
            ResumeThread(hThread);
            std::wcout << L"DLL injected succesfully!" << std::endl;
            CloseHandle(hProcess);
        }
    }
}