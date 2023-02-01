
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <string_view>
#include <cstdint>
#include <vector>
#include <optional>
#include <bcrypt.h>

#include "x86RetSpoof.h"
#include "minhook/MinHook.h"
#include "syscall/syscalls.h"
#include "defines.h"
#include "pe32.h"
#include "utilities.h"

extern "C" void* internal_cleancall_wow64_gate{ nullptr };

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved )
{
    if ( fdwReason == DLL_PROCESS_ATTACH )
    {
        if ( hinstDLL )
            DisableThreadLibraryCalls( hinstDLL );

        internal_cleancall_wow64_gate = ( void* ) __readfsdword( 0xC0 );

        /* calling functions even directly through their export address will still be intercepted and flagged by our "anti-cheat" */

        const MessageBoxW_t messagebox{ reinterpret_cast< MessageBoxW_t >( GetProcAddress( GetModuleHandle( L"User32.dll" ), "MessageBoxW" ) ) };
        messagebox( NULL, L"[dll]: succesfully injected into target process", L"title", MB_OK );

        const VirtualAllocEx_t virtualallocex{ reinterpret_cast< VirtualAllocEx_t >( GetProcAddress( GetModuleHandle( L"Kernel32.dll" ), "VirtualAllocEx" ) ) };
        void* address{ virtualallocex( GetCurrentProcess( ), nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
        if ( !address )
            messagebox( NULL, L"[dll]: failed to allocate virtual memory", L"title", MB_OK | MB_ICONERROR );
        else
            messagebox( NULL, L"[dll]: successfully allocated virtual memory", L"title", MB_OK );

        VirtualFree( address, sizeof address, MEM_RELEASE );

        /* detect detours/trampolines by checking for jmps (not a great way of doing this, could be vastly improved) */
        if ( detect_hook( messagebox, "msgbox" ) )
        {
            /* potentially hook the hook? */
        }

        if ( detect_hook( virtualallocex, "virtualalloc" ) )
        {
            /* potentially hook the hook? */
        }

        /* bypass messagebox hook via direct syscall but will still be picked up by the instrumentation callback */
        syscall_msgbox( L"bypassed messagebox hook through direct sycall", L"title" );

        /* spoofed return address call (this will not be flagged by the check) */
        x86RetSpoof::invokeStdcall<int>( ( uintptr_t ) messagebox, FindPattern( "ac_emulator.exe", "FF 23" ), NULL, L"spoofed retaddr call", L"title", MB_OK );

        void* address_2{ };
        SIZE_T region_size{ 0x1000 };
        if ( NT_ERROR( NtAllocateVirtualMemory( (HANDLE)-1, &address_2, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
            printf( "could not allocate virtual memory\n" );

        printf( "allocated memory via syscall!\n" );

        /* use native api setcursorpos to bypass hook (ntusersetcursorpos) */
        const HMODULE win32u_dll = ( HMODULE ) GetModuleBaseHandle( "win32u.dll" );
        if ( win32u_dll )
        {
            const SetCursorPos_t NtUserSetCursorPos{ reinterpret_cast< SetCursorPos_t >( GetProcAddress( win32u_dll, "NtUserSetCursorPos" ) ) };
            if ( NtUserSetCursorPos )
            {
                messagebox( NULL, L"[dll]: found NtUserSetCursorPos", L"title", MB_OK );
                messagebox( NULL, L"[dll]: setting mouse pos to (0, 0)", L"title", MB_OK );

                NtUserSetCursorPos( 0, 0 );
            }
            else
                messagebox( NULL, L"[dll]: could not find NtUserSetCursorPos", L"title", MB_OK | MB_ICONERROR );
        }

        messagebox( NULL, L"[dll]: successfully completed code execution", L"title", MB_OK );
    }

    return TRUE;

    /* freeing the library crashes/doesn't work if it's manual mapped */
}