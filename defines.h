#pragma once
#include <Psapi.h>

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

using MessageBoxW_t = int( WINAPI* )( HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType );
using VirtualAllocEx_t = LPVOID( WINAPI* )( HANDLE process, LPVOID address, SIZE_T size, DWORD type, DWORD protect );
using SetCursorPos_t = BOOL ( WINAPI* ) ( const int x, const int y );

using ValidateCall_t = bool( __cdecl* )( uintptr_t retaddr );
static ValidateCall_t validate_call_original{ nullptr };

bool detect_hook( void* address, LPCSTR name )
{
	// first byte is a jmp instruction
	if ( *( ( unsigned char* ) address ) == 0xE9 )
	{
		DWORD jumpTargetRelative = *( ( PDWORD ) ( ( char* ) address + 1 ) );
		PDWORD jumpTarget = ( PDWORD ) ( ( DWORD ) address + 5 /* instruction pointer after our jmp instruction */ + jumpTargetRelative );

		char moduleNameBuffer[ 512 ];
		GetMappedFileNameA(
			GetCurrentProcess( ),
			jumpTarget,
			moduleNameBuffer,
			512
		);

		char msg[ 512 ];
		sprintf( msg, "[dll]: %s hooked by module %s", name, moduleNameBuffer );
		MessageBoxA( NULL, msg, "title", MB_OK );

		return true;
	}
	return false;
}

void syscall_msgbox( const wchar_t* body, const wchar_t* caption )
{
	UNICODE_STRING msgBody;
	UNICODE_STRING msgCaption;

	ULONG ErrorResponse;

	msgBody.Length = ( wcslen( body ) + 1 ) * sizeof( wchar_t );
	msgBody.MaximumLength = msgBody.Length;
	msgBody.Buffer = ( PWSTR ) body;

	msgCaption.Length = ( wcslen( caption ) + 1 ) * sizeof( wchar_t );
	msgCaption.MaximumLength = msgCaption.Length;
	msgCaption.Buffer = ( PWSTR ) caption;

	const ULONG_PTR msgParams[ ] = {
	( ULONG_PTR ) &msgBody,
	( ULONG_PTR ) &msgCaption,
	( ULONG_PTR ) ( MB_OK )
	};

	NtRaiseHardError( 0x50000018L, 0x00000003L, 3, ( PULONG_PTR ) msgParams, NULL, &ErrorResponse );
}