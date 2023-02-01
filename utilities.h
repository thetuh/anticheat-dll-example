#pragma once

static std::vector<std::optional<std::uint8_t>> PatternToBytes( const std::string_view szPattern )
{
	std::vector<std::optional<std::uint8_t>> vecBytes = { };
	auto itBegin = szPattern.cbegin( );
	const auto itEnd = szPattern.cend( );

	// convert pattern into bytes
	while ( itBegin < itEnd )
	{
		// check is current byte a wildcard
		if ( *itBegin == '?' )
		{
			// check is two-character wildcard
			if ( ++itBegin; *itBegin == '?' )
				++itBegin;

			// ignore that
			vecBytes.emplace_back( std::nullopt );
		}
		// check is not space
		else if ( *itBegin != ' ' )
		{
			// convert current 4 bits to hex
			std::uint8_t uByte = static_cast< std::uint8_t >( ( ( *itBegin >= 'A' ? ( ( ( *itBegin - 'A' ) & ( ~( 'a' ^ 'A' ) ) ) + 10 ) : ( *itBegin <= '9' ? *itBegin - '0' : 0x0 ) ) | 0xF0 ) << 4 );

			// convert next 4 bits to hex and assign to byte
			if ( ++itBegin; *itBegin != ' ' )
				uByte |= static_cast< std::uint8_t >( *itBegin >= 'A' ? ( ( ( *itBegin - 'A' ) & ( ~( 'a' ^ 'A' ) ) ) + 10 ) : ( *itBegin <= '9' ? *itBegin - '0' : 0x0 ) );

			vecBytes.emplace_back( uByte );
		}

		++itBegin;
	}

	return vecBytes;
}

static void* GetModuleBaseHandle( const std::string_view szModuleName )
{
	const _PEB32* pPEB = reinterpret_cast< _PEB32* >( __readfsdword( 0x30 ) ); // mov eax, fs:[0x30]
	//const _TEB32* pTEB = reinterpret_cast<_TEB32*>(__readfsdword(0x18)); // mov eax, fs:[0x18]
	//const _PEB32* pPEB = pTEB->ProcessEnvironmentBlock;

	if ( szModuleName.empty( ) )
		return pPEB->ImageBaseAddress;

	const std::wstring wszModuleName( szModuleName.begin( ), szModuleName.end( ) );

	for ( LIST_ENTRY* pListEntry = pPEB->Ldr->InLoadOrderModuleList.Flink; pListEntry != &pPEB->Ldr->InLoadOrderModuleList; pListEntry = pListEntry->Flink )
	{
		const _LDR_DATA_TABLE_ENTRY* pEntry = CONTAINING_RECORD( pListEntry, _LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

		if ( pEntry->BaseDllName.Buffer && wszModuleName.compare( pEntry->BaseDllName.Buffer ) == 0 )
			return pEntry->DllBase;
	}

	return nullptr;
}

static std::uintptr_t FindPattern( const std::uint8_t* uRegionStart, const std::uintptr_t uRegionSize, const std::string_view szPattern )
{
	const std::vector<std::optional<std::uint8_t>> vecBytes = PatternToBytes( szPattern );

	// check for bytes sequence match
	for ( std::uintptr_t i = 0U; i < uRegionSize - vecBytes.size( ); ++i )
	{
		bool bByteFound = true;

		for ( std::uintptr_t s = 0U; s < vecBytes.size( ); ++s )
		{
			// compare byte and skip if wildcard
			if ( vecBytes[ s ].has_value( ) && uRegionStart[ i + s ] != vecBytes[ s ].value( ) )
			{
				bByteFound = false;
				break;
			}
		}

		// return valid address
		if ( bByteFound )
			return reinterpret_cast< std::uintptr_t >( &uRegionStart[ i ] );
	}

	return 0U;
}

static std::uintptr_t FindPattern( const std::string_view szModuleName, const std::string_view szPattern )
{
	void* hModule = GetModuleBaseHandle( szModuleName );

	if ( hModule == nullptr )
		return { };

	const std::uint8_t* uModuleAddress = static_cast< std::uint8_t* >( hModule );
	const IMAGE_DOS_HEADER* pDosHeader = static_cast< IMAGE_DOS_HEADER* >( hModule );
	const IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast< const IMAGE_NT_HEADERS* >( uModuleAddress + pDosHeader->e_lfanew );

	return FindPattern( uModuleAddress, pNtHeaders->OptionalHeader.SizeOfImage, szPattern );
}