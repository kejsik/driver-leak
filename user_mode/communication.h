#pragma warning(disable  : 4996).

class rcdrv
{
private:
	typedef LONG_PTR(__cdecl* pfunc_hk_t)(ULONG_PTR a1);
	pfunc_hk_t pHookFunc = (pfunc_hk_t)NULL;

	typedef enum _request_codes
	{
		request_base = 0x6AAE0,
		request_process_base = 0x6AAE1,
		request_read = 0x6AAE2,
		request_write = 0x6AAE3,
		request_success = 0x6AAE4,
		request_unique = 0x6AAE5,
		request_guardreg = 0x6AAE6,
		request_cr3 = 0x6AAE7,
	}request_codes, * prequest_codes;

	typedef struct _read_request {
		uint32_t pid;
		uintptr_t address;
		void* buffer;
		size_t size;
	} read_request, * pread_request;

	typedef struct _write_request {
		uint32_t pid;
		uintptr_t address;
		void* buffer;
		size_t size;
	} write_request, * pwrite_request;

	typedef struct _base_request {
		uint32_t pid;
		uintptr_t handle;
		WCHAR name[260];
	} base_request, * pbase_request;

	typedef struct _guardreg_request {
		uintptr_t allocation;
	} guardreg_request, * pguardreg_request;



	typedef struct _process_base_request {
		uint32_t pid;
		uintptr_t handle;
	} process_base_request, * p_process_base_request;

	typedef struct _cr3_request {
		uint32_t pid;
	} cr3_request, * pcr3_request;


	typedef struct _request_data
	{
		uint32_t unique;
		request_codes code;
		void* data;
	}request_data, * prequest_data;

	int32_t pid = 0;
public:
	uint64_t _guardedregion;
	inline bool attach( int _pid )
	{
		if (!_pid)
			return false;

		pid = _pid;

		return true;
	}

	inline bool reqcr3()
	{
		cr3_request data{ 0 };
		data.pid = pid;



		return send_cmd(&data, request_cr3);
	}

	inline auto send_cmd( void* data, request_codes code ) -> bool
	{
		if (!data || !code)
		{
			return false;
		}

		request_data request{ 0 };

		request.unique = request_unique;
		request.data = data;
		request.code = code;

		const auto result = pHookFunc((uintptr_t) & request );

		if (result != request_success)
		{
			return false;
		}

		return true;
	}

	inline auto get_module_base( const std::string module_name ) -> const std::uintptr_t
	{
		base_request data{ 0 };

		data.pid = pid;
		data.handle = 0;

		std::wstring wstr{ std::wstring( module_name.begin( ), module_name.end( ) ) };

		memset( data.name, 0, sizeof( WCHAR ) * 260 );
		wcscpy( data.name, wstr.c_str( ) );

		send_cmd( &data, request_base );

		return data.handle;
	}

	inline auto guarded_region() -> uintptr_t
	{
		guardreg_request data{ 0 };
		send_cmd(&data, request_guardreg);
		_guardedregion = data.allocation;
		return data.allocation;
	}

	inline auto get_process_base( ) -> const std::uintptr_t
	{
		process_base_request data{ 0 };

		data.pid = pid;
		data.handle = 0;

		send_cmd( &data, request_process_base );

		return data.handle;
	}

	HMODULE ensure_dll_load( )
	{
#define LOAD_DLL(str) LoadLibrary((str))

		LOAD_DLL(L"user32.dll" );

#undef LOAD_DLL
		return LoadLibrary(L"win32u.dll" );
	}

	inline auto initialize( ) -> bool
	{
		if (!pHookFunc)
		{
			HMODULE hDll = GetModuleHandleA("win32u.dll" );
			if (!hDll)
			{
				hDll = ensure_dll_load( );
				if (!hDll) return false;
			}

			pHookFunc = (pfunc_hk_t)GetProcAddress( hDll, ( "NtGdiUnloadPrinterDriver" ) );
			if (!pHookFunc)
			{
				pHookFunc = (pfunc_hk_t)NULL;
				return false;
			}
		}

		pid = GetCurrentProcessId( );
		return true;
	}

	inline auto read_physical_memory( const std::uintptr_t address, void* buffer, const std::size_t size ) -> bool
	{
		read_request data{ 0 };

		data.pid = pid;
		data.address = address;
		data.buffer = buffer;
		data.size = size;

		return send_cmd( &data, request_read );
	}

	template <typename t>
	inline auto read_physical_memory( const std::uintptr_t address ) -> t
	{
		t response{ };
		read_physical_memory( address, &response, sizeof( t ) );
		return response;
	}

	inline auto write_physical_memory( const std::uintptr_t address, void* buffer, const std::size_t size ) -> bool
	{
		write_request data{ 0 };

		data.pid = pid;
		data.address = address;
		data.buffer = buffer;
		data.size = size;

		return send_cmd( &data, request_write );
	}

	template <typename t>
	inline auto write_physical_memory( const std::uintptr_t address, t value ) -> bool
	{
		return write_physical_memory( address, &value, sizeof( t ) );
	}
};

rcdrv* communication = new rcdrv( );