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
}request_codes, *prequest_codes;

typedef struct _read_request {
	uint32_t pid;
	uintptr_t address;
	void *buffer;
	size_t size;
} read_request, *pread_request;

typedef struct _write_request {
	uint32_t pid;
	uintptr_t address;
	void *buffer;
	size_t size;
} write_request, *pwrite_request;

typedef struct _base_request {
	uint32_t pid;
	uintptr_t handle;
	WCHAR name[260];
} base_request, *pbase_request;

typedef struct _guardreg_request {
	uintptr_t allocation;
} guardreg_request, * pguardreg_request;


typedef struct _process_base_request {
	uint32_t pid;
	uintptr_t handle;
} process_base_request, * p_process_base_request;


typedef struct _request_data
{
	uint32_t unique;
	request_codes code;
	void *data;
}request_data, *prequest_data;


typedef struct _cr3_request {
	uint32_t pid;
} cr3_request, * pcr3_request;