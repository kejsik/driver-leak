#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include "ia32.h"
#include "definitions.h"
#include "encrypt.h"
#include "crt.h"
#include "utils.h"
#include "interface.h"
#include "cache.h"
#include "cleaning.h"
#include "physical_internals.h"
ULONG_PTR FnCR3;


__int64 __fastcall cache::f_hook( void *a1 )
{
	PKTHREAD_META thread = ((PKTHREAD_META)((uintptr_t)KeGetCurrentThread( )));

	//if (thread->ApcQueueable == 1 )
	//	thread->ApcQueueable = 0;

	if ( !a1 || ExGetPreviousMode( ) != UserMode || reinterpret_cast< request_data * >( a1 )->unique != request_unique )
	{
		return cache::o_hook( a1 );
	}

	const auto request = reinterpret_cast< request_data * >( a1 );

	switch ( request->code )
	{
	case request_base:
	{
		base_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( base_request ) ) )
		{
			return 0;
		}

		if ( !data.pid )
		{
			return 0;
		}

		const auto base = utils::get_module_handle( data.pid, data.name );

		if ( !base )
		{
			return 0;
		}

		reinterpret_cast< base_request * > ( request->data )->handle = base;

		break;
	}
	case request_guardreg:
	{	
		guardreg_request data{ 0 };

		const auto allocation = utils::find_guarded_region();

		reinterpret_cast<guardreg_request*> (request->data)->allocation = allocation;

		break;
	}
	case request_cr3:
	{
		cr3_request data{ 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(cr3_request)))
		{
			return 0;
		}

		if (!data.pid)
		{
			return 0;
		}

		PEPROCESS process = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data.pid, &process)))
			return 0;


		KeAttachProcess(process);
		FnCR3 = __readcr3();
		KeDetachProcess();
		break;
	}
	case request_write:
	{
		write_request data = { 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(write_request)))
		{
			return 0;
		}

		if (!data.address || !data.pid || !data.buffer || !data.size)
		{
			return 0;
		}

		PEPROCESS process = nullptr;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data.pid, &process)))
		{
			return 0;
		}

		const ULONG_PTR process_dirbase = internals::process_cr3(process);
		ObDereferenceObject(process);

		if (!process_dirbase)
		{
			return 0;
		}

		SIZE_T total_size = data.size;
		SIZE_T cur_offset = 0;

		while (total_size)
		{
			const uint64_t cur_phys_addr = internals::translate_linear_address(process_dirbase, (ULONG64)data.address + cur_offset);
			if (!cur_phys_addr)
			{
				return STATUS_UNSUCCESSFUL;
			}

			const ULONG64 write_size = min(PAGE_SIZE - (cur_phys_addr & 0xFFF), total_size);
			SIZE_T bytes_written = 0;
			const NTSTATUS out = internals::write_physical_address(cur_phys_addr, (PVOID)((ULONG64)data.buffer + cur_offset), write_size, &bytes_written);

			if (out != STATUS_SUCCESS || bytes_written == 0)
			{
				break;
			}

			total_size -= bytes_written;
			cur_offset += bytes_written;
		}

		break;
	}


	case request_process_base:
	{
		process_base_request data{ 0 };

		if (!utils::safe_copy( &data, request->data, sizeof( process_base_request ) ))
		{
			return 0;
		}

		if (!data.pid)
		{
			return 0;
		}

		PEPROCESS target_proc;
		if (!NT_SUCCESS( PsLookupProcessByProcessId( (HANDLE)data.pid, &target_proc ) ))
			return 0;

		uintptr_t base = (uintptr_t)PsGetProcessSectionBaseAddress( target_proc );
		if (!base)
			return 0;

		reinterpret_cast<process_base_request*> (request->data)->handle = base;

		ObDereferenceObject( target_proc );
		break;
	}

	case request_read:
	{
		read_request data = { 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(read_request)))
		{
			return 0;
		}

		if (!data.address || !data.pid || !data.buffer || !data.size)
		{
			return 0;
		}

		PEPROCESS process = nullptr;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data.pid, &process)))
		{
			return 0;
		}

		const ULONG_PTR process_dirbase = FnCR3;
		ObDereferenceObject(process);

		if (!process_dirbase)
		{
			return 0;
		}

		SIZE_T total_size = data.size;
		SIZE_T cur_offset = 0;

		while (total_size)
		{
			const uint64_t cur_phys_addr = internals::translate_linear_address(process_dirbase, (ULONG64)data.address + cur_offset);
			if (!cur_phys_addr)
			{
				return STATUS_UNSUCCESSFUL;
			}

			const ULONG64 read_size = min(PAGE_SIZE - (cur_phys_addr & 0xFFF), total_size);
			SIZE_T bytes_read = 0;
			const NTSTATUS out = internals::read_physical_memory(cur_phys_addr, (PVOID)((ULONG64)data.buffer + cur_offset), read_size, &bytes_read);

			if (out != STATUS_SUCCESS || bytes_read == 0)
			{
				break;
			}

			total_size -= bytes_read;
			cur_offset += bytes_read;
		}

		break;
	}
	}


	return 0;
}


LPCSTR pattern = "";
LPCSTR mask = "";

NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
{
	const auto win32k = utils::get_kernel_module(e("win32k.sys"));
	if (!win32k)
		return STATUS_ABANDONED;

	void* win32kpvoid = (void*)win32k;
	cache::qword_address = utils::find_pattern(win32kpvoid, e("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x08\xFF\x15\x00\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x08\xFF\x15\x00\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x08\xFF\x15\x00\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x08\xFF\x15\x00\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x08\xFF\x15\x00\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x08\xFF\x15\x00\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x12\x4C\x8B\x54\x24\x00\x4C\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x08\xFF\x15\x00\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38"), e("xxx????xxxxxxx????xxx????xxxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxx????xxxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxx????xxxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxx????xxxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxx????xxxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxx????xxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxx?xxxx?xx????xxx????xxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxx????xxxxxxxxxxxxxxxxxxx"));
	if (!cache::qword_address)
		return STATUS_ABANDONED;


	*(void**)&cache::o_hook = InterlockedExchangePointer((void**)dereference(cache::qword_address), (void*)cache::f_hook);

	return STATUS_SUCCESS;
}