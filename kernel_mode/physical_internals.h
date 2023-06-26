#include <cstdint>


//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180
namespace internals
{
    DWORD directory( )
    {
        RTL_OSVERSIONINFOW ver = { 0 };
        RtlGetVersion( &ver );

        switch (ver.dwBuildNumber) {
        case WINDOWS_1803:
            return 0x0278;
            break;
        case WINDOWS_1809:
            return 0x0278;
            break;
        case WINDOWS_1903:
            return 0x0280;
            break;
        case WINDOWS_1909:
            return 0x0280;
            break;
        case WINDOWS_2004:
            return 0x0388;
            break;
        case WINDOWS_20H2:
            return 0x0388;
            break;
        case WINDOWS_21H1:
            return 0x0388;
            break;
        default:
            return 0x0388;
        }
    }

    ULONG_PTR process_cr3( PEPROCESS pProcess )
    {
        PUCHAR process = (PUCHAR)pProcess;
        ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
        if (process_dirbase == 0)
        {
            DWORD UserDirOffset = directory( );
            ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
            return process_userdirbase;
        }
        return process_dirbase;
    }

    NTSTATUS write_physical_address( uintptr_t TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten )
    {
        if (!TargetAddress)
            return STATUS_UNSUCCESSFUL;

        PHYSICAL_ADDRESS AddrToWrite = { 0 };
        AddrToWrite.QuadPart = (LONGLONG)TargetAddress;

        PVOID pmapped_mem = MmMapIoSpaceEx( AddrToWrite, Size, PAGE_READWRITE );

        if (!pmapped_mem)
            return STATUS_UNSUCCESSFUL;

        memcpy( pmapped_mem, lpBuffer, Size );

        *BytesWritten = Size;
        MmUnmapIoSpace( pmapped_mem, Size );
        return STATUS_SUCCESS;
    }

#define PAGE_OFFSET_SIZE 12
    static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

    NTSTATUS read_physical_memory(uint64_t target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read)
    {
        PHYSICAL_ADDRESS phys_addr = { 0 };
        phys_addr.QuadPart = target_address;
        PVOID mapped_addr = MmMapIoSpace(phys_addr, size, MmNonCached);

        if (!mapped_addr)
        {
            return STATUS_UNSUCCESSFUL;
        }

        RtlCopyMemory(buffer, mapped_addr, size);
        *bytes_read = size;

        MmUnmapIoSpace(mapped_addr, size);
        return STATUS_SUCCESS;
    }


    uint64_t translate_linear_address( uint64_t directoryTableBase, uint64_t virtualAddress ) {
        directoryTableBase &= ~0xf;

        uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
        uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
        uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
        uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
        uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

        SIZE_T readsize = 0;
        uint64_t pdpe = 0;
        read_physical_memory( directoryTableBase + 8 * pdp, &pdpe, sizeof( pdpe ), &readsize );
        if (~pdpe & 1)
            return 0;

        uint64_t pde = 0;
        read_physical_memory( (pdpe & PMASK) + 8 * pd, &pde, sizeof( pde ), &readsize );
        if (~pde & 1)
            return 0;

        /* 1GB large page, use pde's 12-34 bits */
        if (pde & 0x80)
            return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

        uint64_t pteAddr = 0;
        read_physical_memory( (pde & PMASK) + 8 * pt, &pteAddr, sizeof( pteAddr ), &readsize );
        if (~pteAddr & 1)
            return 0;

        /* 2MB large page */
        if (pteAddr & 0x80)
            return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

        virtualAddress = 0;
        read_physical_memory( (pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof( virtualAddress ), &readsize );
        virtualAddress &= PMASK;

        if (!virtualAddress)
            return 0;

        return virtualAddress + pageOffset;
    }
}