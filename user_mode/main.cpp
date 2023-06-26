#include <windows.h>
#include <stdint.h>
#include <string>

#include "communication.h"
#include <iostream>
#include <TlHelp32.h>
#include <thread>
#include "math.h"

uintptr_t test_ptr = 0x50;
uint64_t base_address;
DWORD_PTR Uworld;
DWORD_PTR Rootcomp;
DWORD_PTR Localplayer;
DWORD_PTR PlayerController;
DWORD_PTR LocalPawn;
DWORD_PTR PlayerState;
Vector3 localactorpos;

float FOV = 120.0f;

namespace APlayerCameraManager
{
	DWORD DefaultFOV = 0x29c;
};

#define M_PI 3.14159265358979323846264338327950288419716939937510
#define GWorld 0xEE5A148 // gworld is a pointer of uworld. 

DWORD GetProcessID(const std::wstring processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

int pid3;

namespace utils
{
	auto getuworld(uintptr_t pointer) -> uintptr_t
	{
		uintptr_t uworld_addr = communication->read_physical_memory< uintptr_t >(pointer + 0x60);

		unsigned long long uworld_offset;

		if (uworld_addr > 0x10000000000)
		{
			uworld_offset = uworld_addr - 0x10000000000;
		}
		else {
			uworld_offset = uworld_addr - 0x8000000000;
		}

		return pointer + uworld_offset;
	}


	inline static bool isguarded(uintptr_t pointer) noexcept
	{
		static constexpr uintptr_t filter = 0xFFFFFFF000000000;
		uintptr_t result = pointer & filter;
		return result == 0x8000000000 || result == 0x10000000000;
	}
}

Vector3 GetBoneWithRotation(DWORD_PTR mesh, int id)
{
	uintptr_t bone_array = communication->read_physical_memory<uintptr_t>(mesh + 0x5E8);
	int is_bone_array_cached = communication->read_physical_memory<int>(mesh + 0x5F8);
	if (is_bone_array_cached) bone_array = communication->read_physical_memory<uintptr_t>(mesh + 0x5F8);
	FTransform bone = communication->read_physical_memory<FTransform>(bone_array + (id * 0x60));
	FTransform component_to_world = communication->read_physical_memory<FTransform>(mesh + 0x240);
	D3DMATRIX matrix = MatrixMultiplication(bone.ToMatrixWithScale(), component_to_world.ToMatrixWithScale());
	return Vector3(matrix._41, matrix._42, matrix._43);
}


Camera GetCamera(__int64 a1)
{
	Camera LocalCamera;
	__int64 v1;
	v1 = communication->read_physical_memory<__int64>(Localplayer + 0xd0);
	__int64 v9 = communication->read_physical_memory<__int64>(v1 + 0x8); // 0x10
	LocalCamera.FieldOfView = 80.f / (communication->read_physical_memory<double>(v9 + 0x7F0) / 1.19f); // 0x600
	LocalCamera.Rotation.x = communication->read_physical_memory<double>(v9 + 0x9C0);
	LocalCamera.Rotation.y = communication->read_physical_memory<double>(a1 + 0x148);
	uint64_t FGC_Pointerloc = communication->read_physical_memory<uint64_t>(Uworld + 0x110);
	LocalCamera.Location = communication->read_physical_memory<Vector3>(FGC_Pointerloc);
	return LocalCamera;
}

Vector3 ProjectWorldToScreen(Vector3 WorldLocation)
{
	Camera vCamera = GetCamera(Rootcomp);
	vCamera.Rotation.x = (asin(vCamera.Rotation.x)) * (180.0 / M_PI);
	//Rotation.x: 0.870931
	//Rotation.y: -88.0719
	//std::cout << "Rotation.x: " << vCamera.Rotation.x << std::endl;
	//std::cout << "Rotation.y: " << vCamera.Rotation.y << std::endl;
	_MATRIX tempMatrix = Matrix(vCamera.Rotation, Vector3(0, 0, 0));
	Vector3 vAxisX = Vector3(tempMatrix.m[0][0], tempMatrix.m[0][1], tempMatrix.m[0][2]);
	Vector3 vAxisY = Vector3(tempMatrix.m[1][0], tempMatrix.m[1][1], tempMatrix.m[1][2]);
	Vector3 vAxisZ = Vector3(tempMatrix.m[2][0], tempMatrix.m[2][1], tempMatrix.m[2][2]);
	Vector3 vDelta = WorldLocation - vCamera.Location;
	Vector3 vTransformed = Vector3(vDelta.Dot(vAxisY), vDelta.Dot(vAxisZ), vDelta.Dot(vAxisX));
	if (vTransformed.z < 1.f) vTransformed.z = 1.f;
	return Vector3((1920 / 2.0f) + vTransformed.x * (((1920 / 2.0f) / tanf(vCamera.FieldOfView * (float)M_PI / 360.f))) / vTransformed.z, (1080 / 2.0f) - vTransformed.y * (((1920 / 2.0f) / tanf(vCamera.FieldOfView * (float)M_PI / 360.f))) / vTransformed.z, 0);
}


auto cachethread() -> void
{
	auto guardedregion = communication->guarded_region();
	printf("guardedregion: 0x%p\n", guardedregion);

	while (true)
	{
		auto uworld = utils::getuworld(guardedregion);
		printf("uworld: 0x%p\n", uworld);

		auto ulevel = communication->read_physical_memory< uintptr_t >(uworld + 0x38);
		printf("ulevel: 0x%p\n", ulevel);

		auto gamestate = communication->read_physical_memory< uintptr_t >(uworld + 0x140);
		printf("gamestate: 0x%p\n", gamestate);

		Sleep(2000);
	}
}

//void main(int argc, char* argv[])
void main()
{
	/*
	if (argc > 1)
	{
		if (!strcmp( argv[argc - 1], "--test" ))
		{
			if (!communication->initialize( ))
			{
				printf( "driver not loaded.\n" );
				Sleep( 3000 );
				return;
			}
			printf( "driver loaded.\n" );
			Sleep( 3000 );
			return;
		}

		printf( "Unknown arguments given:\n" );
		for (int i = 0; i < argc; i++)
		{
			printf( "arg[%i] = %s\n", i, argv[i] );
		}
		Sleep( 15000 );
		return;
	}
	*/
	if (!communication->initialize())
	{
		printf("failed to initialize the driver.\n");
		std::cin.get();
	}



	pid3 = GetProcessID(L"notepad.exe");

	if (!communication->attach(pid3))
	{
		printf("failed to attatch to the process\n");
		std::cin.get();
	}
	std::thread(cachethread).detach();


	printf("finished operation\n");
}