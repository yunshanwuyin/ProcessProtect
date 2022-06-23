/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_ProcessProtect,
    0xe7d9ad78,0xe456,0x4df8,0xa7,0x99,0x21,0x8c,0x65,0x7f,0x32,0x12);
// {e7d9ad78-e456-4df8-a799-218c657f3212}

typedef struct _LDR_DATA                         			
{
	struct _LIST_ENTRY InLoadOrderLinks;                     
	struct _LIST_ENTRY InMemoryOrderLinks;                 
	struct _LIST_ENTRY InInitializationOrderLinks;      
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG32      SizeOfImage;
	UINT8        _PADDING0_[0x4];
	struct _UNICODE_STRING FullDllName;                 
	struct _UNICODE_STRING BaseDllName;                      
	ULONG32      Flags;
}LDR_DATA, * PLDR_DATA;

#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)

NTSTATUS InitObRegistration();
VOID UnInitObRegistration();
VOID DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject);