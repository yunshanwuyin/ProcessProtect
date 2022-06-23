#include "ntifs.h"
#include <wdm.h>
#include "Public.h"

OB_PREOP_CALLBACK_STATUS
PreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo);

NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
);

OB_OPERATION_REGISTRATION obOperationRegistrations[2] = {{0}, {0}};
OB_CALLBACK_REGISTRATION obCallbackRegistration = {0};
UNICODE_STRING altitude = {0};
PVOID RegistrationHandle = NULL;


NTSTATUS
InitObRegistration()
{
	//进程类型
	obOperationRegistrations[0].ObjectType = PsProcessType;
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[0].PreOperation = PreOperationCallback;

	//线程类型
	obOperationRegistrations[1].ObjectType = PsThreadType;
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[1].PreOperation = PreOperationCallback;


	RtlInitUnicodeString(&altitude, L"1000");

	obCallbackRegistration.Version = ObGetFilterVersion();
	obCallbackRegistration.OperationRegistrationCount = 2;
	obCallbackRegistration.RegistrationContext = NULL;
	obCallbackRegistration.Altitude = altitude;
	obCallbackRegistration.OperationRegistration = obOperationRegistrations;

	return ObRegisterCallbacks(&obCallbackRegistration, &RegistrationHandle);
}


OB_PREOP_CALLBACK_STATUS
PreOperationCallback(_In_ PVOID RegistrationContext,
                     _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	//这里我们演示取消PROCESS_TERMINATE 权限
	ACCESS_MASK AccessBitsToClear = PROCESS_TERMINATE;

	//获取进程
	PEPROCESS process = (PEPROCESS)PreInfo->Object;

	if (PreInfo->ObjectType == *PsThreadType)
	{
		process = IoThreadToProcess((PETHREAD)PreInfo->Object);
	}
	else if (PreInfo->ObjectType == *PsProcessType)
	{
		process = (PEPROCESS)PreInfo->Object;
	}
	else
	{
		//都不是我们需要的类型，直接return
		return OB_PREOP_SUCCESS;
	}

	//获取进程名
	PUCHAR processName = PsGetProcessImageFileName(process);

	if (_stricmp((char*)processName, "Notepad.exe") != 0)
	{
		//不是我们关心的进程，直接return
		return OB_PREOP_SUCCESS;
	}

	if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~AccessBitsToClear;
	}

	if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
	{
		PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~AccessBitsToClear;
	}

	return OB_PREOP_SUCCESS;
}

VOID
UnInitObRegistration()
{
	if (RegistrationHandle)
	{
		ObUnRegisterCallbacks(RegistrationHandle);
		RegistrationHandle = NULL;
	}
}
