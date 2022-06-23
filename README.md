# 基于ObRegisterCallbacks实现的简单进程保护功能
本文将简单讲下如何使用ObRegisterCallbacks，实现进程保护功能。

前置条件：驱动开发相关环境已配置完成。

本文的开发环境：

- Visual Studio：2019
- Windows SDK：10.0.19041.685
- WDK：10.0.19041.685
##  认识ObRegisterCallbacks 函数
通过该函数设置的回调函数，会在我们对某个进程或线程Handle进行操作的前或后执行。具体是前还是后，可根据后面设置的是PreOperation还是PostOperation进行判断。

首先看[MSDN上的函数签名](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)，如下：

```c
NTSTATUS ObRegisterCallbacks(
  [in]  POB_CALLBACK_REGISTRATION CallbackRegistration,
  [out] PVOID                     *RegistrationHandle
);
```
参数CallbackRegistration：调用ObRegisterCallbacks时需传入`POB_CALLBACK_REGISTRATION`类型，该类型是一个`_OB_CALLBACK_REGISTRATION `的一个指针类型。

[该结构体的结构](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration)如下：

```c
typedef struct _OB_CALLBACK_REGISTRATION {
  USHORT                    Version;
  USHORT                    OperationRegistrationCount;
  UNICODE_STRING            Altitude;
  PVOID                     RegistrationContext;
  OB_OPERATION_REGISTRATION *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;

//Version: 使用ObGetFilterVersion()取得
//OperationRegistrationCount:OB_OPERATION_REGISTRATION 该结构体的数组的长度
//Altitude:可理解为驱动的加载顺序
//RegistrationContext:传递给回调的参数
//OperationRegistration:OB_OPERATION_REGISTRATION 该结构体的数组
```

在上述的结构体中，OperationRegistration这个参数是指向如下结构体的数组指针：

```c
typedef struct _OB_OPERATION_REGISTRATION {
  POBJECT_TYPE                *ObjectType;
  OB_OPERATION                Operations;
  POB_PRE_OPERATION_CALLBACK  PreOperation;
  POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;

//ObjectType: 触发回调对象的类型
//Operations: 触发回调的操作
//PreOperation: 操作执行前的回调函数
//PostOperation: 操作执行后的回调函数
```

参数RegistrationHandle：接受注册成功后的handle，在驱动卸载或反注册时需要调用ObUnRegisterCallbacks，并把该参数传入。

## 使用ObRegisterCallbacks函数实现进程保护
前面简单讲述了ObRegisterCallbacks函数及其相关参数，下面开始演示如何使用该函数实现简单的进程保护功能。
### 初始化ObRegisterCallbacks的参数
这里分别注册了两种回调触发类型PsProcessType、PsThreadType，并且我们需要在操作执行前，执行我们的回调，所以我们只设置了PreOperation。Operations：表示我们对某个句柄需要关系的操作，我们将句柄的创建和复制都注册进去，MSDN相关解释如下：
> ```
> Operations
> Specify one or more of the following flags:
> OB_OPERATION_HANDLE_CREATE
> A new process, thread, or desktop handle was or will be opened.
> OB_OPERATION_HANDLE_DUPLICATE
> ```
> PreOperationCallback：是我们的回调函数，当设置的操作触发时(Operations 参数)会调用该函数，也是我们逻辑的主要实现。
>
> 该部分具体实现代码如下：
```c
NTSTATUS InitObRegistration()
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

	obCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	obCallbackRegistration.OperationRegistrationCount = 2;
	obCallbackRegistration.RegistrationContext = NULL;
	obCallbackRegistration.Altitude = altitude;
	obCallbackRegistration.OperationRegistration = obOperationRegistrations;

	return ObRegisterCallbacks(&obCallbackRegistration, RegistrationHandle);
}
```
以上部分完成了ObRegisterCallbacks相关参数的初始化，包括指定我们的回调函数，我们只需要在驱动程序的入口调用InitObRegistration即可。
###  PreOperationCallback回调函数的实现
该回调函数，有两个参数：
- RegistrationContext：在前面的初始化中传入的参数，实际上就是想要传递给回调函数的内容，因为本文没有用到，所以传入的是NULL；
- PreInfo：为该`OB_PRE_OPERATION_INFORMATION`结构体，是当前操作的相关信息，我们通过修改这个参数，拒绝某些操作的权限，以达到保护进程的目的。
- [结构体`OB_PRE_OPERATION_INFORMATION`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_operation_information)
```c
typedef struct _OB_PRE_OPERATION_INFORMATION {
  OB_OPERATION                 Operation;
  union {
    ULONG Flags;
    struct {
      ULONG KernelHandle : 1;
      ULONG Reserved : 31;
    };
  };
  PVOID                        Object;
  POBJECT_TYPE                 ObjectType;
  PVOID                        CallContext;
  POB_PRE_OPERATION_PARAMETERS Parameters;
} OB_PRE_OPERATION_INFORMATION, *POB_PRE_OPERATION_INFORMATION;
```
通过该结构体，可以获取到当前操作的一些信息，我们主要关注Parameters参数，里面是我们需要的权限相关的内容。通过Object成员获取进程或线程的ID，然后通过`PsGetProcessImageFileName`获取到进程名，最后比较进程名是否是我们想要保护的进程。

此处需要注意的是`PsGetProcessImageFileName`，这个函数只在内核中导出，需要使用的话只需要申明一下该函数就行。

该函数申明如下：

```c
NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
);
```

当我们尝试去关闭一个我们保护的进程时，会在操作前触发我们的回调，在回调里我们通过对`POB_PRE_OPERATION_INFORMATION`中成员Parameters中的DesiredAccess来指定相关权限。

DesiredAccess是一个`ACCESS_MASK`，表明授予该操作的权限，该值默认情况下和OriginalDesiredAccess是一样的，即拥有全部权限。通过设置DesiredAccess，取消掉相应权限即可。

```c
PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~AccessBitsToClear;
```
具体逻辑实现如下：
```c
OB_PREOP_CALLBACK_STATUS PreOperationCallback(_In_ PVOID RegistrationContext,
                                              _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	//这里我们演示取消PROCESS_TERMINATE 权限
	ACCESS_MASK AccessBitsToClear = PROCESS_TERMINATE;

	//获取进程
	PEPROCESS process = (PEPROCESS)PreInfo->Object;

	if (PreInfo->ObjectType == *PsThreadType) {
		process = IoThreadToProcess((PETHREAD)PreInfo->Object);
	}
	if (PreInfo->ObjectType == *PsProcessType) {
		process = (PEPROCESS)PreInfo->Object;
	}
	//获取进程名
	PUCHAR processName = PsGetProcessImageFileName(process);

	if (_stricmp((char *)processName, "Notepad.exe") != 0) {
		//不是我们关心的进程，直接return
		return OB_PREOP_SUCCESS;
	}
	if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
		PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~AccessBitsToClear;
	}
	if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
		PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~AccessBitsToClear;
	}
	return OB_PREOP_SUCCESS;
}
```

## 测试驱动
 相关工具：
1. DriverMonitor 用于安装、停止、删除驱动；
2. DebugView 查看驱动程序输出的log信息。
### 安装启动
使用管理员权限打开DriverMonitor，选择驱动文件并安装，点击Go按钮，启动驱动程序；
![](DraggedImage.png)
点击go按钮后，发现启动驱动程序失败，提示拒绝访问。
![](DraggedImage-1.png)

### 解决`STATUS_ACCESS_DENIED`
搜索MSDN后发现啥上述问题是因为签名导致的；
![](DraggedImage-2.png)
正常情况下，由于我们的驱动是签名之后才能运行，所以没问题。

但是我们在开发调试时，一般是没有签名的，所以需要在debug模式下绕过检查：

```c
//定义如下结构体
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

//在调用ObRegisterCallbacks前到调用就可以了。
#ifdef DBG
    PLDR_DATA ldr;
    ldr = (PLDR_DATA)DriverObject->DriverSection;
    ldr->Flags |= 0x20;
#endif
```

### 最终效果
驱动打开后，记事本这个程序已经无法从任务管理器关闭了。

![](iShot_2022-06-20_15.44.25.gif)

## 扩展
通过任务管理器关闭进程，实际上有两种方式：
- 一种是直接杀掉进程，也就是调用系统API，TerminateProcess；
- 还有一种是结束任务，这种方式会发送一个`WM_CLOSE`的消息给程序，如果程序在一定时间内还没有退出的话，才会调用TerminateProcess。如果被保护的程序没有处理这个消息，或消息的处理方式是默认的话，就不会调用TerminateProcess，而是正常程序自身退出，所以如果你想保护自己的程序不被退出，你还需要在你的程序中处理`WM_CLOSE`这个消息。
	![](DraggedImage-3.png)

## References
> 1. [DebugView 介绍以及使用教程]([https://docs.microsoft.com/en-us/sysinternals/downloads/debugview])
> 2. [ObRegisterCallbacks MSDN ]([https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks])
> 3. [Windows Driver Simple](https://github.com/microsoft/Windows-driver-samples/tree/main/general/obcallback)

