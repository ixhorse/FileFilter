#include "linedrv.h"

#define FILTERNAME L"\\Driver\\FileFilter"
#define MEM_TAG 'mtag'

#pragma INITCODE
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;

	//注册其他驱动调用函数入口
	pDriverObject->DriverUnload = HelloDDKUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = HelloDDKCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = HelloDDKClose;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_READ] = HelloDDKRead;

	//创建驱动设备对象
	status = CreateDevice(pDriverObject);

	KdPrint(("DriverA:Leave A DriverEntry\n"));
	return status;
}


/************************************************************************
* 函数名称:CreateDevice
* 功能描述:初始化设备对象
* 参数列表:
pDriverObject:从I/O管理器中传进来的驱动对象
* 返回 值:返回初始化状态
*************************************************************************/
#pragma INITCODE
NTSTATUS CreateDevice(
	IN PDRIVER_OBJECT	pDriverObject)
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	//创建设备名称
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\LineDevice");

	//创建设备
	status = IoCreateDevice(pDriverObject,
		sizeof(DEVICE_EXTENSION),
		&devName,
		FILE_DEVICE_UNKNOWN,
		0, TRUE,
		&pDevObj);
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pDevExt->pDevice = pDevObj;
	pDevExt->ustrDeviceName = devName;

	//创建符号链接
	UNICODE_STRING symLinkName;
	WCHAR dest_buf[256];
	RtlInitUnicodeString(&symLinkName, L"\\??\\LineDevice");
	RtlInitEmptyUnicodeString(&pDevExt->ustrSymLinkName, dest_buf, symLinkName.Length);
	RtlCopyUnicodeString(&pDevExt->ustrSymLinkName, &symLinkName);
	status = IoCreateSymbolicLink(&symLinkName, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}

	
	return STATUS_SUCCESS;
}

/************************************************************************
* 函数名称:HelloDDKUnload
* 功能描述:负责驱动程序的卸载操作
* 参数列表:
pDriverObject:驱动对象
* 返回 值:返回状态
*************************************************************************/
#pragma PAGEDCODE
VOID HelloDDKUnload(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT	pNextObj;
	KdPrint(("DriverA:Enter A DriverUnload\n"));
	pNextObj = pDriverObject->DeviceObject;
	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
		pNextObj->DeviceExtension;

	//删除符号链接
	UNICODE_STRING pLinkName;
	RtlInitUnicodeString(&pLinkName, L"\\??\\LineDevice");
	IoDeleteSymbolicLink(&pLinkName);
	IoDeleteDevice(pNextObj);
	KdPrint(("DriverA:Leave A DriverUnload\n"));
}


VOID PrintNode(
	IN LIST_NODE *list_node)
{
	UCHAR * pBuf;
	ULONG len;
	ULONG i;

	if (list_node != NULL)
	{
		KdPrint(("falgs: %#x\t%#x\n", list_node->Bulk_out.TranferFlags, list_node->Bulk_in.TranferFlags));
		KdPrint(("len: %d\t%d\n", list_node->Bulk_out.Len, list_node->Bulk_in.Len));
		KdPrint(("buf: "));
		pBuf = (UCHAR *)list_node->Bulk_out.Buf;
		for (i = 0; i < list_node->Bulk_in.Len; i++)
			KdPrint(("%02x ", pBuf[i]));
		KdPrint(("\t"));
		pBuf = (UCHAR *)list_node->Bulk_in.Buf;
		for (i = 0; i < list_node->Bulk_in.Len; i++)
			KdPrint(("%02x ", pBuf[i]));
		KdPrint(("\n"));
	}
	else
		KdPrint(("Node NULL.\n"));
}



/************************************************************************
* 函数名称:HelloDDK
* 功能描述:对读IRP进行处理
* 参数列表:
pDevObj:功能设备对象
pIrp:从IO请求包
* 返回 值:返回状态
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS HelloDDKRead(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp)
{
	KdPrint(("Line: enter ioctl.\n"));

	NTSTATUS status;
	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
		pDevObj->DeviceExtension;
	PDRIVER_OBJECT fltDriver = NULL;
	PDEVICE_OBJECT fltDevice = NULL;
	UNICODE_STRING fltName;
	RtlInitUnicodeString(&fltName, FILTERNAME);
	ULONG ret_len;

	status = ObReferenceObjectByName(
		&fltName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID)&fltDriver
	);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Couldn't get driver object.\n"));
	}
	//else
	//{
	//	//ObDereferenceObject(pDevObj->DriverObject);
	//	//ObDereferenceObject(fltDriver);
	//}

	if (fltDriver != NULL)
	{
		fltDevice = fltDriver->DeviceObject;
	}
	//if (fltDevice->NextDevice != NULL)
	//{
	//	fltDevice = fltDevice->NextDevice;
	//}
	fltDevice = fltDevice->NextDevice;
	while (fltDevice)
	{
		PIRP newIrp = IoAllocateIrp(fltDevice->StackSize+1, FALSE);
		IO_STATUS_BLOCK io_block;
		PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(newIrp);
		LIST_NODE *list_node = (LIST_NODE *)ExAllocatePoolWithTag(NonPagedPool, sizeof(LIST_NODE), MEM_TAG);
		
		ret_len = 0;

		newIrp->UserIosb = &io_block;
		newIrp->Tail.Overlay.Thread = PsGetCurrentThread();
		newIrp->AssociatedIrp.SystemBuffer = list_node;

		stack->MajorFunction = IRP_MJ_DEVICE_CONTROL;
		stack->MinorFunction = 0;
		stack->Parameters.DeviceIoControl.IoControlCode = IOCTL_READ_LIST;
		stack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(LIST_NODE);
		
		IoSetCompletionRoutine(newIrp,
			IoCtlCompletion,
			&ret_len,
			TRUE,
			TRUE,
			TRUE);
		status = IoCallDriver(fltDevice, newIrp);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("Call failed. %x\n", status));
			ExFreePoolWithTag(list_node, MEM_TAG);
			fltDevice = fltDevice->NextDevice;
			continue;
		}
		
		ret_len = newIrp->IoStatus.Information;
		RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, list_node, sizeof(LIST_NODE));
		//free
		ExFreePoolWithTag(list_node, MEM_TAG);
		//IoFreeIrp(newIrp);

		//fltDevice = fltDevice->NextDevice;
		break;
	}
	
	pIrp->IoStatus.Information = ret_len;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}




/************************************************************************
* 函数名称:HelloDDKDispatchRoutine
* 功能描述:对读IRP进行处理
* 参数列表:
pDevObj:功能设备对象
pIrp:从IO请求包
* 返回 值:返回状态
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	// 完成IRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

#pragma PAGEDCODE
NTSTATUS HelloDDKCreate(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	// 完成IRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

#pragma PAGEDCODE
NTSTATUS HelloDDKClose(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	// 完成IRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS IoCtlCompletion(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp, IN PVOID Context)
{

	return STATUS_MORE_PROCESSING_REQUIRED;
}