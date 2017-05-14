#include "linedrv.h"

#define FILTERNAME L"\\Driver\\FileFilter"
#define MEM_TAG 'mtag'

PDRIVER_OBJECT fltDriver = NULL;
PDEVICE_OBJECT fltDevice = NULL;

#pragma INITCODE
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING fltName;
	RtlInitUnicodeString(&fltName, FILTERNAME);

	//注册其他驱动调用函数入口
	pDriverObject->DriverUnload = HelloDDKUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = HelloDDKCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = HelloDDKClose;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_READ] = HelloDDKRead;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HelloDDKIoCtl;

	//创建驱动设备对象
	status = CreateDevice(pDriverObject);

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
	KdPrint(("DriverA:Enter line DriverUnload\n"));
	pNextObj = pDriverObject->DeviceObject;
	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
		pNextObj->DeviceExtension;

	//删除符号链接
	UNICODE_STRING pLinkName;
	RtlInitUnicodeString(&pLinkName, L"\\??\\LineDevice");
	IoDeleteSymbolicLink(&pLinkName);
	IoDeleteDevice(pNextObj);
	KdPrint(("DriverA:Leave line DriverUnload\n"));
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
	NTSTATUS status;
	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
		pDevObj->DeviceExtension;

	ULONG ret_len;

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


NTSTATUS HelloDDKIoCtl(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp)
{
	KdPrint(("Line: enter ioctl.\n"));
	fltDevice = fltDriver->DeviceObject->NextDevice;

	NTSTATUS status;
	PDEVICE_OBJECT objectiveDev = NULL;
	PFILE_OBJECT objectiveFile = NULL;

	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(pIrp);
	//CHAR *pBuffer = NULL;
	WCHAR strBuf[152] = { 0 };
	ULONG inlen = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	//new
	PIRP newIrp = IoAllocateIrp(fltDevice->StackSize + 1, FALSE);
	IO_STATUS_BLOCK io_block;
	PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(newIrp);

	newIrp->UserIosb = &io_block;
	newIrp->Tail.Overlay.Thread = PsGetCurrentThread();

	stack->MajorFunction = IRP_MJ_DEVICE_CONTROL;
	stack->MinorFunction = 0;
	stack->Parameters.DeviceIoControl.OutputBufferLength = 0;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_SET_FLAG:
		stack->Parameters.DeviceIoControl.IoControlCode = IOCTL_SET_FLAG;

		IoSetCompletionRoutine(newIrp,
			IoCtlCompletion,
			NULL,
			TRUE,
			TRUE,
			TRUE);
		status = IoCallDriver(fltDevice, newIrp);
		KdPrint(("call status: %x\n", status));

		IoCompleteRequest(newIrp, IO_NO_INCREMENT);
		break;
	case IOCTL_CLEAR_FLAG:
		stack->Parameters.DeviceIoControl.IoControlCode = IOCTL_CLEAR_FLAG;

		IoSetCompletionRoutine(newIrp,
			IoCtlCompletion,
			NULL,
			TRUE,
			TRUE,
			TRUE);
		status = IoCallDriver(fltDevice, newIrp);
		KdPrint(("call status: %x\n", status));

		IoCompleteRequest(newIrp, IO_NO_INCREMENT);
		break;
	case IOCTL_FINDFLT_FLAG:
		RtlCopyMemory(strBuf, pIrp->AssociatedIrp.SystemBuffer, inlen);
		UNICODE_STRING str = { 0 };
		UNICODE_STRING temp = RTL_CONSTANT_STRING(L"\\Device\\USBPDO-2");
		str.Buffer = strBuf;
		str.Length = str.MaximumLength = (USHORT)inlen-2;
		KdPrint(("real len:%d\n", temp.Length));
		//RtlInitUnicodeString(&str, pBuffer);
		//KdPrint(("len:%d, buf:%wZ\n", inlen, &str));
		status = IoGetDeviceObjectPointer(
			&str,
			FILE_ALL_ACCESS,
			&objectiveFile,
			&objectiveDev);
		if(STATUS_SUCCESS != status)
			KdPrint(("select result:%x\n", status));
		else
		{
			stack->Parameters.DeviceIoControl.InputBufferLength = inlen - 2;
			stack->Parameters.DeviceIoControl.OutputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
			newIrp->AssociatedIrp.SystemBuffer = pIrp->AssociatedIrp.SystemBuffer;
			stack->Parameters.DeviceIoControl.IoControlCode = IOCTL_FINDFLT_FLAG;
			IoSetCompletionRoutine(newIrp,
				IoCtlCompletion,
				NULL,
				TRUE,
				TRUE,
				TRUE);
			status = IoCallDriver(objectiveDev, newIrp);
			KdPrint(("Call PDO status: %x\n", status));
			KdPrint(("Ret len: %d", newIrp->IoStatus.Information));

			IoCompleteRequest(newIrp, IO_NO_INCREMENT);
			ObDereferenceObject(objectiveFile);
		}

		//IoCompleteRequest(newIrp, IO_NO_INCREMENT);
		//IoFreeIrp(newIrp);
		//ExFreePool(pBuffer);
		break;
	default:
		break;
	}
	

	//free
	//IoFreeIrp(newIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}