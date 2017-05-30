#include "linedrv.h"

#define FILTERNAME L"\\Driver\\FileFilter"
#define MEM_TAG 'mtag'

PDRIVER_OBJECT fltDriver = NULL;
PDEVICE_OBJECT fltDevice = NULL;
USBD_PIPE_HANDLE pipeHandle;

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
	pDevExt->filterDevice = NULL;

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

	ULONG ret_len = 0;

	//fltDevice = fltDevice->NextDevice;
	if (pDevExt->filterDevice)
	{
		PIRP newIrp = IoAllocateIrp(pDevExt->filterDevice->StackSize, FALSE);
		IO_STATUS_BLOCK io_block;
		PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(newIrp);
		LIST_NODE *list_node = (LIST_NODE *)ExAllocatePoolWithTag(NonPagedPool, sizeof(LIST_NODE), MEM_TAG);

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
		status = IoCallDriver(pDevExt->filterDevice, newIrp);

		if (NT_SUCCESS(status))
		{
			ret_len = newIrp->IoStatus.Information;
			RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, list_node, sizeof(LIST_NODE));

			IoCompleteRequest(newIrp, IO_NO_INCREMENT);
		}
		//free
		ExFreePoolWithTag(list_node, MEM_TAG);
		//IoFreeIrp(newIrp);

		//fltDevice = fltDevice->NextDevice;
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
	//IoFreeIrp(Irp);
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
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(pIrp);
	//CHAR *pBuffer = NULL;
	WCHAR strBuf[152] = { 0 };
	CHAR *pBuffer;
	ULONG inlen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outlen = sizeof(PDEVICE_OBJECT);
	ULONG ret_len = 0;

	IO_STATUS_BLOCK io_block;
	PIRP newIrp;
	PIO_STACK_LOCATION stack;
	PURB urb;

	//new
	/*PIRP newIrp = IoAllocateIrp(fltDevice->StackSize + 1, FALSE);
	IO_STATUS_BLOCK io_block;
	PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(newIrp);

	newIrp->UserIosb = &io_block;
	newIrp->Tail.Overlay.Thread = PsGetCurrentThread();

	stack->MajorFunction = IRP_MJ_DEVICE_CONTROL;
	stack->MinorFunction = 0;
	stack->Parameters.DeviceIoControl.OutputBufferLength = 0;*/

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_SET_FLAG:
		newIrp = MyCreateIrp(pdx->filterDevice, &io_block);
		stack = IoGetNextIrpStackLocation(newIrp);
		stack->Parameters.DeviceIoControl.IoControlCode = IOCTL_SET_FLAG;

		IoSetCompletionRoutine(newIrp,
			IoCtlCompletion,
			NULL,
			TRUE,
			TRUE,
			TRUE);
		status = IoCallDriver(pdx->filterDevice, newIrp);
		KdPrint(("call status: %x\n", status));

		IoCompleteRequest(newIrp, IO_NO_INCREMENT);
		break;
	case IOCTL_CLEAR_FLAG:
		newIrp = MyCreateIrp(pdx->filterDevice, &io_block);
		stack = IoGetNextIrpStackLocation(newIrp);
		stack->Parameters.DeviceIoControl.IoControlCode = IOCTL_CLEAR_FLAG;

		IoSetCompletionRoutine(newIrp,
			IoCtlCompletion,
			NULL,
			TRUE,
			TRUE,
			TRUE);
		status = IoCallDriver(pdx->filterDevice, newIrp);
		KdPrint(("call status: %x\n", status));

		IoCompleteRequest(newIrp, IO_NO_INCREMENT);
		break;
	case IOCTL_FINDFLT_FLAG:
		RtlCopyMemory(strBuf, pIrp->AssociatedIrp.SystemBuffer, inlen);
		UNICODE_STRING str = { 0 };
		UNICODE_STRING temp = RTL_CONSTANT_STRING(L"\\Device\\USBPDO-2");
		str.Buffer = strBuf;
		str.Length = str.MaximumLength = (USHORT)inlen-2;
		//KdPrint(("real len:%d\n", temp.Length));
		//RtlInitUnicodeString(&str, pBuffer);
		//KdPrint(("len:%d, buf:%wZ\n", inlen, &str));
		status = IoGetDeviceObjectPointer(
			&temp,
			FILE_ALL_ACCESS,
			&objectiveFile,
			&objectiveDev);
		if(STATUS_SUCCESS != status)
			KdPrint(("select result:%x\n", status));
		else
		{
			//newIrp = MyCreateIrp(objectiveDev, &io_block);
			//stack = IoGetNextIrpStackLocation(newIrp);
			//stack->Parameters.DeviceIoControl.InputBufferLength = inlen - 2;
			//stack->Parameters.DeviceIoControl.OutputBufferLength = outlen;
			//pBuffer = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, outlen, MEM_TAG);

			//newIrp->AssociatedIrp.SystemBuffer = pBuffer;
			//stack->Parameters.DeviceIoControl.IoControlCode = IOCTL_FINDFLT_FLAG;
			//IoSetCompletionRoutine(newIrp,
			//	IoCtlCompletion,
			//	NULL,
			//	TRUE,
			//	TRUE,
			//	TRUE);
			//status = IoCallDriver(objectiveDev, newIrp);
			////KdPrint(("Call PDO status: %x\n", status));
			//KdPrint(("Ret len: %d %d %d\n", newIrp->IoStatus.Information, sizeof(PDEVICE_OBJECT), sizeof(PCHAR)));

			//if (newIrp->IoStatus.Information == sizeof(PDEVICE_OBJECT) &&
			//	irpSp->Parameters.DeviceIoControl.OutputBufferLength == sizeof(int))
			//{
			//	int temp = 1;

			//	RtlCopyMemory(&pdx->filterDevice, newIrp->AssociatedIrp.SystemBuffer, 4);
			//	RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer, &temp, sizeof(int));
			//	ret_len = sizeof(int);
			//}

			//KdPrint(("Line: %x %x\n", pdx->filterDevice, fltDevice));

			//IoCompleteRequest(newIrp, IO_NO_INCREMENT);

			GetConfiguration(objectiveDev);

			pBuffer = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, 8, MEM_TAG);
			RtlZeroMemory(pBuffer, 8);
			//RtlCopyMemory(Buffer, pBuf, inlen);

			urb = (PURB)ExAllocatePool(NonPagedPool,
				sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER));

			if (urb) {
				UsbBuildInterruptOrBulkTransferRequest(
					urb,
					sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER),
					pipeHandle,
					pBuffer,
					NULL,
					8,
					USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK,
					NULL);

				status = CallUSBD(objectiveDev, urb);

				if (!NT_SUCCESS(status))
				{
					KdPrint((DRIVERNAME " - send call fail %x.\n", status));
				}
			}
			else
				KdPrint(("urb fail.\n"));

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

	pIrp->IoStatus.Information = ret_len;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

PIRP MyCreateIrp(PDEVICE_OBJECT lowerDev, PIO_STATUS_BLOCK pio_block)
{
	//new
	PIRP newIrp = IoAllocateIrp(lowerDev->StackSize, FALSE);
	PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(newIrp);

	newIrp->UserIosb = pio_block;
	newIrp->Tail.Overlay.Thread = PsGetCurrentThread();

	stack->MajorFunction = IRP_MJ_DEVICE_CONTROL;
	stack->MinorFunction = 0;
	stack->Parameters.DeviceIoControl.OutputBufferLength = 0;

	return newIrp;
}


NTSTATUS
CallUSBD(
	IN PDEVICE_OBJECT DeviceObject,
	IN PURB           Urb
)
{
	PIRP               irp;
	KEVENT             event;
	NTSTATUS           ntStatus;
	IO_STATUS_BLOCK    ioStatus;
	PIO_STACK_LOCATION nextStack;
	PDEVICE_EXTENSION  deviceExtension;

	//
	// initialize the variables
	//

	irp = NULL;
	//deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest(IOCTL_INTERNAL_USB_SUBMIT_URB,
		DeviceObject,
		NULL,
		0,
		NULL,
		0,
		TRUE,
		&event,
		&ioStatus);

	if (!irp) {

		KdPrint(("IoBuildDeviceIoControlRequest failed\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	nextStack = IoGetNextIrpStackLocation(irp);
	nextStack->Parameters.Others.Argument1 = Urb;

	ntStatus = IoCallDriver(DeviceObject, irp);

	if (ntStatus == STATUS_PENDING) {

		KeWaitForSingleObject(&event,
			Executive,
			KernelMode,
			FALSE,
			NULL);

		ntStatus = ioStatus.Status;
	}

	return ntStatus;
}


NTSTATUS
GetConfiguration(
	IN PDEVICE_OBJECT                DeviceObject
)
{
	PDEVICE_EXTENSION				pdx = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	NTSTATUS						status;
	PURB							pUrb;
	USB_CONFIGURATION_DESCRIPTOR	ConfigDescriptor;
	PUSB_CONFIGURATION_DESCRIPTOR	fullConfigDescriptor = NULL;

	pUrb = (PURB)ExAllocatePool(NonPagedPool,
		sizeof(struct _URB_CONTROL_DESCRIPTOR_REQUEST));
	//deviceDescriptor = (PUSB_DEVICE_DESCRIPTOR)ExAllocatePool(NonPagedPool, sizeof(USB_DEVICE_DESCRIPTOR));
	//ConfigDescriptor = (PUSB_CONFIGURATION_DESCRIPTOR)ExAllocatePool(NonPagedPool, sizeof(USB_CONFIGURATION_DESCRIPTOR));

	UsbBuildGetDescriptorRequest(
		pUrb,
		(USHORT) sizeof(struct _URB_CONTROL_DESCRIPTOR_REQUEST),
		USB_CONFIGURATION_DESCRIPTOR_TYPE,
		0,
		0,
		&ConfigDescriptor,
		NULL,
		sizeof(USB_CONFIGURATION_DESCRIPTOR),
		NULL);

	/*IoSetCompletionRoutine(Irp,
	IoCtlCompletion,
	NULL,
	TRUE,
	TRUE,
	TRUE);*/

	status = CallUSBD(DeviceObject, pUrb);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVERNAME " - call to get dscr fail.\n"));
	}
	else
	{
		KdPrint((DRIVERNAME " - total len:%d\n", ConfigDescriptor.wTotalLength));
	}
	if (ConfigDescriptor.wTotalLength == 0)
	{
		KdPrint((DRIVERNAME " - could not retrieve the configuration descriptor size"));
		status = USBD_STATUS_INAVLID_CONFIGURATION_DESCRIPTOR;
		//ExFreePool(deviceDescriptor);
		goto Exit;
	}

	fullConfigDescriptor = (PUSB_CONFIGURATION_DESCRIPTOR)ExAllocatePoolWithTag(
		NonPagedPool,
		ConfigDescriptor.wTotalLength,
		MEM_TAG);
	RtlZeroMemory(fullConfigDescriptor, ConfigDescriptor.wTotalLength);

	if (!fullConfigDescriptor)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	UsbBuildGetDescriptorRequest(
		pUrb,
		(USHORT) sizeof(struct _URB_CONTROL_DESCRIPTOR_REQUEST),
		USB_CONFIGURATION_DESCRIPTOR_TYPE,
		0,
		0,
		fullConfigDescriptor,
		NULL,
		ConfigDescriptor.wTotalLength,
		NULL);

	status = CallUSBD(DeviceObject, pUrb);

	if (fullConfigDescriptor->wTotalLength == 0 || !NT_SUCCESS(status))
	{
		KdPrint((DRIVERNAME " - status:%x len:%d.\n", status, fullConfigDescriptor->bNumInterfaces));
		status = USBD_STATUS_INAVLID_CONFIGURATION_DESCRIPTOR;
		goto Exit;
	}
	else
	{
		KdPrint((DRIVERNAME " - intfc num:%d\n", fullConfigDescriptor->bNumInterfaces));
	}

	SelectInterfaces(DeviceObject, fullConfigDescriptor);

	//IoCompleteRequest(newIrp, IO_NO_INCREMENT);
	//ExFreePool(deviceDescriptor);

Exit:
	if (fullConfigDescriptor)
		ExFreePool(fullConfigDescriptor);
	if (pUrb)
		ExFreePool(pUrb);

	return status;
}



NTSTATUS
SelectInterfaces(
	IN PDEVICE_OBJECT                DeviceObject,
	IN PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor
)
{
	LONG                        numberOfInterfaces,
		interfaceNumber,
		interfaceIndex;
	ULONG                       i;
	PURB                        urb;
	PUCHAR                      pInf;
	NTSTATUS                    ntStatus;
	PDEVICE_EXTENSION           deviceExtension;
	PUSB_INTERFACE_DESCRIPTOR   interfaceDescriptor;
	PUSBD_INTERFACE_LIST_ENTRY  interfaceList,
		tmp;
	PUSBD_INTERFACE_INFORMATION Interface;
	PUCHAR						StartPosition;
	//USBD_PIPE_HANDLE			pipeHandle;

	//
	// initialize the variables
	//

	urb = NULL;
	Interface = NULL;
	interfaceDescriptor = NULL;
	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	numberOfInterfaces = ConfigurationDescriptor->bNumInterfaces;
	interfaceIndex = interfaceNumber = 0;
	StartPosition = (PUCHAR)ConfigurationDescriptor;

	//
	// Parse the configuration descriptor for the interface;
	//

	tmp = interfaceList = (PUSBD_INTERFACE_LIST_ENTRY)ExAllocatePool(
		NonPagedPool,
		sizeof(USBD_INTERFACE_LIST_ENTRY) * (numberOfInterfaces + 1));

	if (!tmp) {

		KdPrint((DRIVERNAME " - Failed to allocate mem for interfaceList\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(tmp, sizeof(
		USBD_INTERFACE_LIST_ENTRY) *
		(numberOfInterfaces + 1));

	for (interfaceIndex = 0;
		interfaceIndex < numberOfInterfaces;
		interfaceIndex++)
	{
		interfaceDescriptor = USBD_ParseConfigurationDescriptorEx(
			ConfigurationDescriptor,
			StartPosition, // StartPosition 
			-1,            // InterfaceNumber
			0,             // AlternateSetting
			-1,            // InterfaceClass
			-1,            // InterfaceSubClass
			-1);           // InterfaceProtocol

		if (!interfaceDescriptor)
		{
			KdPrint((DRIVERNAME " - parse fail.\n"));
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			goto Exit;
		}

		// Set the interface entry
		interfaceList[interfaceIndex].InterfaceDescriptor = interfaceDescriptor;
		interfaceList[interfaceIndex].Interface = NULL;

		// Move the position to the next interface descriptor
		StartPosition = (PUCHAR)interfaceDescriptor + interfaceDescriptor->bLength;

	}

	interfaceList[interfaceIndex].InterfaceDescriptor = NULL;
	interfaceList[interfaceIndex].Interface = NULL;

	urb = USBD_CreateConfigurationRequestEx(ConfigurationDescriptor, tmp);

	if (!urb)
	{
		KdPrint((DRIVERNAME " - build urb fail.\n"));
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	ntStatus = CallUSBD(DeviceObject, urb);

	if (!NT_SUCCESS(ntStatus))
	{
		KdPrint((DRIVERNAME " - call fail.\n"));
		goto Exit;
	}

	for (interfaceIndex = 0;
		interfaceIndex < numberOfInterfaces;
		interfaceIndex++)
	{

		Interface = interfaceList[interfaceIndex].Interface;
		//Interface = &urb->UrbSelectConfiguration.Interface;
		/*deviceExtension->Interface = (PUSBD_INTERFACE_INFORMATION)ExAllocatePool(NonPagedPool,
			Interface->Length);

		if (deviceExtension->Interface)
		{
			RtlCopyMemory(deviceExtension->Interface,
				Interface,
				Interface->Length);
		}
		else
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			goto Exit;
		}*/

		KdPrint(("---------\n"));
		KdPrint(("NumberOfPipes 0x%x\n",
			Interface->NumberOfPipes));
		KdPrint(("Length 0x%x\n",
			Interface->Length));
		KdPrint(("Alt Setting 0x%x\n",
			Interface->AlternateSetting));
		KdPrint(("Interface Number 0x%x\n",
			Interface->InterfaceNumber));
		KdPrint(("Class, subclass, protocol 0x%x 0x%x 0x%x\n",
			Interface->Class,
			Interface->SubClass,
			Interface->Protocol));

		for (i = 0; i<Interface->NumberOfPipes; i++) {

			KdPrint(("---------\n"));
			KdPrint(("PipeType 0x%x\n",
				Interface->Pipes[i].PipeType));
			KdPrint(("EndpointAddress 0x%x\n",
				Interface->Pipes[i].EndpointAddress));
			KdPrint(("MaxPacketSize 0x%x\n",
				Interface->Pipes[i].MaximumPacketSize));
			KdPrint(("Interval 0x%x\n",
				Interface->Pipes[i].Interval));
			KdPrint(("Handle 0x%x\n",
				Interface->Pipes[i].PipeHandle));
			KdPrint(("MaximumTransferSize 0x%x\n",
				Interface->Pipes[i].MaximumTransferSize));

			pipeHandle = Interface->Pipes[i].PipeHandle;
			/*
			if (Interface->Pipes[i].PipeType == UsbdPipeTypeInterrupt)
			{
				deviceExtension->pipeContext.InterruptPipe = pipeHandle;
			}
			if (Interface->Pipes[i].PipeType == UsbdPipeTypeBulk && USB_ENDPOINT_DIRECTION_IN(Interface->Pipes[i].EndpointAddress))
			{
				deviceExtension->pipeContext.BulkInPipe = pipeHandle;
			}
			if (Interface->Pipes[i].PipeType == UsbdPipeTypeBulk && USB_ENDPOINT_DIRECTION_OUT(Interface->Pipes[i].EndpointAddress))
			{
				deviceExtension->pipeContext.BulkOutPipe = pipeHandle;
			}*/
		}
		break;
	}


Exit:
	if (interfaceList)
	{
		ExFreePool(interfaceList);
		interfaceList = NULL;
	}

	if (urb)
	{
		ExFreePool(urb);
	}

	return ntStatus;
}