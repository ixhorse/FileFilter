#include "stddcls.h"
#include "driver.h"

#include <srb.h>
#include <scsi.h>

#define MEM_TAG 'mtag'	//32bit

NTSTATUS AddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT pdo);
VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchAny(IN PDEVICE_OBJECT fido, IN PIRP Irp);
NTSTATUS DispatchPower(IN PDEVICE_OBJECT fido, IN PIRP Irp);
NTSTATUS DispatchPnp(IN PDEVICE_OBJECT fido, IN PIRP Irp);
NTSTATUS DispatchWmi(IN PDEVICE_OBJECT fido, IN PIRP Irp);
ULONG GetDeviceTypeToUse(PDEVICE_OBJECT pdo);
NTSTATUS StartDeviceCompletionRoutine(PDEVICE_OBJECT fido, PIRP Irp, PDEVICE_EXTENSION pdx);
NTSTATUS UsageNotificationCompletionRoutine(PDEVICE_OBJECT fido, PIRP Irp, PDEVICE_EXTENSION pdx);
NTSTATUS DispatchInternalDeviceControl(IN PDEVICE_OBJECT fido, IN PIRP Irp);
NTSTATUS InternalCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);
NTSTATUS DispatchIoDeviceControl(IN PDEVICE_OBJECT fido, IN PIRP Irp);
ULONG GetDevSeq(IN PDEVICE_OBJECT pdo);
VOID GetListTail(IN PDEVICE_EXTENSION pdx);
LIST_NODE *mallocStrNode();


HANDLE file_handle = NULL;
OBJECT_ATTRIBUTES object_attributes;
IO_STATUS_BLOCK io_status;
LARGE_INTEGER offset = { 0 };
UNICODE_STRING file_name = RTL_CONSTANT_STRING(L"\\??\\C:\\a.txt");
USHORT buf[10] = { 0 };
ULONG func_code[10][100][2];
ULONG func_num[10] = { 0 };
ULONG j = 0;
PDEVICE_OBJECT lowerDev[10];
ULONG lowerDev_num = 0;

///////////////////////////////////////////////////////////////////////////////
#pragma INITCODE 
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath)
{							// DriverEntry
	KdPrint((DRIVERNAME " - Entering DriverEntry: DriverObject %8.8lX\n", DriverObject));
	// Initialize function pointers
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->DriverExtension->AddDevice = AddDevice;
	for (int i = 0; i < arraysize(DriverObject->MajorFunction); ++i)
		DriverObject->MajorFunction[i] = DispatchAny;
	DriverObject->MajorFunction[IRP_MJ_POWER] = DispatchPower;
	DriverObject->MajorFunction[IRP_MJ_PNP] = DispatchPnp;
	DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = DispatchInternalDeviceControl;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoDeviceControl;
	//DriverObject->MajorFunction[IRP_MJ_SCSI] = DispatchForSCSI;


	/*if (file_handle == NULL)
	{
		InitializeObjectAttributes(
			&object_attributes,
			&file_name,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
		status = ZwCreateFile(
			&file_handle,
			FILE_APPEND_DATA,
			&object_attributes,
			&io_status,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN_IF,
			FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
	}*/

	return STATUS_SUCCESS;
}							// DriverEntry


///////////////////////////////////////////////////////////////////////////////
#pragma PAGEDCODE
VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{							// DriverUnload
	PAGED_CODE();
	KdPrint((DRIVERNAME " - Entering DriverUnload: DriverObject %8.8lX\n", DriverObject));
}							// DriverUnload

///////////////////////////////////////////////////////////////////////////////

NTSTATUS AddDevice(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT pdo)
{							// AddDevice
	PAGED_CODE();
	NTSTATUS status;

	PDEVICE_OBJECT fido;
	static UNICODE_STRING pdo_name = pdo->DriverObject->DriverName;
	UNICODE_STRING target_driver;
	RtlInitUnicodeString(&target_driver, TARGETDRIVER);
	//KdPrint(("Attached to driver: %wZ\n", &pdo_name));
	//KdPrint(("Attached to driver: %wZ\n", &target_driver));

	if (RtlEqualUnicodeString(&target_driver, &pdo_name, TRUE))
	{
		ULONG j, k;
		lowerDev[lowerDev_num] = pdo;
		for (j = 0; j < 100; j++)
			for (k = 0; k < 2; k++)
				func_code[lowerDev_num][j][k] = -1;
		lowerDev_num++;

		status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), NULL,
			GetDeviceTypeToUse(pdo), 0, FALSE, &fido);
		if (!NT_SUCCESS(status))
		{						// can't create device object
			KdPrint((DRIVERNAME " - IoCreateDevice failed - %X\n", status));
			return status;
		}						// can't create device object
		PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;

		do
		{	
			// finish initialization
			IoInitializeRemoveLock(&pdx->RemoveLock, 0, 0, 0);
			KeInitializeEvent(&pdx->List_event, SynchronizationEvent, TRUE);
			KeInitializeSpinLock(&pdx->ListLock);
			InitializeListHead(&pdx->ListHead);

			pdx->DeviceObject = fido;
			pdx->Pdo = pdo;
			//将过滤驱动附加在底层驱动之上
			PDEVICE_OBJECT fdo = IoAttachDeviceToDeviceStack(fido, pdo);
			if (!fdo)
			{					// can't attach								 
				KdPrint((DRIVERNAME " - IoAttachDeviceToDeviceStack failed\n"));
				status = STATUS_DEVICE_REMOVED;
				break;
			}					// can't attach
								//记录底层驱动
			pdx->LowerDeviceObject = fdo;
			//由于不知道底层驱动是直接IO还是BufferIO，因此将标志都置上
			fido->Flags |= fdo->Flags & (DO_DIRECT_IO | DO_BUFFERED_IO | DO_POWER_PAGABLE);
			// Clear the "initializing" flag so that we can get IRPs
			fido->Flags &= ~DO_DEVICE_INITIALIZING;
		} while (FALSE);					// finish initialization

		if (!NT_SUCCESS(status))
		{					// need to cleanup
			if (pdx->LowerDeviceObject)
				IoDetachDevice(pdx->LowerDeviceObject);
			IoDeleteDevice(fido);
		}					// need to cleanup
	}
	else
		KdPrint(("Not equal.\n"));

	return status;
}							// AddDevice


							///////////////////////////////////////////////////////////////////////////////
#pragma LOCKEDCODE
NTSTATUS CompleteRequest(IN PIRP Irp, IN NTSTATUS status, IN ULONG_PTR info)
{							// CompleteRequest
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}							// CompleteRequest

NTSTATUS
USBSCSICompletion(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context)
{
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)
		DeviceObject->DeviceExtension;

	IoAcquireRemoveLock(&pdx->RemoveLock, Irp);

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

	PSCSI_REQUEST_BLOCK CurSrb = irpStack->Parameters.Scsi.Srb;
	PCDB cdb = (PCDB)CurSrb->Cdb;
	UCHAR opCode = cdb->CDB6GENERIC.OperationCode;

	if (opCode == SCSIOP_MODE_SENSE  && CurSrb->DataBuffer
		&& CurSrb->DataTransferLength >=
		sizeof(MODE_PARAMETER_HEADER))
	{
		KdPrint(("SCSIOP_MODE_SENSE comming!\n"));

		PMODE_PARAMETER_HEADER modeData = (PMODE_PARAMETER_HEADER)CurSrb->DataBuffer;

		modeData->DeviceSpecificParameter |= MODE_DSP_WRITE_PROTECT;
	}

	if (Irp->PendingReturned)
	{
		IoMarkIrpPending(Irp);
	}

	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);

	return Irp->IoStatus.Status;
}

#pragma LOCKEDCODE
NTSTATUS DispatchForSCSI(IN PDEVICE_OBJECT fido, IN PIRP Irp)
{

	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

	// Pass request down without additional processing
	NTSTATUS status;
	status = IoAcquireRemoveLock(&pdx->RemoveLock, Irp);
	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);

	IoCopyCurrentIrpStackLocationToNext(Irp);

	IoSetCompletionRoutine(Irp,
		USBSCSICompletion,
		NULL,
		TRUE,
		TRUE,
		TRUE);
	status = IoCallDriver(pdx->LowerDeviceObject, Irp);
	return status;
}
///////////////////////////////////////////////////////////////////////////////

NTSTATUS InternalCompletion(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context)
{
	NTSTATUS status;
	UCHAR *pbuf;
	ULONG len;
	ULONG i;
	LIST_NODE *list_node = (LIST_NODE *)Context;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	PURB urb = (PURB)stack->Parameters.Others.Argument1;
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;


	if (urb != NULL)
	{
		ULONG devSeq = GetDevSeq(pdx->Pdo);
		if (func_num[devSeq] < 100)
		{
			func_code[devSeq][func_num[devSeq]][1] = urb->UrbHeader.Function;
			func_num[devSeq]++;
		}
		/*if (i == 100)
			for (i = 0; i < 100; i++)
			{
				KdPrint(("%x|%x ", func_code[i][0], func_code[i][1]));
				if (i % 10 == 9)
					KdPrint(("\n"));
			}
		i = 100;*/

		switch (urb->UrbHeader.Function)
		{
		case URB_FUNCTION_CONTROL_TRANSFER:
			//0x8 对应0x28
			if (urb->UrbControlDescriptorRequest.DescriptorType == 0x22)
			{
				//KdPrint(("get descriptor.\n"));
				pbuf = (UCHAR *)urb->UrbControlDescriptorRequest.TransferBuffer;
				len = urb->UrbControlDescriptorRequest.TransferBufferLength;
				//KdPrint(("Descriptor len: %d\n", len));
			}
			break;
		case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
			if ((urb->UrbBulkOrInterruptTransfer.TransferFlags) & 0x01)
			{
				pbuf = (UCHAR *)urb->UrbBulkOrInterruptTransfer.TransferBuffer;
				len = urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
				if (list_node != NULL)
				{
					list_node->Bulk_in.Buf = ExAllocatePoolWithTag(NonPagedPool, len, MEM_TAG);
					memcpy(list_node->Bulk_in.Buf, pbuf, len);
					list_node->Bulk_in.Len = len;
					list_node->Bulk_in.TranferFlags = urb->UrbBulkOrInterruptTransfer.TransferFlags;

					//add node to list
					ExInterlockedInsertTailList(&pdx->ListHead, (PLIST_ENTRY)list_node, &pdx->ListLock);
					//KeSetEvent(&list_event, 0, FALSE);

					GetListTail(pdx);
				}
			}
			break;
		default:
			break;
		}
	}
	
	if (Irp->PendingReturned) {

		IoMarkIrpPending(Irp);
	}

	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);

	return Irp->IoStatus.Status;
}

#pragma LOCKEDCODE
NTSTATUS DispatchInternalDeviceControl(IN PDEVICE_OBJECT fido, IN PIRP Irp)
{
	NTSTATUS status;
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	PURB urb = (PURB) stack->Parameters.Others.Argument1;
	ULONG i;
	LIST_NODE *list_node;

	status = IoAcquireRemoveLock(&pdx->RemoveLock, Irp);
	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_INTERNAL_USB_SUBMIT_URB
		&& urb != NULL)
	{
		/*buf[0] = urb->UrbHeader.Function;
		buf[9] = '\n';
		status = ZwWriteFile(
			file_handle, NULL, NULL, NULL,
			&io_status,
			buf, 10, NULL,
			NULL
		);
		offset.QuadPart += 10;
		if (!NT_SUCCESS(status))
			KdPrint(("Write file failed. %x.\n", status));
		status = STATUS_SUCCESS;*/
		ULONG devSeq = GetDevSeq(pdx->Pdo);
		ULONG j;
		/*if (func_num[devSeq] < 100)
		{
			func_code[devSeq][func_num[devSeq]][0] = urb->UrbHeader.Function;
		}
		for (j = 0; j < 100; j++)
		{
			KdPrint(("%x|%x ", func_code[devSeq][j][0], func_code[devSeq][j][1]));
			if (j % 10 == 9)
				KdPrint(("\n"));
		}*/

		switch (urb->UrbHeader.Function)
		{
		case URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE:
			//0x28
			if (urb->UrbControlDescriptorRequest.DescriptorType == 0x22)
			{

				//完成函数
				IoCopyCurrentIrpStackLocationToNext(Irp);
				IoSetCompletionRoutine(Irp,
					InternalCompletion,
					NULL,
					TRUE,
					TRUE,
					TRUE);
				return IoCallDriver(pdx->LowerDeviceObject, Irp);
			}
			break;
		case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
			//0x9
			//最低位为传输方向
			if ((urb->UrbBulkOrInterruptTransfer.TransferFlags) & 0x01)
			{
				UCHAR *pbuf;
				ULONG len;
				pbuf = (UCHAR *)urb->UrbBulkOrInterruptTransfer.TransferBuffer;
				len = urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
				
				list_node = mallocStrNode();
				if (list_node == NULL)
				{
					KdPrint(("Node malloc failed.\n"));
					break;
				}
				list_node->Bulk_out.Buf = ExAllocatePoolWithTag(NonPagedPool, len, MEM_TAG);
				if (list_node->Bulk_out.Buf != NULL)
				{
					memcpy(list_node->Bulk_out.Buf, pbuf, len);
					list_node->Bulk_out.Len = len;
					list_node->Bulk_out.TranferFlags = urb->UrbBulkOrInterruptTransfer.TransferFlags;
				}
					
				

				//完成函数
				IoCopyCurrentIrpStackLocationToNext(Irp);
				IoSetCompletionRoutine(Irp,
					InternalCompletion,
					list_node,
					TRUE,
					TRUE,
					TRUE);
				return IoCallDriver(pdx->LowerDeviceObject, Irp);
			}
			else
			{
				//KdPrint(("Output.\n"));
				//get buf
				UCHAR *pbuf;
				ULONG len;

				pbuf = (UCHAR *)urb->UrbBulkOrInterruptTransfer.TransferBuffer;
				len = urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
			}
			break;
		default:
			break;
		}
	}

	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(pdx->LowerDeviceObject, Irp);

	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);

	return status;
}


NTSTATUS DispatchIoDeviceControl(
	IN PDEVICE_OBJECT fido,
	IN PIRP Irp
)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	NTSTATUS status;
	ULONG outlen = stack->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG node_len = sizeof(LIST_NODE);
	ULONG ret_len = 0;
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	LIST_NODE *list_node = NULL;

	IoAcquireRemoveLock(&pdx->RemoveLock, Irp);
	
	status = STATUS_SUCCESS;
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_READ_LIST:
		list_node = (LIST_NODE *)ExInterlockedRemoveHeadList(&pdx->ListHead, &pdx->ListLock);

		if (outlen < node_len)
		{
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		if (list_node != NULL)
		{
			RtlCopyMemory(pBuf, list_node, node_len);
			ret_len = node_len;

			//free memory
			ExFreePoolWithTag(list_node->Bulk_in.Buf, MEM_TAG);
			ExFreePoolWithTag(list_node->Bulk_out.Buf, MEM_TAG);
			ExFreePoolWithTag(list_node, MEM_TAG);

			//irp
			Irp->IoStatus.Information = ret_len;
			Irp->IoStatus.Status = status;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
		}
		break;

	default:
		IoSkipCurrentIrpStackLocation(Irp);
		status = IoCallDriver(pdx->LowerDeviceObject, Irp);
		break;
	}

	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);

	return status;
}


VOID MyWriteFile(UCHAR *pbuf, ULONG len)
{
	NTSTATUS status;
	status = ZwWriteFile(
		file_handle, NULL, NULL, NULL,
		&io_status,
		(PVOID)pbuf, len, &offset,
		NULL
	);
	offset.QuadPart += len;
	if (!NT_SUCCESS(status))
		KdPrint(("Write file failed.\n"));
}

ULONG GetDevSeq(IN PDEVICE_OBJECT pdo)
{
	ULONG i;
	for (i = 0; i < lowerDev_num; i++)
		if (lowerDev[i] == pdo)
			return i;
	return -1;
}

VOID GetListTail(IN PDEVICE_EXTENSION pdx)
{
	LIST_NODE *list_node;
	list_node = (LIST_NODE *)ExInterlockedRemoveHeadList(&pdx->ListHead, &pdx->ListLock);
	ULONG i;
	UCHAR *pbuf;
	if (list_node != NULL)
	{
		KdPrint(("falgs: %#x\t%#x\n", list_node->Bulk_out.TranferFlags, list_node->Bulk_in.TranferFlags));
		KdPrint(("len: %d\t%d\n", list_node->Bulk_out.Len, list_node->Bulk_in.Len));
		KdPrint(("buf: "));
		pbuf = (UCHAR *)list_node->Bulk_out.Buf;
		for (i = 0; i < list_node->Bulk_in.Len; i++)
			KdPrint(("%02x ", pbuf[i]));
		KdPrint(("\t"));
		pbuf = (UCHAR *)list_node->Bulk_in.Buf;
		for (i = 0; i < list_node->Bulk_in.Len; i++)
			KdPrint(("%02x ", pbuf[i]));
		KdPrint(("\n"));

		//free memory
		ExFreePoolWithTag(list_node->Bulk_in.Buf, MEM_TAG);
		ExFreePoolWithTag(list_node->Bulk_out.Buf, MEM_TAG);
		ExFreePoolWithTag(list_node, MEM_TAG);
	}
}

#pragma LOCKEDCODE				// make no assumptions about pageability of dispatch fcns
NTSTATUS DispatchAny(IN PDEVICE_OBJECT fido, IN PIRP Irp)
{							// DispatchAny
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	static char* irpname[] =
	{
		"IRP_MJ_CREATE",
		"IRP_MJ_CREATE_NAMED_PIPE",
		"IRP_MJ_CLOSE",
		"IRP_MJ_READ",
		"IRP_MJ_WRITE",
		"IRP_MJ_QUERY_INFORMATION",
		"IRP_MJ_SET_INFORMATION",
		"IRP_MJ_QUERY_EA",
		"IRP_MJ_SET_EA",
		"IRP_MJ_FLUSH_BUFFERS",
		"IRP_MJ_QUERY_VOLUME_INFORMATION",
		"IRP_MJ_SET_VOLUME_INFORMATION",
		"IRP_MJ_DIRECTORY_CONTROL",
		"IRP_MJ_FILE_SYSTEM_CONTROL",
		"IRP_MJ_DEVICE_CONTROL",
		"IRP_MJ_INTERNAL_DEVICE_CONTROL",
		"IRP_MJ_SHUTDOWN",
		"IRP_MJ_LOCK_CONTROL",
		"IRP_MJ_CLEANUP",
		"IRP_MJ_CREATE_MAILSLOT",
		"IRP_MJ_QUERY_SECURITY",
		"IRP_MJ_SET_SECURITY",
		"IRP_MJ_POWER",
		"IRP_MJ_SYSTEM_CONTROL",
		"IRP_MJ_DEVICE_CHANGE",
		"IRP_MJ_QUERY_QUOTA",
		"IRP_MJ_SET_QUOTA",
		"IRP_MJ_PNP",
	};

	UCHAR type = stack->MajorFunction;
	if (type >= arraysize(irpname))
	 	KdPrint((DRIVERNAME " - Unknown IRP, major type %X\n", type));
	else
	 	KdPrint((DRIVERNAME " - %s\n", irpname[type]));

	/*
	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_INTERNAL_USB_SUBMIT_URB)
		KdPrint(("Submit urb.\n"));*/

	/*static UNICODE_STRING driver_name = pdx->LowerDeviceObject->DriverObject->DriverName;
	KdPrint((DRIVERNAME " -Driver: %wZ.\n", &driver_name));*/

	/*if (stack->DeviceObject == fido)
		KdPrint(("stack->DeviceObject == fido.\n"));*/

	// Pass request down without additional processing

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_INTERNAL_USB_SUBMIT_URB)
	{
		PURB urb = (PURB)stack->Parameters.Others.Argument1;
		if (urb != NULL)
		{
			KdPrint(("Urb function: %x\n", urb->UrbHeader.Function));
		}
	}

	NTSTATUS status;
	status = IoAcquireRemoveLock(&pdx->RemoveLock, Irp);
	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);
	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(pdx->LowerDeviceObject, Irp);
	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);
	return status;
}// DispatchAny


///////////////////////////////////////////////////////////////////////////////
NTSTATUS DispatchPower(IN PDEVICE_OBJECT fido, IN PIRP Irp)
{							// DispatchPower
#if DBG
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG fcn = stack->MinorFunction;
	static char* fcnname[] =
	{
		"IRP_MN_WAIT_WAKE",
		"IRP_MN_POWER_SEQUENCE",
		"IRP_MN_SET_POWER",
		"IRP_MN_QUERY_POWER",
	};

	if (fcn == IRP_MN_SET_POWER || fcn == IRP_MN_QUERY_POWER)
	{
		static char* sysstate[] =
		{
			"PowerSystemUnspecified",
			"PowerSystemWorking",
			"PowerSystemSleeping1",
			"PowerSystemSleeping2",
			"PowerSystemSleeping3",
			"PowerSystemHibernate",
			"PowerSystemShutdown",
			"PowerSystemMaximum",
		};

		static char* devstate[] =
		{
			"PowerDeviceUnspecified",
			"PowerDeviceD0",
			"PowerDeviceD1",
			"PowerDeviceD2",
			"PowerDeviceD3",
			"PowerDeviceMaximum",
		};

		ULONG context = stack->Parameters.Power.SystemContext;
		POWER_STATE_TYPE type = stack->Parameters.Power.Type;
		KdPrint((DRIVERNAME " - IRP_MJ_POWER (%s)", fcnname[fcn]));
		if (type == SystemPowerState)
			KdPrint((", SystemPowerState = %s\n", sysstate[stack->Parameters.Power.State.SystemState]));
		else
			KdPrint((", DevicePowerState = %s\n", devstate[stack->Parameters.Power.State.DeviceState]));
	}
	else if (fcn < arraysize(fcnname))
		KdPrint((DRIVERNAME " - IRP_MJ_POWER (%s)\n", fcnname[fcn]));
	else
		KdPrint((DRIVERNAME " - IRP_MJ_POWER (%2.2X)\n", fcn));
#endif // DBG

	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	PoStartNextPowerIrp(Irp);	// must be done while we own the IRP
	NTSTATUS status;
	status = IoAcquireRemoveLock(&pdx->RemoveLock, Irp);
	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);
	IoSkipCurrentIrpStackLocation(Irp);
	status = PoCallDriver(pdx->LowerDeviceObject, Irp);
	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);
	return status;
}							// DispatchPower


							///////////////////////////////////////////////////////////////////////////////
NTSTATUS DispatchPnp(IN PDEVICE_OBJECT fido, IN PIRP Irp)
{							// DispatchPnp
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG fcn = stack->MinorFunction;
	NTSTATUS status;
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	LIST_NODE *list_node;

	status = IoAcquireRemoveLock(&pdx->RemoveLock, Irp);
	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);
	static char* pnpname[] =
	{
		"IRP_MN_START_DEVICE",
		"IRP_MN_QUERY_REMOVE_DEVICE",
		"IRP_MN_REMOVE_DEVICE",
		"IRP_MN_CANCEL_REMOVE_DEVICE",
		"IRP_MN_STOP_DEVICE",
		"IRP_MN_QUERY_STOP_DEVICE",
		"IRP_MN_CANCEL_STOP_DEVICE",
		"IRP_MN_QUERY_DEVICE_RELATIONS",
		"IRP_MN_QUERY_INTERFACE",
		"IRP_MN_QUERY_CAPABILITIES",
		"IRP_MN_QUERY_RESOURCES",
		"IRP_MN_QUERY_RESOURCE_REQUIREMENTS",
		"IRP_MN_QUERY_DEVICE_TEXT",
		"IRP_MN_FILTER_RESOURCE_REQUIREMENTS",
		"",
		"IRP_MN_READ_CONFIG",
		"IRP_MN_WRITE_CONFIG",
		"IRP_MN_EJECT",
		"IRP_MN_SET_LOCK",
		"IRP_MN_QUERY_ID",
		"IRP_MN_QUERY_PNP_DEVICE_STATE",
		"IRP_MN_QUERY_BUS_INFORMATION",
		"IRP_MN_DEVICE_USAGE_NOTIFICATION",
		"IRP_MN_SURPRISE_REMOVAL",
		"IRP_MN_QUERY_LEGACY_BUS_INFORMATION",
	};

	if (fcn < arraysize(pnpname))
		KdPrint((DRIVERNAME " - IRP_MJ_PNP (%s)\n", pnpname[fcn]));
	else
		KdPrint((DRIVERNAME " - IRP_MJ_PNP (%2.2X)\n", fcn));

	// Handle usage notification specially in order to track power pageable
	// flag correctly. We need to avoid allowing a non-pageable handler to be
	// layered on top of a pageable handler.
	if (fcn == IRP_MN_DEVICE_USAGE_NOTIFICATION)
	{						// usage notification
		if (!fido->AttachedDevice || (fido->AttachedDevice->Flags & DO_POWER_PAGABLE))
			fido->Flags |= DO_POWER_PAGABLE;
		IoCopyCurrentIrpStackLocationToNext(Irp);
		IoSetCompletionRoutine(Irp, (PIO_COMPLETION_ROUTINE)UsageNotificationCompletionRoutine,
			(PVOID)pdx, TRUE, TRUE, TRUE);
		return IoCallDriver(pdx->LowerDeviceObject, Irp);
	}						// usage notification

							// Handle start device specially in order to correctly inherit
							// FILE_REMOVABLE_MEDIA
	if (fcn == IRP_MN_START_DEVICE)
	{						// device start
		IoCopyCurrentIrpStackLocationToNext(Irp);
		IoSetCompletionRoutine(Irp, (PIO_COMPLETION_ROUTINE)StartDeviceCompletionRoutine,
			(PVOID)pdx, TRUE, TRUE, TRUE);
		return IoCallDriver(pdx->LowerDeviceObject, Irp);
	}						// device start

							// Handle remove device specially in order to cleanup device stack
	if (fcn == IRP_MN_REMOVE_DEVICE)
	{						// remove device
		IoSkipCurrentIrpStackLocation(Irp);
		status = IoCallDriver(pdx->LowerDeviceObject, Irp);
		IoReleaseRemoveLockAndWait(&pdx->RemoveLock, Irp);

		//回收链表内存
		while (1) {
			list_node = (LIST_NODE *)ExfInterlockedRemoveHeadList(
				&pdx->ListHead, &pdx->ListLock);
			if (list_node != NULL) 
			{
				if(list_node->Bulk_in.Buf != NULL)
					ExFreePoolWithTag(list_node->Bulk_in.Buf, MEM_TAG);
				if(list_node->Bulk_out.Buf != NULL)
					ExFreePoolWithTag(list_node->Bulk_out.Buf, MEM_TAG);

					ExFreePoolWithTag(list_node, MEM_TAG);
			}
			else
				break;
		}

		IoDetachDevice(pdx->LowerDeviceObject);
		RemoveDevice(fido);
		return status;
	}						// remove device

							// Simply forward any other type of PnP request
	IoSkipCurrentIrpStackLocation(Irp);
	status = IoCallDriver(pdx->LowerDeviceObject, Irp);
	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);
	return status;
}							// DispatchPnp

///////////////////////////////////////////////////////////////////////////////
// GetDeviceTypeToUse returns the device object type of the next lower device
// object. This helps overcome a bug in some Win2K file systems which expect the
// topmost FiDO in a storage stack to have a VPB and, hence, to have been created
// with a type such as FILE_DEVICE_DISK.
#pragma PAGEDCODE
ULONG GetDeviceTypeToUse(PDEVICE_OBJECT pdo)
{							// GetDeviceTypeToUse
	PDEVICE_OBJECT ldo = IoGetAttachedDeviceReference(pdo);
	if (!ldo)
		return FILE_DEVICE_UNKNOWN;
	ULONG devtype = ldo->DeviceType;
	ObDereferenceObject(ldo);
	return devtype;
}							// GetDeviceTypeToUse

							///////////////////////////////////////////////////////////////////////////////
#pragma PAGEDCODE
VOID RemoveDevice(IN PDEVICE_OBJECT fido)
{							// RemoveDevice
	KdPrint(("Enter RemoveDevice"));
	PAGED_CODE();
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	if (pdx->LowerDeviceObject)
		IoDetachDevice(pdx->LowerDeviceObject);
	IoDeleteDevice(fido);
}							// RemoveDevice

							///////////////////////////////////////////////////////////////////////////////
#pragma LOCKEDCODE
NTSTATUS StartDeviceCompletionRoutine(PDEVICE_OBJECT fido, PIRP Irp, PDEVICE_EXTENSION pdx)
{							// StartDeviceCompletionRoutine
	if (Irp->PendingReturned)
		IoMarkIrpPending(Irp);
	// Inherit FILE_REMOVABLE_MEDIA flag from lower object. This is necessary
	// for a disk filter, but it isn't available until start-device time. Drivers
	// above us may examine the flag as part of their own start-device processing, too.
	if (pdx->LowerDeviceObject->Characteristics & FILE_REMOVABLE_MEDIA)
		fido->Characteristics |= FILE_REMOVABLE_MEDIA;
	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);
	return STATUS_SUCCESS;
}							// StartDeviceCompletionRoutine

							///////////////////////////////////////////////////////////////////////////////
#pragma LOCKEDCODE
NTSTATUS UsageNotificationCompletionRoutine(PDEVICE_OBJECT fido, PIRP Irp, PDEVICE_EXTENSION pdx)
{							// UsageNotificationCompletionRoutine
	if (Irp->PendingReturned)
		IoMarkIrpPending(Irp);
	// If lower driver cleared pageable flag, we must do the same
	if (!(pdx->LowerDeviceObject->Flags & DO_POWER_PAGABLE))
		fido->Flags &= ~DO_POWER_PAGABLE;
	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);
	return STATUS_SUCCESS;
}							// UsageNotificationCompletionRoutine

#pragma LOCKEDCODE				// force inline functions into nonpaged code


LIST_NODE *mallocStrNode()
{
	LIST_NODE *ret = (LIST_NODE *)ExAllocatePoolWithTag(
		NonPagedPool, sizeof(LIST_NODE), MEM_TAG);
	return ret;
}