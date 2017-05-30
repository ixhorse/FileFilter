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

			pdx->flag = FALSE;
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

		pdx->Interface = NULL;

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
	NTSTATUS				status;
	UCHAR					*pbuf;
	ULONG					len;
	ULONG					i;
	LIST_NODE				*list_node = (LIST_NODE *)Context;
	PIO_STACK_LOCATION		stack = IoGetCurrentIrpStackLocation(Irp);
	PURB					urb = (PURB)stack->Parameters.Others.Argument1;
	PDEVICE_EXTENSION		pdx = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	PUSBD_INTERFACE_INFORMATION temp = NULL;


	if (urb != NULL)
	{
		ULONG devSeq = GetDevSeq(pdx->Pdo);
		if (func_num[devSeq] < 100)
		{
			func_code[devSeq][func_num[devSeq]][1] = urb->UrbHeader.Function;
			func_num[devSeq]++;
		}

		switch (urb->UrbHeader.Function)
		{
		case URB_FUNCTION_SELECT_CONFIGURATION:
			len = 0;
			temp = &urb->UrbSelectConfiguration.Interface;
			pdx->interfaceNums = urb->UrbSelectConfiguration.ConfigurationDescriptor->bNumInterfaces;

			pdx->InterfaceList = (PUSBD_INTERFACE_INFORMATION *)ExAllocatePoolWithTag(NonPagedPool, 
				pdx->interfaceNums * sizeof(PVOID),
				MEM_TAG);

			for (i = 0; i < pdx->interfaceNums; i++)
			{
				len += temp->Length;
				temp = (PUSBD_INTERFACE_INFORMATION)((char *)temp + temp->Length);
				//temp = temp + temp->Length;
			}

			pdx->Interface = (PUSBD_INTERFACE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, len, MEM_TAG);
			RtlCopyMemory(pdx->Interface, &urb->UrbSelectConfiguration.Interface, len);

			temp = pdx->Interface;
			for (i = 0; i < pdx->interfaceNums; i++)
			{
				pdx->InterfaceList[i] = temp;
				//temp += temp->Length;
				temp = (PUSBD_INTERFACE_INFORMATION)((char *)temp + temp->Length);
			}
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
				len = (len > 100 ? 100 : len);
				if (list_node != NULL)
				{
					//list_node->Bulk_in.Buf = ExAllocatePoolWithTag(NonPagedPool, len, MEM_TAG);
					memcpy(list_node->Bulk_in.Buf, pbuf, len);
					list_node->Bulk_in.Len = len;
					list_node->Bulk_in.TranferFlags = urb->UrbBulkOrInterruptTransfer.TransferFlags;

					//add node to list
					ExInterlockedInsertTailList(&pdx->ListHead, (PLIST_ENTRY)list_node, &pdx->ListLock);
					//KeSetEvent(&list_event, 0, FALSE);

					//GetListTail(pdx);
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
	NTSTATUS				status;
	PDEVICE_EXTENSION		pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	PIO_STACK_LOCATION		stack = IoGetCurrentIrpStackLocation(Irp);
	PURB					urb = (PURB)stack->Parameters.Others.Argument1;
	ULONG					i;
	LIST_NODE				*list_node;
	PFILE_OBJECT			fileObject = NULL;
	PUSBD_PIPE_INFORMATION	pipeInfo = NULL;

	status = IoAcquireRemoveLock(&pdx->RemoveLock, Irp);
	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_INTERNAL_USB_SUBMIT_URB
		&& urb != NULL)
	{

		switch (urb->UrbHeader.Function)
		{
		case URB_FUNCTION_SELECT_CONFIGURATION:
			IoCopyCurrentIrpStackLocationToNext(Irp);
			IoSetCompletionRoutine(Irp,
				InternalCompletion,
				NULL,
				TRUE,
				TRUE,
				TRUE);
			return IoCallDriver(pdx->LowerDeviceObject, Irp);
			break;
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
				if (pdx->flag == TRUE)
				{
					
					pbuf = (UCHAR *)urb->UrbBulkOrInterruptTransfer.TransferBuffer;
					len = urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
					len = (len > 100 ? 100 : len);

					list_node = mallocStrNode();
					if (list_node == NULL)
					{
						KdPrint(("Node malloc failed.\n"));
						break;
					}
					//list_node->Bulk_out.Buf = ExAllocatePoolWithTag(NonPagedPool, len, MEM_TAG);
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
					IoReleaseRemoveLock(&pdx->RemoveLock, Irp);
					return IoCallDriver(pdx->LowerDeviceObject, Irp);
				}
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
	PIO_STACK_LOCATION				stack = IoGetCurrentIrpStackLocation(Irp);
	PIO_STACK_LOCATION				nextStack;
	PDEVICE_EXTENSION				pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	NTSTATUS						status;
	ULONG							outlen = stack->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG							inlen = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG							node_len = sizeof(LIST_NODE);
	ULONG							ret_len = 0;
	PVOID							pBuf = Irp->AssociatedIrp.SystemBuffer;
	LIST_NODE						*list_node = NULL;
	PUSBD_INTERFACE_INFORMATION		Interface = NULL;
	PURB							urb = NULL;
	PIRP							newIrp = NULL;
	IO_STATUS_BLOCK					io_block;
	CHAR                            *Buffer;
	PIPE_INFO						*pipe_info = NULL;
	ULONG							pipeNums;

	IoAcquireRemoveLock(&pdx->RemoveLock, Irp);
	
	status = STATUS_SUCCESS;
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_READ_LIST:
		if (outlen < node_len)
		{
			KdPrint(("len wrong.\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		list_node = (LIST_NODE *)ExInterlockedRemoveHeadList(&pdx->ListHead, &pdx->ListLock);
		if (list_node != NULL)
		{
			RtlCopyMemory(pBuf, list_node, node_len);
			ret_len = node_len;

			//free memory
			ExFreePoolWithTag(list_node, MEM_TAG);
		}

			//irp
			Irp->IoStatus.Information = ret_len;
			Irp->IoStatus.Status = status;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;

	case IOCTL_SET_FLAG:
		KdPrint(("Set flag.\n"));
		pdx->flag = TRUE;

		//irp
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;

	case IOCTL_CLEAR_FLAG:
		KdPrint(("Clear flag.\n"));
		pdx->flag = FALSE;

		//回收链表内存
		while (1) {
			list_node = (LIST_NODE *)ExfInterlockedRemoveHeadList(
				&pdx->ListHead, &pdx->ListLock);
			if (list_node != NULL)
			{
				ExFreePoolWithTag(list_node, MEM_TAG);
			}
			else
				break;
		}
		//irp
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;

	case IOCTL_FIND_FILTER:
		KdPrint((DRIVERNAME " - find filter\n"));

		RetrievePipeInfo(fido, &pipe_info, &pipeNums);

		if (pipe_info)
		{
			if (outlen < pipeNums * sizeof(PIPE_INFO))
			{
				KdPrint((DRIVERNAME " - wrong length.\n"));
				status = STATUS_INVALID_PARAMETER;
				ret_len = 0;
			}
			else
			{
				ret_len = pipeNums * sizeof(PIPE_INFO);
				RtlCopyMemory(pBuf, pipe_info, pipeNums * sizeof(PIPE_INFO));
			}
			ExFreePool(pipe_info);
		}
		else
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			ret_len = 0;
		}
		

		Irp->IoStatus.Information = ret_len;
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		break;

	case IOCTL_SEND_DATA:
		KdPrint((DRIVERNAME " - send data\n"));
		KdPrint((DRIVERNAME " - len:%d data:%s\n", inlen, pBuf));
			

		Buffer = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, inlen, MEM_TAG);
		RtlZeroMemory(Buffer, inlen);
		RtlCopyMemory(Buffer, pBuf, inlen);

		urb = (PURB)ExAllocatePool(NonPagedPool,
			sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER));

		if (urb && pdx->PipeHandle) {
			UsbBuildInterruptOrBulkTransferRequest(
				urb,
				sizeof(struct _URB_BULK_OR_INTERRUPT_TRANSFER),
				pdx->PipeHandle,
				Buffer,
				NULL,
				inlen,
				USBD_TRANSFER_DIRECTION_IN,
				NULL);

			status = CallUSBD(fido, urb);

			if (!NT_SUCCESS(status))
			{
				KdPrint((DRIVERNAME " - send call fail %x.\n", status));
			}
			else
			{
				KdPrint((DRIVERNAME " - send call success.\n"));

				RtlCopyMemory(pBuf, Buffer, inlen);
			}
			ExFreePool(urb);

			Irp->IoStatus.Information = inlen;
			Irp->IoStatus.Status = status;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			break;

			/*urb = (PURB)ExAllocatePool(NonPagedPool,
				sizeof(struct _URB_PIPE_REQUEST));
			urb->UrbHeader.Length = (USHORT) sizeof(struct _URB_PIPE_REQUEST);
			urb->UrbHeader.Function = URB_FUNCTION_RESET_PIPE;
			urb->UrbPipeRequest.PipeHandle = Interface->Pipes[0].PipeHandle;

			status = CallUSBD(fido, urb);
			if (!NT_SUCCESS(status))
			{
				KdPrint((DRIVERNAME " - reset call fail %x.\n", status));
			}
			else
			{
				KdPrint((DRIVERNAME " - reset call success.\n"));
			}
			ExFreePool(urb);*/
		}
		else
		{
			KdPrint((DRIVERNAME " - urb or handle null.\n"));
		}
		ExFreePool(Buffer);

		//irp
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;

	case IOCTL_SELECT_PIPE:
		KdPrint((DRIVERNAME " - set pipe\n"));

		if (inlen == sizeof(USBD_PIPE_HANDLE))
		{
			pdx->PipeHandle = *(USBD_PIPE_HANDLE *)pBuf;
			status = STATUS_SUCCESS;
		}
		else
		{
			KdPrint((DRIVERNAME " - wrong para.\n"));
			status = STATUS_INVALID_PARAMETER;
		}

		//Irp
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;

	default:
		IoSkipCurrentIrpStackLocation(Irp);
		status = IoCallDriver(pdx->LowerDeviceObject, Irp);
		break;
	}

	IoReleaseRemoveLock(&pdx->RemoveLock, Irp);

	return status;
}

NTSTATUS IoCtlCompletion(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp, IN PVOID Context)
{
	return STATUS_MORE_PROCESSING_REQUIRED;
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
		//ExFreePoolWithTag(list_node->Bulk_in.Buf, MEM_TAG);
		//ExFreePoolWithTag(list_node->Bulk_out.Buf, MEM_TAG);
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
	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest(IOCTL_INTERNAL_USB_SUBMIT_URB,
		deviceExtension->LowerDeviceObject,
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

	ntStatus = IoCallDriver(deviceExtension->LowerDeviceObject, irp);

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
	IN PDEVICE_OBJECT				DeviceObject,
	OUT PPIPE_INFO					*pipe_info,
	OUT ULONG						 *pipeNums
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

	SelectInterfaces(DeviceObject, fullConfigDescriptor, pipe_info, pipeNums);

	//IoCompleteRequest(newIrp, IO_NO_INCREMENT);
	//ExFreePool(deviceDescriptor);

Exit:
	if(fullConfigDescriptor)
		ExFreePool(fullConfigDescriptor);
	if(pUrb)
		ExFreePool(pUrb);

	return status;
}



NTSTATUS
SelectInterfaces(
	IN PDEVICE_OBJECT                DeviceObject,
	IN PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor,
	OUT PPIPE_INFO					 *pipe_info,
	OUT ULONG						 *pipeNums
)
{
	LONG                        numberOfInterfaces,
								interfaceNumber,
								interfaceIndex,
								pipeNumber;
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
	USBD_PIPE_HANDLE			pipeHandle;

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

	//get numbers of all pipes
	pipeNumber = 0;
	for (interfaceIndex = 0;
		interfaceIndex < numberOfInterfaces;
		interfaceIndex++)
	{
		pipeNumber += interfaceList[interfaceIndex].Interface->NumberOfPipes;
	}

	//allocate memory
	*pipe_info = (PPIPE_INFO )ExAllocatePoolWithTag(NonPagedPool, pipeNumber * sizeof(PIPE_INFO), MEM_TAG);

	//
	for (interfaceIndex = 0;
		interfaceIndex < numberOfInterfaces;
		interfaceIndex++)
	{

		Interface = interfaceList[interfaceIndex].Interface;
		//Interface = &urb->UrbSelectConfiguration.Interface;
		deviceExtension->Interface = (PUSBD_INTERFACE_INFORMATION)ExAllocatePool(NonPagedPool,
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
		}

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

			(*pipe_info)[interfaceIndex + i].Class = Interface->Class;
			(*pipe_info)[interfaceIndex + i].Subclass = Interface->SubClass;
			(*pipe_info)[interfaceIndex + i].Protocol = Interface->Protocol;
			if(USB_ENDPOINT_DIRECTION_IN(Interface->Pipes[i].EndpointAddress))
				(*pipe_info)[interfaceIndex + i].Direction = In;
			else if(USB_ENDPOINT_DIRECTION_OUT(Interface->Pipes[i].EndpointAddress))
				(*pipe_info)[interfaceIndex + i].Direction = Out;
			(*pipe_info)[interfaceIndex + i].EndpointAddress = Interface->Pipes[i].EndpointAddress;
			switch (Interface->Pipes[i].PipeType)
			{
			case UsbdPipeTypeInterrupt:
				(*pipe_info)[interfaceIndex + i].PipeType = Interrupt;
				break;
			case UsbdPipeTypeBulk:
				(*pipe_info)[interfaceIndex + i].PipeType = Bulk;
				break;
			default:
				break;
			}
			(*pipe_info)[interfaceIndex + i].MaximumPacketSize = Interface->Pipes[i].MaximumPacketSize;
			(*pipe_info)[interfaceIndex + i].PipeHandle = Interface->Pipes[i].PipeHandle;
		}
	}

	*pipeNums = pipeNumber;

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

VOID RetrievePipeInfo(
	IN PDEVICE_OBJECT		fido,
	OUT PPIPE_INFO	    *pipe_info,
	OUT ULONG			*pipeNums
	)
{
	ULONG						interfaceIndex,
								pipeIndex,
								pipeNumber;
	PDEVICE_EXTENSION			pdx = (PDEVICE_EXTENSION)fido->DeviceExtension;
	PUSBD_INTERFACE_INFORMATION	xInterface;


	//get numbers of all pipes
	pipeNumber = 0;
	for (interfaceIndex = 0;
		interfaceIndex < pdx->interfaceNums;
		interfaceIndex++)
	{
		pipeNumber += pdx->InterfaceList[interfaceIndex]->NumberOfPipes;
	}

	*pipeNums = pipeNumber;

	//allocate memory
	*pipe_info = (PPIPE_INFO)ExAllocatePoolWithTag(NonPagedPool, pdx->interfaceNums * sizeof(PIPE_INFO), MEM_TAG);

	for (interfaceIndex = 0;
		interfaceIndex < pdx->interfaceNums;
		interfaceIndex++)
	{
		xInterface = pdx->InterfaceList[interfaceIndex];
		for (pipeIndex = 0;
			pipeIndex < xInterface->NumberOfPipes;
			pipeIndex++)
		{
			(*pipe_info)[interfaceIndex + pipeIndex].Class = xInterface->Class;
			(*pipe_info)[interfaceIndex + pipeIndex].Subclass = xInterface->SubClass;
			(*pipe_info)[interfaceIndex + pipeIndex].Protocol = xInterface->Protocol;
			switch (xInterface->Pipes[pipeIndex].PipeType)
			{
			case UsbdPipeTypeInterrupt:
				(*pipe_info)[interfaceIndex + pipeIndex].PipeType = Interrupt;
				(*pipe_info)[interfaceIndex + pipeIndex].Direction = In;
				break;
			case UsbdPipeTypeBulk:
				(*pipe_info)[interfaceIndex + pipeIndex].PipeType = Bulk;
				if (USB_ENDPOINT_DIRECTION_IN(xInterface->Pipes[pipeIndex].EndpointAddress))
					(*pipe_info)[interfaceIndex + pipeIndex].Direction = In;
				else if (USB_ENDPOINT_DIRECTION_OUT(xInterface->Pipes[pipeIndex].EndpointAddress))
					(*pipe_info)[interfaceIndex + pipeIndex].Direction = Out;
				break;
			default:
				break;
			}
			(*pipe_info)[interfaceIndex + pipeIndex].MaximumPacketSize = xInterface->Pipes[pipeIndex].MaximumPacketSize;
			(*pipe_info)[interfaceIndex + pipeIndex].PipeHandle = xInterface->Pipes[pipeIndex].PipeHandle;
		}
	}
}