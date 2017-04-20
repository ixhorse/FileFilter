#include "linedrv.h"

#define FILTERNAME L"\\Driver\\FileFilter"
#define MEM_TAG "mtag"

#pragma INITCODE
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;

	//ע�������������ú������
	pDriverObject->DriverUnload = HelloDDKUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = HelloDDKCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = HelloDDKClose;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = HelloDDKDispatchRoutine;
	pDriverObject->MajorFunction[IRP_MJ_READ] = HelloDDKRead;

	//���������豸����
	status = CreateDevice(pDriverObject);

	KdPrint(("DriverA:Leave A DriverEntry\n"));
	return status;
}


/************************************************************************
* ��������:CreateDevice
* ��������:��ʼ���豸����
* �����б�:
pDriverObject:��I/O�������д���������������
* ���� ֵ:���س�ʼ��״̬
*************************************************************************/
#pragma INITCODE
NTSTATUS CreateDevice(
	IN PDRIVER_OBJECT	pDriverObject)
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	//�����豸����
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\LineDevice");

	//�����豸
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

	//������������
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, L"\\??\\LineDevice");
	pDevExt->ustrSymLinkName = symLinkName;
	status = IoCreateSymbolicLink(&symLinkName, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	return STATUS_SUCCESS;
}

/************************************************************************
* ��������:HelloDDKUnload
* ��������:�������������ж�ز���
* �����б�:
pDriverObject:��������
* ���� ֵ:����״̬
*************************************************************************/
#pragma PAGEDCODE
VOID HelloDDKUnload(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT	pNextObj;
	KdPrint(("DriverA:Enter A DriverUnload\n"));
	pNextObj = pDriverObject->DeviceObject;
	while (pNextObj != NULL)
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
			pNextObj->DeviceExtension;

		//ɾ����������
		UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;
		IoDeleteSymbolicLink(&pLinkName);
		pNextObj = pNextObj->NextDevice;
		IoDeleteDevice(pDevExt->pDevice);
	}
	KdPrint(("DriverA:Leave A DriverUnload\n"));
}


/************************************************************************
* ��������:HelloDDKRead
* ��������:�Զ�IRP���д���
* �����б�:
pDevObj:�����豸����
pIrp:��IO�����
* ���� ֵ:����״̬
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS HelloDDKRead(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp)
{
	NTSTATUS status;
	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
		pDevObj->DeviceExtension;
	PDRIVER_OBJECT fltDriver = NULL;
	PDEVICE_OBJECT fltDevice = NULL;
	UNICODE_STRING fltName;
	RtlInitUnicodeString(&fltName, FILTERNAME);

	status = ObReferenceObjectByName(
		&fltName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		IoDriverObjectType,
		KernelMode,
		NULL,
		&fltDriver
	);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Couldn't get driver object.\n"));
	}
	else
	{
		ObDereferenceObject(fltDriver);
	}

	fltDevice = fltDriver->DeviceObject;
	while (fltDevice)
	{
		PFILE_OBJECT FileObject;
		PIRP newIrp = IoAllocateIrp(fltDevice->StackSize, FALSE);
		IO_STATUS_BLOCK io_block;
		PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(newIrp);
		UCHAR * pBuf;
		ULONG len;
		LIST_NODE *list_node;
		ULONG i;

		newIrp->UserIosb = &io_block;
		newIrp->Tail.Overlay.Thread = PsGetCurrentThread();
		newIrp->AssociatedIrp.SystemBuffer = NULL;

		stack->MajorFunction = IRP_MJ_DEVICE_CONTROL;
		stack->Parameters.DeviceIoControl.IoControlCode = IOCTL_READ_LIST;
		stack->Parameters.DeviceIoControl.OutputBufferLength = sizeof(LIST_NODE);
		
		status = IoCallDriver(fltDevice, newIrp);

		if (!NT_SUCCESS(status))
		{
			break;
		}

		list_node = (LIST_NODE *)newIrp->AssociatedIrp.SystemBuffer;

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

		break;
	}
	

	return STATUS_PENDING;
}


/************************************************************************
* ��������:HelloDDKDispatchRoutine
* ��������:�Զ�IRP���д���
* �����б�:
pDevObj:�����豸����
pIrp:��IO�����
* ���� ֵ:����״̬
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	// ���IRP
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
	// ���IRP
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
	// ���IRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}