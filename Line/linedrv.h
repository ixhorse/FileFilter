/************************************************************************
* 文件名称:Driver.h
* 作    者:张帆
* 完成日期:2007-11-1
*************************************************************************/
#pragma once

#include <wdm.h>


#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()
#define INITCODE code_seg("INIT")

#define PAGEDDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")

#define arraysize(p) (sizeof(p)/sizeof((p)[0]))

#define IOCTL_READ_LIST \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X822,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;	//设备名称
	UNICODE_STRING ustrSymLinkName;	//符号链接名

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// 函数声明

NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDriverObject);
VOID HelloDDKUnload(IN PDRIVER_OBJECT pDriverObject);
NTSTATUS HelloDDKDispatchRoutine(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp);
NTSTATUS HelloDDKRead(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp);

NTSTATUS HelloDDKCreate(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp);
NTSTATUS HelloDDKClose(IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp);

NTSTATUS IoCtlCompletion(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp, IN PVOID Context);

extern POBJECT_TYPE *IoDriverObjectType;

NTSTATUS ObReferenceObjectByName(
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext,
	PVOID *Object
);

typedef struct {
	ULONG TranferFlags;
	ULONG Len;
	UCHAR Buf[100];
	PVOID MDLbuf;
}BULK_STRUCTURE;

typedef struct {
	LIST_ENTRY list_entry;
	BULK_STRUCTURE Bulk_in;
	BULK_STRUCTURE Bulk_out;
} LIST_NODE;