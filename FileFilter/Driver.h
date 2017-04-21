#pragma once
// Declarations for filter driver

// Copyright (C) 1999 by Walter Oney

// All rights reserved



#ifndef DRIVER_H

#define DRIVER_H 



#define DRIVERNAME "MyFileFilter(zhangfan!)"					// for use in messages
#define TARGETDRIVER L"\\Driver\\usbhub"


///////////////////////////////////////////////////////////////////////////////

// Device extension structure


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


typedef struct tagDEVICE_EXTENSION {

	PDEVICE_OBJECT DeviceObject;			// device object this extension belongs to

	PDEVICE_OBJECT LowerDeviceObject;		// next lower driver in same stack

	PDEVICE_OBJECT Pdo;						// the PDO

	IO_REMOVE_LOCK RemoveLock;

	LIST_ENTRY ListHead;

	KSPIN_LOCK ListLock;

	KEVENT List_event;

	BOOLEAN flag;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;


#define IOCTL_READ_LIST \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X822,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_SET_FLAG \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X823,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_CLEAR_FLAG \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X824,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)


///////////////////////////////////////////////////////////////////////////////

// Global functions



VOID RemoveDevice(IN PDEVICE_OBJECT fdo);

NTSTATUS CompleteRequest(IN PIRP Irp, IN NTSTATUS status, IN ULONG_PTR info);

NTSTATUS DispatchForSCSI(IN PDEVICE_OBJECT fido, IN PIRP Irp);

#endif // DRIVER_H

