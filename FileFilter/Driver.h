#pragma once
// Declarations for filter driver

// Copyright (C) 1999 by Walter Oney

// All rights reserved



#ifndef DRIVER_H

#define DRIVER_H 



#define DRIVERNAME "USBFilter"					// for use in messages
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


typedef struct _PIPE_CONTEXT {

	USBD_PIPE_HANDLE InterruptPipe;

	USBD_PIPE_HANDLE BulkInPipe;

	USBD_PIPE_HANDLE BulkOutPipe;
} PipeContext;

typedef enum _PIPE_TYPE {
	Control,
	Bulk,
	Interrupt
} PIPE_TYPE;

typedef enum _DIRECTION {
	In,
	Out,
	Inout
} DIRECTION;

typedef struct _PIPE_INFO {
	UCHAR       EndpointAddress;
	PIPE_TYPE   PipeType;
	DIRECTION   Direction;
	UCHAR       Class;
	UCHAR       Subclass;
	UCHAR       Protocol;
	USHORT      MaximumPacketSize;
	USBD_PIPE_HANDLE	PipeHandle;
} PIPE_INFO, *PPIPE_INFO;

typedef struct tagDEVICE_EXTENSION {

	PDEVICE_OBJECT				DeviceObject;			// device object this extension belongs to

	PDEVICE_OBJECT				LowerDeviceObject;		// next lower driver in same stack

	PDEVICE_OBJECT				Pdo;						// the PDO

	IO_REMOVE_LOCK				RemoveLock;

	LIST_ENTRY					ListHead;

	KSPIN_LOCK					ListLock;

	KEVENT						List_event;

	BOOLEAN						flag;

	PUSBD_INTERFACE_INFORMATION Interface;

	PUSBD_INTERFACE_INFORMATION *InterfaceList;

	ULONG						interfaceNums;

	USBD_PIPE_HANDLE			PipeHandle;

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

#define IOCTL_FIND_FILTER \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X825,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_SEND_DATA \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X826,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_SELECT_PIPE \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X827,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)


///////////////////////////////////////////////////////////////////////////////

// Global functions



VOID RemoveDevice(IN PDEVICE_OBJECT fdo);

NTSTATUS CompleteRequest(IN PIRP Irp, IN NTSTATUS status, IN ULONG_PTR info);

NTSTATUS DispatchForSCSI(IN PDEVICE_OBJECT fido, IN PIRP Irp);

NTSTATUS IoCtlCompletion(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp, IN PVOID Context);

NTSTATUS
CallUSBD(
	IN PDEVICE_OBJECT DeviceObject,
	IN PURB           Urb
);

NTSTATUS
SelectInterfaces(
	IN PDEVICE_OBJECT                DeviceObject,
	IN PUSB_CONFIGURATION_DESCRIPTOR ConfigurationDescriptor,
	OUT PPIPE_INFO					 *pipe_info,
	OUT ULONG						 *pipeNums
);

NTSTATUS
GetConfiguration(
	IN PDEVICE_OBJECT                DeviceObject,
	OUT PPIPE_INFO					 *pipe_info,
	OUT ULONG						 *pipeNums
);

VOID RetrievePipeInfo(
	IN PDEVICE_OBJECT		fido,
	OUT PPIPE_INFO	    *pipe_info,
	OUT ULONG			*pipeNums
);
#endif // DRIVER_H

