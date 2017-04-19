#include <stdio.h>
#include <Windows.h>

typedef struct {
	ULONG TranferFlags;
	ULONG Len;
	PVOID Buf;
	PVOID MDLbuf;
}BULK_STRUCTURE;

typedef struct {
	LIST_ENTRY list_entry;
	BULK_STRUCTURE Bulk_in;
	BULK_STRUCTURE Bulk_out;
} LIST_NODE;

#define IOCTL_READ_LIST \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X822,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

int main()
{
	HANDLE device = NULL;
	HANDLE readHandle = NULL;

	//open device
	
}