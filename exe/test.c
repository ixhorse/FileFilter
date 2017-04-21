#include <windows.h>
#include <stdio.h>
#define _CRT_SECURE_NO_WARNINGS

#define IOCTL_READ_LIST \
	CTL_CODE(\
			FILE_DEVICE_UNKNOWN,\
			0X822,\
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

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

int main()
{
	LIST_NODE list_node;
	DWORD dRet;
	UCHAR * pBuf;
	int i;
	HANDLE hDevice =
		CreateFile("\\\\.\\LineDevice",
			GENERIC_READ | GENERIC_WRITE,
			0,		// share mode none
			NULL,	// no security
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);		// no template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Failed to obtain file handle to device "
			"with Win32 error code: %d\n",
			GetLastError());
		return 1;
	}

	while (1)
	{

		ReadFile(hDevice, &list_node, sizeof(LIST_NODE), &dRet, NULL);

		/*if (!DeviceIoControl(hDevice, IOCTL_READ_LIST, NULL, 0, buf, 1000, &dRet, 0))
		{
		printf("fail.\n");
		getchar();
		}*/

		if (dRet > 0)
		{
			printf("falgs: %#x\t%#x\n", list_node.Bulk_out.TranferFlags, list_node.Bulk_in.TranferFlags);
			printf("len: %d\t%d\n", list_node.Bulk_out.Len, list_node.Bulk_in.Len);
			printf("buf: ");
			pBuf = (UCHAR *)list_node.Bulk_out.Buf;
			for (i = 0; i < list_node.Bulk_in.Len; i++)
				printf("%02x ", pBuf[i]);
			printf("\t");
			pBuf = (UCHAR *)list_node.Bulk_in.Buf;
			for (i = 0; i < list_node.Bulk_in.Len; i++)
				printf("%02x ", pBuf[i]);
			printf("\n");
		}
		else
		{
			printf("empty.\n");
			Sleep(1 * 1000);
		}
	}

	CloseHandle(hDevice);

	return 0;
}
