#define BOOL					NTFS_BOOL
#define GUID					NTFS_GUID
#define SID_IDENTIFIER_AUTHORITY		NTFS_SID_IDENTIFIER_AUTHORITY
#define SID					NTFS_SID
#define ACE_HEADER				NTFS_ACE_HEADER
#define SECURITY_DESCRIPTOR			NTFS_SECURITY_DESCRIPTOR
#define SECURITY_DESCRIPTOR_CONTROL		NTFS_SECURITY_DESCRIPTOR_CONTROL
#define ACCESS_MASK				NTFS_ACCESS_MASK
#define GENERIC_MAPPING				NTFS_GENERIC_MAPPING
#define ACCESS_ALLOWED_ACE			NTFS_ACCESS_ALLOWED_ACE
#define ACCESS_DENIED_ACE			NTFS_ACCESS_DENIED_ACE
#define SYSTEM_AUDIT_ACE			NTFS_SYSTEM_AUDIT_ACE
#define SYSTEM_ALARM_ACE			NTFS_SYSTEM_ALARM_ACE
#define ACCESS_ALLOWED_OBJECT_ACE		NTFS_ACCESS_ALLOWED_OBJECT_ACE
#define ACCESS_DENIED_OBJECT_ACE		NTFS_ACCESS_DENIED_OBJECT_ACE
#define SYSTEM_AUDIT_OBJECT_ACE			NTFS_SYSTEM_AUDIT_OBJECT_ACE
#define SYSTEM_ALARM_OBJECT_ACE			NTFS_SYSTEM_ALARM_OBJECT_ACE
#define ACCESS_ALLOWED_ACE_TYPE			NTFS_ACCESS_ALLOWED_ACE_TYPE
#define ACCESS_DENIED_ACE_TYPE			NTFS_ACCESS_DENIED_ACE_TYPE
#define SYSTEM_AUDIT_ACE_TYPE			NTFS_SYSTEM_AUDIT_ACE_TYPE
#define SYSTEM_ALARM_ACE_TYPE			NTFS_SYSTEM_ALARM_ACE_TYPE
#define OBJECT_INHERIT_ACE			NTFS_OBJECT_INHERIT_ACE
#define FILE_READ_DATA				NTFS_FILE_READ_DATA
#define ACE_OBJECT_TYPE_PRESENT			NTFS_ACE_OBJECT_TYPE_PRESENT
#define ACL					NTFS_ACL

#define SECURITY_NULL_RID			NTFS_SECURITY_NULL_RID
#define SECURITY_WORLD_RID			NTFS_SECURITY_WORLD_RID
#define SECURITY_LOCAL_RID			NTFS_SECURITY_LOCAL_RID
#define SECURITY_CREATOR_OWNER_RID		NTFS_SECURITY_CREATOR_OWNER_RID
#define SECURITY_CREATOR_GROUP_RID		NTFS_SECURITY_CREATOR_GROUP_RID
#define SECURITY_CREATOR_OWNER_SERVER_RID	NTFS_SECURITY_CREATOR_OWNER_SERVER_RID
#define SECURITY_CREATOR_GROUP_SERVER_RID	NTFS_SECURITY_CREATOR_GROUP_SERVER_RID
#define SECURITY_DIALUP_RID			NTFS_SECURITY_DIALUP_RID
#define SECURITY_NETWORK_RID			NTFS_SECURITY_NETWORK_RID
#define SECURITY_BATCH_RID			NTFS_SECURITY_BATCH_RID
#define SECURITY_INTERACTIVE_RID		NTFS_SECURITY_INTERACTIVE_RID
#define SECURITY_SERVICE_RID			NTFS_SECURITY_SERVICE_RID
#define SECURITY_ANONYMOUS_LOGON_RID		NTFS_SECURITY_ANONYMOUS_LOGON_RID
#define SECURITY_PROXY_RID			NTFS_SECURITY_PROXY_RID
#define SECURITY_ENTERPRISE_CONTROLLERS_RID	NTFS_SECURITY_ENTERPRISE_CONTROLLERS_RID
#define SECURITY_SERVER_LOGON_RID		NTFS_SECURITY_SERVER_LOGON_RID
#define SECURITY_PRINCIPAL_SELF_RID		NTFS_SECURITY_PRINCIPAL_SELF_RID
#define SECURITY_AUTHENTICATED_USER_RID		NTFS_SECURITY_AUTHENTICATED_USER_RID
#define SECURITY_RESTRICTED_CODE_RID		NTFS_SECURITY_RESTRICTED_CODE_RID
#define SECURITY_TERMINAL_SERVER_RID		NTFS_SECURITY_TERMINAL_SERVER_RID
#define SECURITY_LOGON_IDS_RID			NTFS_SECURITY_LOGON_IDS_RID
#define SECURITY_LOGON_IDS_RID_COUNT		NTFS_SECURITY_LOGON_IDS_RID_COUNT
#define SECURITY_LOCAL_SYSTEM_RID		NTFS_SECURITY_LOCAL_SYSTEM_RID
#define SECURITY_NT_NON_UNIQUE			NTFS_SECURITY_NT_NON_UNIQUE
#define SECURITY_BUILTIN_DOMAIN_RID		NTFS_SECURITY_BUILTIN_DOMAIN_RID
#define DOMAIN_USER_RID_ADMIN			NTFS_DOMAIN_USER_RID_ADMIN
#define DOMAIN_USER_RID_GUEST			NTFS_DOMAIN_USER_RID_GUEST
#define DOMAIN_USER_RID_KRBTGT			NTFS_DOMAIN_USER_RID_KRBTGT
#define DOMAIN_GROUP_RID_ADMINS			NTFS_DOMAIN_GROUP_RID_ADMINS
#define DOMAIN_GROUP_RID_USERS			NTFS_DOMAIN_GROUP_RID_USERS
#define DOMAIN_GROUP_RID_GUESTS			NTFS_DOMAIN_GROUP_RID_GUESTS
#define DOMAIN_GROUP_RID_COMPUTERS		NTFS_DOMAIN_GROUP_RID_COMPUTERS
#define DOMAIN_GROUP_RID_CONTROLLERS		NTFS_DOMAIN_GROUP_RID_CONTROLLERS
#define DOMAIN_GROUP_RID_CERT_ADMINS		NTFS_DOMAIN_GROUP_RID_CERT_ADMINS
#define DOMAIN_GROUP_RID_SCHEMA_ADMINS		NTFS_DOMAIN_GROUP_RID_SCHEMA_ADMINS
#define DOMAIN_GROUP_RID_ENTERPRISE_ADMINS	NTFS_DOMAIN_GROUP_RID_ENTERPRISE_ADMINS
#define DOMAIN_GROUP_RID_POLICY_ADMINS		NTFS_DOMAIN_GROUP_RID_POLICY_ADMINS
#define DOMAIN_ALIAS_RID_ADMINS			NTFS_DOMAIN_ALIAS_RID_ADMINS
#define DOMAIN_ALIAS_RID_USERS			NTFS_DOMAIN_ALIAS_RID_USERS
#define DOMAIN_ALIAS_RID_GUESTS			NTFS_DOMAIN_ALIAS_RID_GUESTS
#define DOMAIN_ALIAS_RID_POWER_USERS		NTFS_DOMAIN_ALIAS_RID_POWER_USERS
#define DOMAIN_ALIAS_RID_ACCOUNT_OPS		NTFS_DOMAIN_ALIAS_RID_ACCOUNT_OPS
#define DOMAIN_ALIAS_RID_SYSTEM_OPS		NTFS_DOMAIN_ALIAS_RID_SYSTEM_OPS
#define DOMAIN_ALIAS_RID_PRINT_OPS		NTFS_DOMAIN_ALIAS_RID_PRINT_OPS
#define DOMAIN_ALIAS_RID_BACKUP_OPS		NTFS_DOMAIN_ALIAS_RID_BACKUP_OPS
#define DOMAIN_ALIAS_RID_REPLICATOR		NTFS_DOMAIN_ALIAS_RID_REPLICATOR
#define DOMAIN_ALIAS_RID_RAS_SERVERS		NTFS_DOMAIN_ALIAS_RID_RAS_SERVERS
#define DOMAIN_ALIAS_RID_PREW2KCOMPACCESS	NTFS_DOMAIN_ALIAS_RID_PREW2KCOMPACCESS
#define SID_REVISION				NTFS_SID_REVISION

#undef NO_NTFS_DEVICE_DEFAULT_IO_OPS
#define __CYGWIN32__
#include "libntfs-3g/include/device_io.h"

#include "libntfs-3g/include/device.h"
#include "libntfs-3g/include/inode.h"
#include "libntfs-3g/include/attrib.h"
#include "libntfs-3g/include/types.h"
#include "libntfs-3g/include/debug.h"
#include "libntfs-3g/include/dir.h"

#undef BOOL
#undef FILE_READ_DATA
#undef ACCESS_MASK
#undef GUID
#undef GENERIC_MAPPING
#undef ACE_HEADER
#undef ACCESS_ALLOWED_ACE
#undef ACCESS_DENIED_ACE
#undef SYSTEM_AUDIT_ACE
#undef SYSTEM_ALARM_ACE
#undef ACCESS_ALLOWED_OBJECT_ACE
#undef ACCESS_DENIED_OBJECT_ACE
#undef SYSTEM_AUDIT_OBJECT_ACE
#undef SYSTEM_ALARM_OBJECT_ACE
#undef ACL
#undef SID_IDENTIFIER_AUTHORITY
#undef SID
#undef SECURITY_DESCRIPTOR

#include <windows.h>
#include <winioctl.h>

BOOL WINAPI GetFileSizeEx(
  IN   HANDLE hFile,
  OUT  PLARGE_INTEGER lpFileSize
);

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#include "fout.h"
#include "local.h"

#ifndef NTFS_BLOCK_SIZE
#define NTFS_BLOCK_SIZE		512
#define NTFS_BLOCK_SIZE_BITS	9
#endif

#ifndef IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
#define IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 5636096
#endif

/* Windows 2k+ imports. */
typedef HANDLE (WINAPI *LPFN_FINDFIRSTVOLUME)(LPTSTR, DWORD);
typedef BOOL (WINAPI *LPFN_FINDNEXTVOLUME)(HANDLE, LPTSTR, DWORD);
typedef BOOL (WINAPI *LPFN_FINDVOLUMECLOSE)(HANDLE);
typedef BOOL (WINAPI *LPFN_SETFILEPOINTEREX)(HANDLE, LARGE_INTEGER,
		PLARGE_INTEGER, DWORD);

typedef DWORD (WINAPI *LPFN_GETLONGPATHNAME)(LPCTSTR,LPTSTR,DWORD);
typedef DWORD (WINAPI *LPFN_GETSHORTPATHNAME)(LPCTSTR,LPTSTR,DWORD);

static LPFN_FINDFIRSTVOLUME fnFindFirstVolume = NULL;
static LPFN_FINDNEXTVOLUME fnFindNextVolume = NULL;
static LPFN_FINDVOLUMECLOSE fnFindVolumeClose = NULL;
static LPFN_SETFILEPOINTEREX fnSetFilePointerEx = NULL;
static LPFN_GETLONGPATHNAME fnGetLongPathName = NULL;
static LPFN_GETSHORTPATHNAME fnGetShortPathName = NULL;

#ifdef UNICODE
#define FNPOSTFIX "W"
#else
#define FNPOSTFIX "A"
#endif

/**
 * struct win32_fd -
 */
typedef struct {
	HANDLE handle;
	s64 pos;		/* Logical current position on the volume. */
	s64 part_start;
	s64 part_length;
	int part_hidden_sectors;
	s64 geo_size, geo_cylinders;
	DWORD geo_sectors, geo_heads;
	HANDLE vol_handle;
} win32_fd;

/**
 * ntfs_w32error_to_errno - convert a win32 error code to the unix one
 * @w32error:	the win32 error code
 *
 * Limited to a relatively small but useful number of codes.
 */
static int ntfs_w32error_to_errno(unsigned int w32error)
{
	ntfs_log_trace("Converting w32error 0x%x.\n",w32error);
	switch (w32error) {
		case ERROR_INVALID_FUNCTION:
			return EBADRQC;
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
		case ERROR_INVALID_NAME:
			return ENOENT;
		case ERROR_TOO_MANY_OPEN_FILES:
			return EMFILE;
		case ERROR_ACCESS_DENIED:
			return EACCES;
		case ERROR_INVALID_HANDLE:
			return EBADF;
		case ERROR_NOT_ENOUGH_MEMORY:
			return ENOMEM;
		case ERROR_OUTOFMEMORY:
			return ENOSPC;
		case ERROR_INVALID_DRIVE:
		case ERROR_BAD_UNIT:
			return ENODEV;
		case ERROR_WRITE_PROTECT:
			return EROFS;
		case ERROR_NOT_READY:
		case ERROR_SHARING_VIOLATION:
			return EBUSY;
		case ERROR_BAD_COMMAND:
			return EINVAL;
		case ERROR_SEEK:
		case ERROR_NEGATIVE_SEEK:
			return ESPIPE;
		case ERROR_NOT_SUPPORTED:
			return EOPNOTSUPP;
		case ERROR_BAD_NETPATH:
			return ENOSHARE;
		default:
			/* generic message */
			return ENOMSG;
	}
}

/**
 * libntfs_SetFilePointerEx - emulation for SetFilePointerEx()
 *
 * We use this to emulate SetFilePointerEx() when it is not present.  This can
 * happen since SetFilePointerEx() only exists in Win2k+.
 */
static BOOL WINAPI libntfs_SetFilePointerEx(HANDLE hFile,
		LARGE_INTEGER liDistanceToMove,
		PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
{
	liDistanceToMove.LowPart = SetFilePointer(hFile,
			liDistanceToMove.LowPart, &liDistanceToMove.HighPart,
			dwMoveMethod);
	if (liDistanceToMove.LowPart == INVALID_SET_FILE_POINTER &&
			GetLastError() != NO_ERROR) {
		if (lpNewFilePointer)
			lpNewFilePointer->QuadPart = -1;
		return FALSE;
	}
	if (lpNewFilePointer)
		lpNewFilePointer->QuadPart = liDistanceToMove.QuadPart;
	return TRUE;
}

/**
 * ntfs_device_win32_init_imports - initialize the function pointers
 *
 * The Find*Volume and SetFilePointerEx functions exist only on win2k+, as such
 * we cannot just staticly import them.
 *
 * This function initializes the imports if the functions do exist and in the
 * SetFilePointerEx case, we emulate the function ourselves if it is not
 * present.
 *
 * Note: The values are cached, do be afraid to run it more than once.
 */
static void ntfs_device_win32_init_imports(void)
{
	HMODULE kernel32 = GetModuleHandle("kernel32");
	if (!kernel32) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("kernel32.dll could not be imported.\n");
	}
	if (!fnSetFilePointerEx) {
		if (kernel32)
			fnSetFilePointerEx = (LPFN_SETFILEPOINTEREX)
					GetProcAddress(kernel32,
					"SetFilePointerEx");
		/*
		 * If we did not get kernel32.dll or it is not Win2k+, emulate
		 * SetFilePointerEx().
		 */
		if (!fnSetFilePointerEx) {
			ntfs_log_debug("SetFilePonterEx() not found in "
					"kernel32.dll: Enabling emulation.\n");
			fnSetFilePointerEx = libntfs_SetFilePointerEx;
		}
	}
	if (!fnGetLongPathName) {
		if (kernel32) fnGetLongPathName = (LPFN_GETLONGPATHNAME)
			GetProcAddress(kernel32, "GetLongPathNameA");
	}
	if (!fnGetShortPathName) {
		if (kernel32) fnGetShortPathName = (LPFN_GETLONGPATHNAME)
			GetProcAddress(kernel32, "GetShortPathNameA");
	}
	/* Cannot do lookups if we could not get kernel32.dll... */
	if (!kernel32)
		return;
	if (!fnFindFirstVolume)
		fnFindFirstVolume = (LPFN_FINDFIRSTVOLUME)
				GetProcAddress(kernel32, "FindFirstVolume"
				FNPOSTFIX);
	if (!fnFindNextVolume)
		fnFindNextVolume = (LPFN_FINDNEXTVOLUME)
				GetProcAddress(kernel32, "FindNextVolume"
				FNPOSTFIX);
	if (!fnFindVolumeClose)
		fnFindVolumeClose = (LPFN_FINDVOLUMECLOSE)
				GetProcAddress(kernel32, "FindVolumeClose");
}

/**
 * ntfs_device_unix_status_flags_to_win32 - convert unix->win32 open flags
 * @flags:	unix open status flags
 *
 * Supported flags are O_RDONLY, O_WRONLY and O_RDWR.
 */
static __inline__ int ntfs_device_unix_status_flags_to_win32(int flags)
{
	return FILE_READ_DATA;
}


/**
 * ntfs_device_win32_simple_open_file - just open a file via win32 API
 * @filename:	name of the file to open
 * @handle:	pointer the a HANDLE in which to put the result
 * @flags:	unix open status flags
 * @locking:	will the function gain an exclusive lock on the file?
 *
 * Supported flags are O_RDONLY, O_WRONLY and O_RDWR.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.  In this case handle is trashed.
 */
static int ntfs_device_win32_simple_open_file(const char *filename,
		HANDLE *handle, int flags, BOOL locking)
{
	*handle = CreateFile(filename,
			ntfs_device_unix_status_flags_to_win32(flags),
			(FILE_SHARE_WRITE | FILE_SHARE_READ),
			NULL, OPEN_EXISTING, 0, NULL);
	if (*handle == INVALID_HANDLE_VALUE) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("CreateFile(%s) failed.\n", filename);
		return -1;
	}
	return 0;
}

/**
 * ntfs_device_win32_unlock - unlock the volume
 * @handle:	the win32 HANDLE which the volume was locked with
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.
 */
static int ntfs_device_win32_unlock(HANDLE handle)
{
	DWORD i;

	if (!DeviceIoControl(handle, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &i,
			NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("Couldn't unlock volume.\n");
		return -1;
	}
	ntfs_log_debug("Volume unlocked.\n");
	return 0;
}

/**
 * ntfs_device_win32_dismount - dismount a volume
 * @handle:	a win32 HANDLE for a volume to dismount
 *
 * Dismounting means the system will refresh the volume in the first change it
 * gets.  Usefull after altering the file structures.
 * The volume must be locked by the current process while dismounting.
 * A side effect is that the volume is also unlocked, but you must not rely om
 * this.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.
 */
static int ntfs_device_win32_dismount(HANDLE handle)
{
	DWORD i;

	if (!DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0,
			&i, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("Couldn't dismount volume.\n");
		return -1;
	}
	ntfs_log_debug("Volume dismounted.\n");
	return 0;
}

/**
 * ntfs_device_win32_getsize - get file size via win32 API
 * @handle:	pointer the file HANDLE obtained via open
 *
 * Only works on ordinary files.
 *
 * Return The file size if o.k.
 *	 -1 if not, and errno set.
 */
static s64 ntfs_device_win32_getsize(HANDLE handle)
{
	DWORD loword, hiword;

	loword = GetFileSize(handle, &hiword);
	if (loword == INVALID_FILE_SIZE) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("Couldn't get file size.\n");
		return -1;
	}
	return ((s64)hiword << 32) + loword;
}

/**
 * ntfs_device_win32_getdisklength - get disk size via win32 API
 * @handle:	pointer the file HANDLE obtained via open
 * @argp:	pointer to result buffer
 *
 * Only works on PhysicalDriveX type handles.
 *
 * Return The disk size if o.k.
 *	 -1 if not, and errno set.
 */
static s64 ntfs_device_win32_getdisklength(HANDLE handle)
{
	GET_LENGTH_INFORMATION buf;
	DWORD i;

	if (!DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &buf,
			sizeof(buf), &i, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("Couldn't get disk length.\n");
		return -1;
	}
	ntfs_log_debug("Disk length: %lld.\n", buf.Length.QuadPart);
	return buf.Length.QuadPart;
}

/**
 * ntfs_device_win32_getntfssize - get NTFS volume size via win32 API
 * @handle:	pointer the file HANDLE obtained via open
 * @argp:	pointer to result buffer
 *
 * Only works on NTFS volume handles.
 * An annoying bug in windows is that an NTFS volume does not occupy the entire
 * partition, namely not the last sector (which holds the backup boot sector,
 * and normally not interesting).
 * Use this function to get the length of the accessible space through a given
 * volume handle.
 *
 * Return The volume size if o.k.
 *	 -1 if not, and errno set.
 */
static s64 ntfs_device_win32_getntfssize(HANDLE handle)
{
	s64 rvl;
#ifdef FSCTL_GET_NTFS_VOLUME_DATA
	DWORD i;
	NTFS_VOLUME_DATA_BUFFER buf;

	if (!DeviceIoControl(handle, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &buf,
			sizeof(buf), &i, NULL)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("Couldn't get NTFS volume length.\n");
		return -1;
	}
	rvl = buf.NumberSectors.QuadPart * buf.BytesPerSector;
	ntfs_log_debug("NTFS volume length: 0x%llx.\n", (long long)rvl);
#else
	errno = EINVAL;
	rvl = -1;
#endif
	return rvl;
}

/**
 * ntfs_device_win32_getgeo - get CHS information of a drive
 * @handle:	an open handle to the PhysicalDevice
 * @fd:		a win_fd structure that will be filled
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno  set.
 *
 * In Windows NT+: fills size, sectors, and cylinders and sets heads to -1.
 * In Windows XP+: fills size, sectors, cylinders, and heads.
 *
 * Note: In pre XP, this requires write permission, even though nothing is
 * actually written.
 *
 * If fails, sets sectors, cylinders, heads, and size to -1.
 */
static int ntfs_device_win32_getgeo(HANDLE handle, win32_fd *fd)
{
	DWORD i;
	BOOL rvl;
	BYTE b[sizeof(DISK_GEOMETRY) + sizeof(DISK_PARTITION_INFO) +
			sizeof(DISK_DETECTION_INFO) + 512];

	rvl = DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL,
			0, &b, sizeof(b), &i, NULL);
	if (rvl) {
		ntfs_log_debug("GET_DRIVE_GEOMETRY_EX detected.\n");
		DISK_DETECTION_INFO *ddi = (PDISK_DETECTION_INFO)
				(((PBYTE)(&((PDISK_GEOMETRY_EX)b)->Data)) +
				(((PDISK_PARTITION_INFO)
				(&((PDISK_GEOMETRY_EX)b)->Data))->
				SizeOfPartitionInfo));
		fd->geo_cylinders = ((DISK_GEOMETRY*)&b)->Cylinders.QuadPart;
		fd->geo_sectors = ((DISK_GEOMETRY*)&b)->SectorsPerTrack;
		fd->geo_size = ((DISK_GEOMETRY_EX*)&b)->DiskSize.QuadPart;
		switch (ddi->DetectionType) {
		case DetectInt13:
			fd->geo_cylinders = ddi->Int13.MaxCylinders;
			fd->geo_sectors = ddi->Int13.SectorsPerTrack;
			fd->geo_heads = ddi->Int13.MaxHeads;
			return 0;
		case DetectExInt13:
			fd->geo_cylinders = ddi->ExInt13.ExCylinders;
			fd->geo_sectors = ddi->ExInt13.ExSectorsPerTrack;
			fd->geo_heads = ddi->ExInt13.ExHeads;
			return 0;
		case DetectNone:
		default:
			break;
		}
	} else
		fd->geo_heads = -1;
	rvl = DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
			&b, sizeof(b), &i, NULL);
	if (rvl) {
		ntfs_log_debug("GET_DRIVE_GEOMETRY detected.\n");
		fd->geo_cylinders = ((DISK_GEOMETRY*)&b)->Cylinders.QuadPart;
		fd->geo_sectors = ((DISK_GEOMETRY*)&b)->SectorsPerTrack;
		fd->geo_size = fd->geo_cylinders * fd->geo_sectors *
				((DISK_GEOMETRY*)&b)->TracksPerCylinder *
				((DISK_GEOMETRY*)&b)->BytesPerSector;
		return 0;
	}
	errno = ntfs_w32error_to_errno(GetLastError());
	ntfs_log_trace("Couldn't retrieve disk geometry.\n");
	fd->geo_cylinders = -1;
	fd->geo_sectors = -1;
	fd->geo_size = -1;
	return -1;
}

/**
 * ntfs_device_win32_open_file - open a file via win32 API
 * @filename:	name of the file to open
 * @fd:		pointer to win32 file device in which to put the result
 * @flags:	unix open status flags
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.
 */
static __inline__ int ntfs_device_win32_open_file(char *filename, win32_fd *fd,
		int flags)
{
	HANDLE handle;

	if (ntfs_device_win32_simple_open_file(filename, &handle, flags,
			FALSE)) {
		/* open error */
		return -1;
	}
	/* fill fd */
	fd->handle = handle;
	fd->part_start = 0;
	fd->part_length = ntfs_device_win32_getsize(handle);
	fd->pos = 0;
	fd->part_hidden_sectors = -1;
	fd->geo_size = -1;	/* used as a marker that this is a file */
	fd->vol_handle = INVALID_HANDLE_VALUE;
	return 0;
}

/**
 * ntfs_device_win32_open_drive - open a drive via win32 API
 * @drive_id:	drive to open
 * @fd:		pointer to win32 file device in which to put the result
 * @flags:	unix open status flags
 *
 * return 0 if o.k.
 *        -1 if not, and errno set.
 */
static __inline__ int ntfs_device_win32_open_drive(int drive_id, win32_fd *fd,
		int flags)
{
	HANDLE handle;
	int err;
	char filename[MAX_PATH];

	sprintf(filename, "\\\\.\\PhysicalDrive%d", drive_id);
	if ((err = ntfs_device_win32_simple_open_file(filename, &handle, flags,
			TRUE))) {
		/* open error */
		return err;
	}
	/* store the drive geometry */
	ntfs_device_win32_getgeo(handle, fd);
	/* Just to be sure */
	if (fd->geo_size == -1)
		fd->geo_size = ntfs_device_win32_getdisklength(handle);
	/* fill fd */
	fd->handle = handle;
	fd->part_start = 0;
	fd->part_length = fd->geo_size;
	fd->pos = 0;
	fd->part_hidden_sectors = -1;
	fd->vol_handle = INVALID_HANDLE_VALUE;
	return 0;
}

/**
 * ntfs_device_win32_open_volume_for_partition - find and open a volume
 *
 * Windows NT/2k/XP handles volumes instead of partitions.
 * This function gets the partition details and return an open volume handle.
 * That volume is the one whose only physical location on disk is the described
 * partition.
 *
 * The function required Windows 2k/XP, otherwise it fails (gracefully).
 *
 * Return success: a valid open volume handle.
 *        fail   : INVALID_HANDLE_VALUE
 */
static HANDLE ntfs_device_win32_open_volume_for_partition(unsigned int drive_id,
		s64 part_offset, s64 part_length, int flags)
{
	HANDLE vol_find_handle;
	TCHAR vol_name[MAX_PATH];

	/* Make sure all the required imports exist. */
	if (!fnFindFirstVolume || !fnFindNextVolume || !fnFindVolumeClose) {
		ntfs_log_trace("Required dll imports not found.\n");
		return INVALID_HANDLE_VALUE;
	}
	/* Start iterating through volumes. */
	ntfs_log_trace("Entering with drive_id=%d, part_offset=%lld, "
			"path_length=%lld, flags=%d.\n", drive_id,
			(unsigned long long)part_offset,
			(unsigned long long)part_length, flags);
	vol_find_handle = fnFindFirstVolume(vol_name, MAX_PATH);
	/* If a valid handle could not be aquired, reply with "don't know". */
	if (vol_find_handle == INVALID_HANDLE_VALUE) {
		ntfs_log_trace("FindFirstVolume failed.\n");
		return INVALID_HANDLE_VALUE;
	}
	do {
		int vol_name_length;
		HANDLE handle;

		/* remove trailing '/' from vol_name */
#ifdef UNICODE
		vol_name_length = wcslen(vol_name);
#else
		vol_name_length = strlen(vol_name);
#endif
		if (vol_name_length>0)
			vol_name[vol_name_length-1]=0;

		ntfs_log_debug("Processing %s.\n", vol_name);
		/* open the file */
		handle = CreateFile(vol_name,
				ntfs_device_unix_status_flags_to_win32(flags),
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
				OPEN_EXISTING, 0, NULL);
		if (handle != INVALID_HANDLE_VALUE) {
			DWORD bytesReturned;
#define EXTENTS_SIZE sizeof(VOLUME_DISK_EXTENTS) + 9 * sizeof(DISK_EXTENT)
			char extents[EXTENTS_SIZE];

			/* Check physical locations. */
			if (DeviceIoControl(handle,
					IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
					NULL, 0, extents, EXTENTS_SIZE,
					&bytesReturned, NULL)) {
				if (((VOLUME_DISK_EXTENTS *)extents)->
						NumberOfDiskExtents == 1) {
					DISK_EXTENT *extent = &((
							VOLUME_DISK_EXTENTS *)
							extents)->Extents[0];
					if ((extent->DiskNumber==drive_id) &&
							(extent->StartingOffset.
							QuadPart==part_offset)
							&& (extent->
							ExtentLength.QuadPart
							== part_length)) {
						/*
						 * Eureka! (Archimedes, 287 BC,
						 * "I have found it!")
						 */
						fnFindVolumeClose(
							vol_find_handle);
						return handle;
					}
				}
			}
		} else
			ntfs_log_trace("getExtents() Failed.\n");
	} while (fnFindNextVolume(vol_find_handle, vol_name, MAX_PATH));
	/* End of iteration through volumes. */
	ntfs_log_trace("Closing, volume was not found.\n");
	fnFindVolumeClose(vol_find_handle);
	return INVALID_HANDLE_VALUE;
}

/**
 * ntfs_device_win32_find_partition - locates partition details by id.
 * @handle:		HANDLE to the PhysicalDrive
 * @partition_id:	the partition number to locate
 * @part_offset:	pointer to where to put the offset to the partition
 * @part_length:	pointer to where to put the length of the partition
 * @hidden_sectors:	pointer to where to put the hidden sectors
 *
 * This function requires an open PhysicalDrive handle and a partition_id.
 * If a partition with the required id is found on the supplied device,
 * the partition attributes are returned back.
 *
 * Returns: TRUE  if found, and sets the output parameters.
 *          FALSE if not and errno is set to the error code.
 */
static BOOL ntfs_device_win32_find_partition(HANDLE handle, DWORD partition_id,
		s64 *part_offset, s64 *part_length, int *hidden_sectors)
{
	DRIVE_LAYOUT_INFORMATION *drive_layout;
	unsigned int err, buf_size, part_count;
	DWORD i;

	/*
	 * There is no way to know the required buffer, so if the ioctl fails,
	 * try doubling the buffer size each time until the ioctl succeeds.
	 */
	part_count = 8;
	do {
		buf_size = sizeof(DRIVE_LAYOUT_INFORMATION) +
				part_count * sizeof(PARTITION_INFORMATION);
		drive_layout = malloc(buf_size);
		if (!drive_layout) {
			errno = ENOMEM;
			return FALSE;
		}
		if (DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT, NULL,
				0, (BYTE*)drive_layout, buf_size, &i, NULL))
			break;
		err = GetLastError();
		free(drive_layout);
		if (err != ERROR_INSUFFICIENT_BUFFER) {
			ntfs_log_trace("GetDriveLayout failed.\n");
			errno = ntfs_w32error_to_errno(err);
			return FALSE;
		}
		ntfs_log_debug("More than %u partitions.\n", part_count);
		part_count <<= 1;
		if (part_count > 512) {
			ntfs_log_trace("GetDriveLayout failed: More than 512 "
					"partitions?\n");
			errno = ENOBUFS;
			return FALSE;
		}
	} while (1);
	for (i = 0; i < drive_layout->PartitionCount; i++) {
		if (drive_layout->PartitionEntry[i].PartitionNumber ==
				partition_id) {
			*part_offset = drive_layout->PartitionEntry[i].
					StartingOffset.QuadPart;
			*part_length = drive_layout->PartitionEntry[i].
					PartitionLength.QuadPart;
			*hidden_sectors = drive_layout->PartitionEntry[i].
					HiddenSectors;
			free(drive_layout);
			return TRUE;
		}
	}
	free(drive_layout);
	errno = ENOENT;
	return FALSE;
}

/**
 * ntfs_device_win32_open_partition - open a partition via win32 API
 * @drive_id:		drive to open
 * @partition_id:	partition to open
 * @fd:			win32 file device to return
 * @flags:		unix open status flags
 *
 * Return  0 if o.k.
 *        -1 if not, and errno set.
 *
 * When fails, fd contents may have not been preserved.
 */
static int ntfs_device_win32_open_partition(int drive_id,
		unsigned int partition_id, win32_fd *fd, int flags)
{
	s64 part_start, part_length;
	HANDLE handle;
	int err, hidden_sectors;
	char drive_name[MAX_PATH];

	sprintf(drive_name, "\\\\.\\PhysicalDrive%d", drive_id);
	/* Open the entire device without locking, ask questions later */
	if ((err = ntfs_device_win32_simple_open_file(drive_name, &handle,
			flags, FALSE))) {
		/* error */
		return err;
	}
	if (ntfs_device_win32_find_partition(handle, partition_id, &part_start,
			&part_length, &hidden_sectors)) {
		s64 tmp;
		HANDLE vol_handle = ntfs_device_win32_open_volume_for_partition(
			drive_id, part_start, part_length, flags);
		/* Store the drive geometry. */
		ntfs_device_win32_getgeo(handle, fd);
		fd->handle = handle;
		fd->pos = 0;
		fd->part_start = part_start;
		fd->part_length = part_length;
		fd->part_hidden_sectors = hidden_sectors;
		tmp = ntfs_device_win32_getntfssize(vol_handle);
		if (tmp > 0)
			fd->geo_size = tmp;
		else
			fd->geo_size = fd->part_length;
		if (vol_handle != INVALID_HANDLE_VALUE) {
			fd->vol_handle = vol_handle;
		} else {
			fd->vol_handle = INVALID_HANDLE_VALUE;
		}
		return 0;
	} else {
		ntfs_log_debug("Partition %u not found on drive %d.\n",
				partition_id, drive_id);
		CloseHandle(handle);
		errno = ENODEV;
		return -1;
	}
}

/**
 * ntfs_device_win32_open - open a device
 * @dev:	a pointer to the NTFS_DEVICE to open
 * @flags:	unix open status flags
 *
 * @dev->d_name must hold the device name, the rest is ignored.
 * Supported flags are O_RDONLY, O_WRONLY and O_RDWR.
 *
 * If name is in format "(hd[0-9],[0-9])" then open a partition.
 * If name is in format "(hd[0-9])" then open a volume.
 * Otherwise open a file.
 */
static int ntfs_device_win32_open(struct ntfs_device *dev, int flags)
{
	unsigned int drive_id = 0;
	int numparams;
	unsigned int part = 0;
	win32_fd fd;
	int err;

	if (NDevOpen(dev)) {
		errno = EBUSY;
		return -1;
	}
	ntfs_device_win32_init_imports();
	numparams = sscanf(dev->d_name, "(hd%u,%u)", &drive_id, &part);
	switch (numparams) {
	case 0:
		ntfs_log_debug("win32_open(%s) -> file.\n", dev->d_name);
		err = ntfs_device_win32_open_file(dev->d_name, &fd, flags);
		break;
	case 1:
		ntfs_log_debug("win32_open(%s) -> drive %d.\n", dev->d_name,
				drive_id);
		err = ntfs_device_win32_open_drive(drive_id, &fd, flags);
		break;
	case 2:
		ntfs_log_debug("win32_open(%s) -> drive %d, part %u.\n",
				dev->d_name, drive_id, part);
		err = ntfs_device_win32_open_partition(drive_id, part, &fd,
				flags);
		break;
	default:
		ntfs_log_debug("win32_open(%s) -> unknwon file format.\n",
				dev->d_name);
		err = -1;
	}
	if (err)
		return err;
	ntfs_log_debug("win32_open(%s) -> %p, offset 0x%llx.\n", dev->d_name,
			dev, fd.part_start);
	/* Setup our read-only flag. */
	NDevSetReadOnly(dev);
	dev->d_private = malloc(sizeof(win32_fd));
	memcpy(dev->d_private, &fd, sizeof(win32_fd));
	NDevSetOpen(dev);
	NDevClearDirty(dev);
	return 0;
}

/**
 * ntfs_device_win32_seek - change current logical file position
 * @dev:	ntfs device obtained via ->open
 * @offset:	required offset from the whence anchor
 * @whence:	whence anchor specifying what @offset is relative to
 *
 * Return the new position on the volume on success and -1 on error with errno
 * set to the error code.
 *
 * @whence may be one of the following:
 *	SEEK_SET - Offset is relative to file start.
 *	SEEK_CUR - Offset is relative to current position.
 *	SEEK_END - Offset is relative to end of file.
 */
static s64 ntfs_device_win32_seek(struct ntfs_device *dev, s64 offset,
		int whence)
{
	s64 abs_ofs;
	win32_fd *fd = (win32_fd *)dev->d_private;

	ntfs_log_trace("seek offset = 0x%llx, whence = %d.\n", offset, whence);
	switch (whence) {
	case SEEK_SET:
		abs_ofs = offset;
		break;
	case SEEK_CUR:
		abs_ofs = fd->pos + offset;
		break;
	case SEEK_END:
		/* End of partition != end of disk. */
		if (fd->part_length == -1) {
			ntfs_log_trace("Position relative to end of disk not "
					"implemented.\n");
			errno = EOPNOTSUPP;
			return -1;
		}
		abs_ofs = fd->part_length + offset;
		break;
	default:
		ntfs_log_trace("Wrong mode %d.\n", whence);
		errno = EINVAL;
		return -1;
	}
	if (abs_ofs < 0 || abs_ofs > fd->part_length) {
		ntfs_log_trace("Seeking outsize seekable area.\n");
		errno = EINVAL;
		return -1;
	}
	fd->pos = abs_ofs;
	return abs_ofs;
}

/**
 * ntfs_device_win32_pio - positioned low level i/o
 * @fd:		win32 device descriptor obtained via ->open
 * @pos:	at which position to do i/o from/to
 * @count:	how many bytes should be transfered
 * @b:		source/destination buffer
 * @write:	TRUE if write transfer and FALSE if read transfer
 *
 * On success returns the number of bytes transfered (can be < @count) and on
 * error returns -1 and errno set.  Transfer starts from position @pos on @fd.
 *
 * Notes:
 *	- @pos, @buf, and @count must be aligned to NTFS_BLOCK_SIZE.
 *	- When dealing with volumes, a single call must not span both volume
 *	  and disk extents.
 *	- Does not use/set @fd->pos.
 */
static s64 ntfs_device_win32_pio(win32_fd *fd, const s64 pos,
		const s64 count, void *b, const BOOL write)
{
	LARGE_INTEGER li, lo;
	HANDLE handle;
	DWORD bt;
	BOOL res;

	li.QuadPart = pos;
	if (fd->vol_handle != INVALID_HANDLE_VALUE && pos < fd->geo_size) {
		ntfs_log_debug("Transfering via vol_handle.\n");
		handle = fd->vol_handle;
	} else {
		ntfs_log_debug("Transfering via handle.\n");
		handle = fd->handle;
		li.QuadPart += fd->part_start;
	}
	if (!fnSetFilePointerEx(handle, li, &lo, FILE_BEGIN)) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("SetFilePointer failed.\n");
		return -1;
	}
	if (write) {
		abort();
	} else {
		res = ReadFile(handle, b, count, &bt, NULL);
	}
	if (!res) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("%sFile() failed.\n", write ? "Write" : "Read");
		return -1;
	}

	return bt;
}


/**
 * ntfs_device_win32_pread_simple - positioned simple read
 * @fd:		win32 device descriptor obtained via ->open
 * @pos:	at which position to read from
 * @count:	how many bytes should be read
 * @b:		a pointer to where to put the contents
 *
 * On success returns the number of bytes read (can be < @count) and on error
 * returns -1 and errno set.  Read starts from position @pos.
 *
 * Notes:
 *	- @pos, @buf, and @count must be aligned to NTFS_BLOCK_SIZE.
 *	- When dealing with volumes, a single call must not span both volume
 *	  and disk extents.
 *	- Does not use/set @fd->pos.
 */
static inline s64 ntfs_device_win32_pread_simple(win32_fd *fd, const s64 pos,
		const s64 count, void *b)
{
	return ntfs_device_win32_pio(fd, pos, count, b, FALSE);
}

/**
 * ntfs_device_win32_read - read bytes from an ntfs device
 * @dev:	ntfs device obtained via ->open
 * @b:		pointer to where to put the contents
 * @count:	how many bytes should be read
 *
 * On success returns the number of bytes actually read (can be < @count).
 * On error returns -1 with errno set.
 */
static s64 ntfs_device_win32_read(struct ntfs_device *dev, void *b, s64 count)
{
	s64 old_pos, to_read, i, br = 0;
	win32_fd *fd = (win32_fd *)dev->d_private;
	BYTE *alignedbuffer;
	int old_ofs, ofs;

	old_pos = fd->pos;
	old_ofs = ofs = old_pos & (NTFS_BLOCK_SIZE - 1);
	to_read = (ofs + count + NTFS_BLOCK_SIZE - 1) &
			~(s64)(NTFS_BLOCK_SIZE - 1);
	/* Impose maximum of 2GB to be on the safe side. */
	if (to_read > 0x80000000) {
		int delta = to_read - count;
		to_read = 0x80000000;
		count = to_read - delta;
	}
	ntfs_log_trace("fd = %p, b = %p, count = 0x%llx, pos = 0x%llx, "
			"ofs = %i, to_read = 0x%llx.\n", fd, b,
			(long long)count, (long long)old_pos, ofs,
			(long long)to_read);
	if (!((unsigned long)b & (NTFS_BLOCK_SIZE - 1)) && !old_ofs &&
			!(count & (NTFS_BLOCK_SIZE - 1)))
		alignedbuffer = b;
	else {
		alignedbuffer = (BYTE *)VirtualAlloc(NULL, to_read, MEM_COMMIT,
				PAGE_READWRITE);
		if (!alignedbuffer) {
			errno = ntfs_w32error_to_errno(GetLastError());
			ntfs_log_trace("VirtualAlloc failed for read.\n");
			return -1;
		}
	}
	if (fd->vol_handle != INVALID_HANDLE_VALUE && old_pos < fd->geo_size) {
		s64 vol_to_read = fd->geo_size - old_pos;
		if (count > vol_to_read) {
			br = ntfs_device_win32_pread_simple(fd,
					old_pos & ~(s64)(NTFS_BLOCK_SIZE - 1),
					ofs + vol_to_read, alignedbuffer);
			if (br == -1)
				goto read_error;
			to_read -= br;
			if (br < ofs) {
				br = 0;
				goto read_partial;
			}
			br -= ofs;
			fd->pos += br;
			ofs = fd->pos & (NTFS_BLOCK_SIZE - 1);
			if (br != vol_to_read)
				goto read_partial;
		}
	}
	i = ntfs_device_win32_pread_simple(fd,
			fd->pos & ~(s64)(NTFS_BLOCK_SIZE - 1), to_read,
			alignedbuffer + br);
	if (i == -1) {
		if (br)
			goto read_partial;
		goto read_error;
	}
	if (i < ofs)
		goto read_partial;
	i -= ofs;
	br += i;
	if (br > count)
		br = count;
	fd->pos = old_pos + br;
read_partial:
	if (alignedbuffer != b) {
		memcpy((void*)b, alignedbuffer + old_ofs, br);
		VirtualFree(alignedbuffer, 0, MEM_RELEASE);
	}
	return br;
read_error:
	if (alignedbuffer != b)
		VirtualFree(alignedbuffer, 0, MEM_RELEASE);
	return -1;
}

/**
 * ntfs_device_win32_close - close an open ntfs deivce
 * @dev:	ntfs device obtained via ->open
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.  Note if error fd->vol_handle is trashed.
 */
static int ntfs_device_win32_close(struct ntfs_device *dev)
{
	win32_fd *fd = (win32_fd *)dev->d_private;
	BOOL rvl;

	ntfs_log_trace("Closing device %p.\n", dev);
	if (!NDevOpen(dev)) {
		errno = EBADF;
		return -1;
	}
	if (fd->vol_handle != INVALID_HANDLE_VALUE) {
		if (!NDevReadOnly(dev)) {
			ntfs_device_win32_dismount(fd->vol_handle);
			ntfs_device_win32_unlock(fd->vol_handle);
		}
		if (!CloseHandle(fd->vol_handle))
			ntfs_log_trace("CloseHandle() failed for volume.\n");
	}
	rvl = CloseHandle(fd->handle);
	free(fd);
	if (!rvl) {
		errno = ntfs_w32error_to_errno(GetLastError());
		ntfs_log_trace("CloseHandle() failed.\n");
		return -1;
	}
	return 0;
}

/**
 * ntfs_device_win32_sync - flush write buffers to disk
 * @dev:	ntfs device obtained via ->open
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.
 *
 * Note: Volume syncing works differently in windows.
 *	 Disk cannot be synced in windows.
 */
static int ntfs_device_win32_sync(struct ntfs_device *dev)
{
	int err = 0;
	BOOL to_clear = TRUE;

	if (!NDevReadOnly(dev) && NDevDirty(dev)) {
		win32_fd *fd = (win32_fd *)dev->d_private;

		if ((fd->vol_handle != INVALID_HANDLE_VALUE) &&
				!FlushFileBuffers(fd->vol_handle)) {
			to_clear = FALSE;
			err = ntfs_w32error_to_errno(GetLastError());
		}
		if (!FlushFileBuffers(fd->handle)) {
			to_clear = FALSE;
			if (!err)
				err = ntfs_w32error_to_errno(GetLastError());
		}
		if (!to_clear) {
			ntfs_log_trace("Could not sync.\n");
			errno = err;
			return -1;
		}
		NDevClearDirty(dev);
	}
	return 0;
}

/**
 * ntfs_device_win32_pwrite_simple - positioned simple write
 * @fd:		win32 device descriptor obtained via ->open
 * @pos:	at which position to write to
 * @count:	how many bytes should be written
 * @b:		a pointer to the data to write
 *
 * On success returns the number of bytes written and on error returns -1 and
 * errno set.  Write starts from position @pos.
 *
 * Notes:
 *	- @pos, @buf, and @count must be aligned to NTFS_BLOCK_SIZE.
 *	- When dealing with volumes, a single call must not span both volume
 *	  and disk extents.
 *	- Does not use/set @fd->pos.
 */
static inline s64 ntfs_device_win32_pwrite_simple(win32_fd *fd, const s64 pos,
		const s64 count, const void *b)
{
	errno = EACCES;
	return -1;
}

/**
 * ntfs_device_win32_write - write bytes to an ntfs device
 * @dev:	ntfs device obtained via ->open
 * @b:		pointer to the data to write
 * @count:	how many bytes should be written
 *
 * On success returns the number of bytes actually written.
 * On error returns -1 with errno set.
 */
static s64 ntfs_device_win32_write(struct ntfs_device *dev, const void *b,
		s64 count)
{
	errno = EACCES;
	return -1;
}

/**
 * ntfs_device_win32_stat - get a unix-like stat structure for an ntfs device
 * @dev:	ntfs device obtained via ->open
 * @buf:	pointer to the stat structure to fill
 *
 * Note: Only st_mode, st_size, and st_blocks are filled.
 *
 * Return 0 if o.k.
 *	 -1 if not and errno set. in this case handle is trashed.
 */
static int ntfs_device_win32_stat(struct ntfs_device *dev, struct stat *buf)
{
	win32_fd *fd = (win32_fd *)dev->d_private;
	mode_t st_mode;

	st_mode = 0;
	memset(buf, 0, sizeof(struct stat));
	buf->st_mode = st_mode;
	buf->st_size = fd->part_length;
	return 0;
}

/**
 * ntfs_win32_hdio_getgeo - get drive geometry
 * @dev:	ntfs device obtained via ->open
 * @argp:	pointer to where to put the output
 *
 * Note: Works on windows NT/2k/XP only.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.  Note if error fd->handle is trashed.
 */
static __inline__ int ntfs_win32_hdio_getgeo(struct ntfs_device *dev,
		struct hd_geometry *argp)
{
	win32_fd *fd = (win32_fd *)dev->d_private;

	argp->heads = fd->geo_heads;
	argp->sectors = fd->geo_sectors;
	argp->cylinders = fd->geo_cylinders;
	argp->start = fd->part_hidden_sectors;
	return 0;
}

/**
 * ntfs_win32_blksszget - get block device sector size
 * @dev:	ntfs device obtained via ->open
 * @argp:	pointer to where to put the output
 *
 * Note: Works on windows NT/2k/XP only.
 *
 * Return 0 if o.k.
 *	 -1 if not, and errno set.  Note if error fd->handle is trashed.
 */
static __inline__ int ntfs_win32_blksszget(struct ntfs_device *dev,int *argp)
{
	win32_fd *fd = (win32_fd *)dev->d_private;
	DWORD bytesReturned;
	DISK_GEOMETRY dg;

	if (DeviceIoControl(fd->handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
			&dg, sizeof(DISK_GEOMETRY), &bytesReturned, NULL)) {
		/* success */
		*argp = dg.BytesPerSector;
		return 0;
	}
	errno = ntfs_w32error_to_errno(GetLastError());
	ntfs_log_trace("GET_DRIVE_GEOMETRY failed.\n");
	return -1;
}

static int ntfs_device_win32_ioctl(struct ntfs_device *dev, int request,
		void *argp)
{
	win32_fd *fd = (win32_fd *)dev->d_private;

	ntfs_log_trace("win32_ioctl(%d) called.\n", request);
	switch (request) {
#if defined(BLKGETSIZE)
	case BLKGETSIZE:
		ntfs_log_debug("BLKGETSIZE detected.\n");
		if (fd->part_length >= 0) {
			*(int *)argp = (int)(fd->part_length / 512);
			return 0;
		}
		errno = EOPNOTSUPP;
		return -1;
#endif
#if defined(BLKGETSIZE64)
	case BLKGETSIZE64:
		ntfs_log_debug("BLKGETSIZE64 detected.\n");
		if (fd->part_length >= 0) {
			*(s64 *)argp = fd->part_length;
			return 0;
		}
		errno = EOPNOTSUPP;
		return -1;
#endif
#ifdef HDIO_GETGEO
	case HDIO_GETGEO:
		ntfs_log_debug("HDIO_GETGEO detected.\n");
		return ntfs_win32_hdio_getgeo(dev, (struct hd_geometry *)argp);
#endif
#ifdef BLKSSZGET
	case BLKSSZGET:
		ntfs_log_debug("BLKSSZGET detected.\n");
		return ntfs_win32_blksszget(dev, (int *)argp);
#endif
#ifdef BLKBSZSET
	case BLKBSZSET:
		ntfs_log_debug("BLKBSZSET detected.\n");
		/* Nothing to do on Windows. */
		return 0;
#endif
	default:
		ntfs_log_debug("unimplemented ioctl %d.\n", request);
		errno = EOPNOTSUPP;
		return -1;
	}
}

static s64 ntfs_device_win32_pread(struct ntfs_device *dev, void *b,
		s64 count, s64 offset)
{
	win32_fd *fd = (win32_fd *)dev->d_private;
	return ntfs_device_win32_pread_simple(fd, offset, count, b);
}

static s64 ntfs_device_win32_pwrite(struct ntfs_device *dev, const void *b,
		s64 count, s64 offset)
{
	errno = EACCES;
	return -1;
}

struct ntfs_device_operations ntfs_device_unix_io_ops = {
	.open		= ntfs_device_win32_open,
	.close		= ntfs_device_win32_close,
	.seek		= ntfs_device_win32_seek,
	.read		= ntfs_device_win32_read,
	.write		= ntfs_device_win32_write,
	.pread		= ntfs_device_win32_pread,
	.pwrite		= ntfs_device_win32_pwrite,
	.sync		= ntfs_device_win32_sync,
	.stat		= ntfs_device_win32_stat,
	.ioctl		= ntfs_device_win32_ioctl
};


int backup1_ntfs(struct fout *ff, const char *f)
{
	char buf[65536];
	int n;

	struct ntfs_device *ntd;
	ntfs_volume *vol;
	ntfs_inode *ni;
	ntfs_attr *na;

	char tmp[_MAX_FNAME];
	char tmp1[_MAX_FNAME];
	char tmp2[16];
	char *filepart;
	int i, ok;
	DWORD tmp3[3];
	DWORD rc;
	HANDLE h;

	s64 ret, todo, offset;


	filepart = NULL;
	rc = GetFullPathName(f, sizeof(tmp1)-1, tmp1,  &filepart);
	if (rc < 0 || rc >= (sizeof(tmp1)-2)) return 0;

	sprintf(tmp2, "\\\\.\\%c:", tmp1[0]);
	h = CreateFile(tmp2,
			FILE_READ_DATA,
			(FILE_SHARE_WRITE | FILE_SHARE_READ),
			NULL, OPEN_EXISTING, 0, NULL);

	if (!DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
			NULL, 0, tmp3, sizeof(tmp3), &rc, NULL)) {
		win32_perror(tmp2);
		return 0;
	}
	CloseHandle(h);
	sprintf(tmp2, "(hd%u,%u)",
			(unsigned)tmp3[1],
			(unsigned)tmp3[2]);

	ntfs_device_win32_init_imports();
	if (fnGetLongPathName && fnGetShortPathName) {
		if (!fnGetShortPathName(tmp1, buf, sizeof(buf)-1)) {
			win32_perror(tmp1);
			return 0;
		}
		if (!fnGetLongPathName(buf, tmp, sizeof(tmp)-1)) {
			win32_perror(tmp1);
			return 0;
		}
	} else {
		strcpy(tmp, tmp1);
	}

	for (i = 2; tmp[i]; i++) if (tmp[i] == '\\') tmp[i] = '/';

	ntd = malloc(sizeof(struct ntfs_device));
	if (!ntd) abort();

	ntd->d_ops = &ntfs_device_unix_io_ops;
	ntd->d_state = 0;
	ntd->d_name = strdup(tmp2);
	if (!ntd->d_name) abort();
	ntd->d_private = NULL;

	vol = ntfs_device_mount(ntd, 1);
	if (!vol) {
		free(ntd);
		SetLastError(ERROR_FILE_NOT_FOUND);
		return 0;
	}
	ni = ntfs_pathname_to_inode(vol, NULL, tmp+3);
	if (!ni) {
		free(ntd);
		SetLastError(ERROR_FILE_NOT_FOUND);
		return 0;
	}
	na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);

	todo = na->data_size;
	offset = 0;

	ok = 1;

	while (todo > 0) {
		n = sizeof(buf);
		if (n > todo) n = todo;
		ret = ntfs_attr_pread(na, offset, n, buf);
		if (ret != n) {
			ok=0;
			break;
		}
		if (!fout(ff, buf, ret)) {
			ok = 0;
			break;
		}
		todo -= ret;
		offset += ret;
	}

	ntfs_attr_close(na);
	ntfs_inode_close(ni);
	ntfs_umount(vol, 0);
	CloseHandle(h);
	return 1;

}

