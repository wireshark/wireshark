/* errno.c
 * String descriptions for errno values.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/value_string.h>

/* Note: sorted in (unsigned) ascending order with no gaps to enable direct,
 * array-indexed access. */
static const value_string linux_negative_errno_vals[] = {
    /* from include/uapi/asm-generic/errno.h */
    { -133, "Memory page has hardware error (-EHWPOISON)" },
    { -132, "Operation not possible due to RF-kill (-ERFKILL)" },
    { -131, "State not recoverable (-ENOTRECOVERABLE)" },
    { -130, "Owner died (-EOWNERDEAD)" },
    { -129, "Key was rejected by service (-EKEYREJECTED)" },
    { -128, "Key has been revoked (-EKEYREVOKED)" },
    { -127, "Key has expired (-EKEYEXPIRED)" },
    { -126, "Required key not available (-ENOKEY)" },
    { -125, "Operation Canceled (-ECANCELED)" },
    { -124, "Wrong medium type (-EMEDIUMTYPE)" },
    { -123, "No medium found (-ENOMEDIUM)" },
    { -122, "Quota exceeded (-EDQUOT)" },
    { -121, "Remote I/O error (-EREMOTEIO)" },
    { -120, "Is a named type file (-EISNAM)" },
    { -119, "No XENIX semaphores available (-ENAVAIL)" },
    { -118, "Not a XENIX named type file (-ENOTNAM)" },
    { -117, "Structure needs cleaning (-EUCLEAN)" },
    { -116, "Stale file handle (-ESTALE)" },
    { -115, "Operation now in progress (-EINPROGRESS)" },
    { -114, "Operation already in progress (-EALREADY)" },
    { -113, "No route to host (-EHOSTUNREACH)" },
    { -112, "Host is down (-EHOSTDOWN)" },
    { -111, "Connection refused (-ECONNREFUSED)" },
    { -110, "Connection timed out (-ETIMEDOUT)" },
    { -109, "Too many references: cannot splice (-ETOOMANYREFS)" },
    { -108, "Cannot send after transport endpoint shutdown (-ESHUTDOWN)" },
    { -107, "Transport endpoint is not connected (-ENOTCONN)" },
    { -106, "Transport endpoint is already connected (-EISCONN)" },
    { -105, "No buffer space available (-ENOBUFS)" },
    { -104, "Connection reset by peer (-ECONNRESET)" },
    { -103, "Software caused connection abort (-ECONNABORTED)" },
    { -102, "Network dropped connection because of reset (-ENETRESET)" },
    { -101, "Network is unreachable (-ENETUNREACH)" },
    { -100, "Network is down (-ENETDOWN)" },
    { -99,  "Cannot assign requested address (-EADDRNOTAVAIL)" },
    { -98,  "Address already in use (-EADDRINUSE)" },
    { -97,  "Address family not supported by protocol (-EAFNOSUPPORT)" },
    { -96,  "Protocol family not supported (-EPFNOSUPPORT)" },
    { -95,  "Operation not supported on transport endpoint (-EOPNOTSUPP)" },
    { -94,  "Socket type not supported (-ESOCKTNOSUPPORT)" },
    { -93,  "Protocol not supported (-EPROTONOSUPPORT)" },
    { -92,  "Protocol not available (-ENOPROTOOPT)" },
    { -91,  "Protocol wrong type for socket (-EPROTOTYPE)" },
    { -90,  "Message too long (-EMSGSIZE)" },
    { -89,  "Destination address required (-EDESTADDRREQ)" },
    { -88,  "Socket operation on non-socket (-ENOTSOCK)" },
    { -87,  "Too many users (-EUSERS)" },
    { -86,  "Streams pipe error (-ESTRPIPE)" },
    { -85,  "Interrupted system call should be restarted (-ERESTART)" },
    { -84,  "Illegal byte sequence (-EILSEQ)" },
    { -83,  "Cannot exec a shared library directly (-ELIBEXEC)" },
    { -82,  "Attempting to link in too many shared libraries (-ELIBMAX)" },
    { -81,  ".lib section in a.out corrupted (-ELIBSCN)" },
    { -80,  "Accessing a corrupted shared library (-ELIBBAD)" },
    { -79,  "Can not access a needed shared library (-ELIBACC)" },
    { -78,  "Remote address changed (-EREMCHG)" },
    { -77,  "File descriptor in bad state (-EBADFD)" },
    { -76,  "Name not unique on network (-ENOTUNIQ)" },
    { -75,  "Value too large for defined data type (-EOVERFLOW)" },
    { -74,  "Not a data message (-EBADMSG)" },
    { -73,  "RFS specific error (-EDOTDOT)" },
    { -72,  "Multihop attempted (-EMULTIHOP)" },
    { -71,  "Protocol error (-EPROTO)" },
    { -70,  "Communication error on send (-ECOMM)" },
    { -69,  "Srmount error (-ESRMNT)" },
    { -68,  "Advertise error (-EADV)" },
    { -67,  "Link has been severed (-ENOLINK)" },
    { -66,  "Object is remote (-EREMOTE)" },
    { -65,  "Package not installed (-ENOPKG)" },
    { -64,  "Machine is not on the network (-ENONET)" },
    { -63,  "Out of streams resources (-ENOSR)" },
    { -62,  "Timer expired (-ETIME)" },
    { -61,  "No data available (-ENODATA)" },
    { -60,  "Device not a stream (-ENOSTR)" },
    { -59,  "Bad font file format (-EBFONT)" },
    { -58,  "(-58 \?\?\?)" },   /* dummy so that there are no "gaps" */
    { -57,  "Invalid slot (-EBADSLT)" },
    { -56,  "Invalid request code (-EBADRQC)" },
    { -55,  "No anode (-ENOANO)" },
    { -54,  "Exchange full (-EXFULL)" },
    { -53,  "Invalid request descriptor (-EBADR)" },
    { -52,  "Invalid exchange (-EBADE)" },
    { -51,  "Level 2 halted (-EL2HLT)" },
    { -50,  "No CSI structure available (-ENOCSI)" },
    { -49,  "Protocol driver not attached (-EUNATCH)" },
    { -48,  "Link number out of range (-ELNRNG)" },
    { -47,  "Level 3 reset (-EL3RST)" },
    { -46,  "Level 3 halted (-EL3HLT)" },
    { -45,  "Level 2 not synchronized (-EL2NSYNC)" },
    { -44,  "Channel number out of range (-ECHRNG)" },
    { -43,  "Identifier removed (-EIDRM)" },
    { -42,  "No message of desired type (-ENOMSG)" },
    { -41,  "(-41 \?\?\?)" },   /* dummy so that there are no "gaps" */
    { -40,  "Too many symbolic links encountered (-ELOOP)" },
    { -39,  "Directory not empty (-ENOTEMPTY)" },
    { -38,  "Invalid system call number (-ENOSYS)" },
    { -37,  "No record locks available (-ENOLCK)" },
    { -36,  "File name too long (-ENAMETOOLONG)" },
    { -35,  "Resource deadlock would occur (-EDEADLK)" },
    /* from include/uapi/asm-generic/errno-base.h */
    { -34,  "Math result not representable (-ERANGE)" },
    { -33,  "Math argument out of domain of func (-EDOM)" },
    { -32,  "Broken pipe (-EPIPE)" },
    { -31,  "Too many links (-EMLINK)" },
    { -30,  "Read-only file system (-EROFS)" },
    { -29,  "Illegal seek (-ESPIPE)" },
    { -28,  "No space left on device (-ENOSPC)" },
    { -27,  "File too large (-EFBIG)" },
    { -26,  "Text file busy (-ETXTBSY)" },
    { -25,  "Not a typewriter (-ENOTTY)" },
    { -24,  "Too many open files (-EMFILE)" },
    { -23,  "File table overflow (-ENFILE)" },
    { -22,  "Invalid argument (-EINVAL)" },
    { -21,  "Is a directory (-EISDIR)" },
    { -20,  "Not a directory (-ENOTDIR)" },
    { -19,  "No such device (-ENODEV)" },
    { -18,  "Cross-device link (-EXDEV)" },
    { -17,  "File exists (-EEXIST)" },
    { -16,  "Device or resource busy (-EBUSY)" },
    { -15,  "Block device required (-ENOTBLK)" },
    { -14,  "Bad address (-EFAULT)" },
    { -13,  "Permission denied (-EACCES)" },
    { -12,  "Out of memory (-ENOMEM)" },
    { -11,  "Try again (-EAGAIN)" },
    { -10,  "No child processes (-ECHILD)" },
    { -9,   "Bad file number (-EBADF)" },
    { -8,   "Exec format error (-ENOEXEC)" },
    { -7,   "Argument list too long (-E2BIG)" },
    { -6,   "No such device or address (-ENXIO)" },
    { -5,   "I/O error (-EIO)" },
    { -4,   "Interrupted system call (-EINTR)" },
    { -3,   "No such process (-ESRCH)" },
    { -2,   "No such file or directory (-ENOENT)" },
    { -1,   "Operation not permitted (-EPERM)" },
    { 0,    "Success" },
    { 0, NULL }
};

value_string_ext linux_negative_errno_vals_ext = VALUE_STRING_EXT_INIT(linux_negative_errno_vals);

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
