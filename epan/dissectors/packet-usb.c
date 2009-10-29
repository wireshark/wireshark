/* packet-usb.c
 *
 * $Id$
 *
 * USB basic dissector
 * By Paolo Abeni <paolo.abeni@email.it>
 * Ronnie Sahlberg 2006
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>
#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <string.h>
#include "packet-usb.h"
#include "packet-usb-hid.h"

/* protocols and header fields */
static int proto_usb = -1;

/* Linux USB pseudoheader fields */
static int hf_usb_urb_id = -1;
static int hf_usb_urb_type = -1;
static int hf_usb_transfer_type = -1;
static int hf_usb_endpoint_number = -1;
static int hf_usb_device_address = -1;
static int hf_usb_bus_id = -1;
static int hf_usb_setup_flag = -1;
static int hf_usb_data_flag = -1;
static int hf_usb_urb_status = -1;
static int hf_usb_urb_len = -1;
static int hf_usb_data_len = -1;

static int hf_usb_src_endpoint_number = -1;
static int hf_usb_dst_endpoint_number = -1;
static int hf_usb_request = -1;
static int hf_usb_request_unknown_class = -1;
static int hf_usb_value = -1;
static int hf_usb_index = -1;
static int hf_usb_length = -1;
static int hf_usb_data = -1;
static int hf_usb_capdata = -1;
static int hf_usb_wFeatureSelector = -1;
static int hf_usb_wInterface = -1;
static int hf_usb_wStatus = -1;
static int hf_usb_wFrameNumber = -1;
static int hf_usb_bmRequestType = -1;
static int hf_usb_bmRequestType_direction = -1;
static int hf_usb_bmRequestType_type = -1;
static int hf_usb_bmRequestType_recipient = -1;
static int hf_usb_bDescriptorType = -1;
static int hf_usb_descriptor_index = -1;
static int hf_usb_language_id = -1;
static int hf_usb_bLength = -1;
static int hf_usb_bcdUSB = -1;
static int hf_usb_bDeviceClass = -1;
static int hf_usb_bDeviceSubClass = -1;
static int hf_usb_bDeviceProtocol = -1;
static int hf_usb_bMaxPacketSize0 = -1;
static int hf_usb_idVendor = -1;
static int hf_usb_idProduct = -1;
static int hf_usb_bcdDevice = -1;
static int hf_usb_iManufacturer = -1;
static int hf_usb_iProduct = -1;
static int hf_usb_iSerialNumber = -1;
static int hf_usb_bNumConfigurations = -1;
static int hf_usb_wLANGID = -1;
static int hf_usb_bString = -1;
static int hf_usb_bInterfaceNumber = -1;
static int hf_usb_bAlternateSetting = -1;
static int hf_usb_bNumEndpoints = -1;
static int hf_usb_bInterfaceClass = -1;
static int hf_usb_bInterfaceSubClass = -1;
static int hf_usb_bInterfaceProtocol = -1;
static int hf_usb_iInterface = -1;
static int hf_usb_bEndpointAddress = -1;
static int hf_usb_bmAttributes = -1;
static int hf_usb_bEndpointAttributeTransfer = -1;
static int hf_usb_bEndpointAttributeSynchonisation = -1;
static int hf_usb_bEndpointAttributeBehaviour = -1;
static int hf_usb_wMaxPacketSize = -1;
static int hf_usb_bInterval = -1;
static int hf_usb_wTotalLength = -1;
static int hf_usb_bNumInterfaces = -1;
static int hf_usb_bConfigurationValue = -1;
static int hf_usb_iConfiguration = -1;
static int hf_usb_bMaxPower = -1;
static int hf_usb_configuration_bmAttributes = -1;
static int hf_usb_configuration_legacy10buspowered = -1;
static int hf_usb_configuration_selfpowered = -1;
static int hf_usb_configuration_remotewakeup = -1;
static int hf_usb_bEndpointAddress_direction = -1;
static int hf_usb_bEndpointAddress_number = -1;
static int hf_usb_response_in = -1;
static int hf_usb_time = -1;
static int hf_usb_request_in = -1;

static gint usb_hdr = -1;
static gint usb_setup_hdr = -1;
static gint ett_usb_setup_bmrequesttype = -1;
static gint ett_descriptor_device = -1;
static gint ett_configuration_bmAttributes = -1;
static gint ett_configuration_bEndpointAddress = -1;
static gint ett_endpoint_bmAttributes = -1;


static int usb_tap = -1;

static dissector_table_t usb_bulk_dissector_table;
static dissector_table_t usb_control_dissector_table;

static const value_string usb_langid_vals[] = {
    {0x0000,	"no language specified"},
    {0x0409,	"English (United States)"},
    {0, NULL}
};

static const value_string usb_interfaceclass_vals[] = {
    {IF_CLASS_FROM_INTERFACE_DESC,	"Use class info in Interface Descriptor"},
    {IF_CLASS_AUDIO,			"AUDIO"},
    {IF_CLASS_COMMUNICATIONS,		"COMMUNICATIONS"},
    {IF_CLASS_HID,			"HID"},
    {IF_CLASS_PHYSICAL,			"PHYSICAL"},
    {IF_CLASS_IMAGE,			"IMAGE"},
    {IF_CLASS_PRINTER,			"PRINTER"},
    {IF_CLASS_MASSTORAGE,		"MASSTORAGE"},
    {IF_CLASS_HUB,			"HUB"},
    {IF_CLASS_CDC_DATA,			"CDC_DATA"},
    {IF_CLASS_SMART_CARD,		"SMART_CARD"},
    {IF_CLASS_CONTENT_SECURITY,		"CONTENT_SECURITY"},
    {IF_CLASS_VIDEO,			"VIDEO"},
    {IF_CLASS_DIAGNOSTIC_DEVICE,	"DIAGNOSTIC_DEVICE"},
    {IF_CLASS_WIRELESS_CONTROLLER,	"WIRELESS_CONTROLLER"},
    {IF_CLASS_MISCELLANEOUS,		"MISCELLANEOUS"},
    {IF_CLASS_APPLICATION_SPECIFIC,	"APPLICATION_SPECIFIC"},
    {IF_CLASS_VENDOR_SPECIFIC,		"VENDOR_SPECIFIC"},
    {0, NULL}
};


static const value_string usb_transfer_type_vals[] = {
    {URB_CONTROL, "URB_CONTROL out"},
    {URB_ISOCHRONOUS,"URB_ISOCHRONOUS out"},
    {URB_INTERRUPT,"URB_INTERRUPT out"},
    {URB_BULK,"URB_BULK out"},
    {URB_CONTROL | URB_TRANSFER_IN, "URB_CONTROL in"},
    {URB_ISOCHRONOUS | URB_TRANSFER_IN,"URB_ISOCHRONOUS in"},
    {URB_INTERRUPT | URB_TRANSFER_IN,"URB_INTERRUPT in"},
    {URB_BULK | URB_TRANSFER_IN,"URB_BULK in"},
    {0, NULL}
};

static const value_string usb_urb_type_vals[] = {
    {URB_SUBMIT, "URB_SUBMIT"},
    {URB_COMPLETE,"URB_COMPLETE"},
    {URB_ERROR,"URB_ERROR"},
    {0, NULL}
};

/*
 * Descriptor types.
 */
#define USB_DT_DEVICE                   1
#define USB_DT_CONFIG                   2
#define USB_DT_STRING                   3
#define USB_DT_INTERFACE                4
#define USB_DT_ENDPOINT                 5
#define USB_DT_DEVICE_QUALIFIER         6
#define USB_DT_OTHER_SPEED_CONFIG       7
#define USB_DT_INTERFACE_POWER          8
/* these are from a minor usb 2.0 revision (ECN) */
#define USB_DT_OTG                      9
#define USB_DT_DEBUG                    10
#define USB_DT_INTERFACE_ASSOCIATION    11
/* these are from the Wireless USB spec */
#define USB_DT_SECURITY                 12
#define USB_DT_KEY                      13
#define USB_DT_ENCRYPTION_TYPE          14
#define USB_DT_BOS                      15
#define USB_DT_DEVICE_CAPABILITY        16
#define USB_DT_WIRELESS_ENDPOINT_COMP   17
#define USB_DT_HID			33
#define USB_DT_RPIPE                    34

static const value_string descriptor_type_vals[] = {
    {USB_DT_DEVICE,			"DEVICE"},
    {USB_DT_CONFIG,			"CONFIGURATION"},
    {USB_DT_STRING,			"STRING"},
    {USB_DT_INTERFACE,			"INTERFACE"},
    {USB_DT_ENDPOINT,			"ENDPOINT"},
    {USB_DT_DEVICE_QUALIFIER,		"DEVICE QUALIFIER"},
    {USB_DT_OTHER_SPEED_CONFIG,		"OTHER_SPEED CONFIG"},
    {USB_DT_INTERFACE_POWER,		"INTERFACE POWER"},
    {USB_DT_OTG,			"OTG"},
    {USB_DT_DEBUG,			"DEBUG"},
    {USB_DT_INTERFACE_ASSOCIATION,	"INTERFACE ASSOCIATION"},
    {USB_DT_SECURITY,			"SECURITY"},
    {USB_DT_KEY,			"KEY"},
    {USB_DT_ENCRYPTION_TYPE,		"ENCRYPTION TYPE"},
    {USB_DT_BOS,			"BOS"},
    {USB_DT_DEVICE_CAPABILITY,		"DEVICE CAPABILITY"},
    {USB_DT_WIRELESS_ENDPOINT_COMP,	"WIRELESS ENDPOINT COMP"},
    {USB_DT_HID,			"HID"},
    {USB_DT_RPIPE,			"RPIPE"},
    {0,NULL}
};

/*
 * Feature selectors.
 */
#define USB_FS_DEVICE_REMOTE_WAKEUP	1
#define USB_FS_ENDPOINT_HALT		0
#define USB_FS_TEST_MODE		2

static const value_string usb_feature_selector_vals[] = {
    {USB_FS_DEVICE_REMOTE_WAKEUP,	"DEVICE REMOTE WAKEUP"},
    {USB_FS_ENDPOINT_HALT,		"ENDPOINT HALT"},
    {USB_FS_TEST_MODE,			"TEST MODE"},
    {0,NULL}
};

static const value_string usb_bmAttributes_transfer_vals[] = {
    {0x00,	"Control-Transfer"},
    {0x01,	"Isochronous-Transfer"},
    {0x02,	"Bulk-Transfer"},
    {0x03,	"Interrupt-Transfer"},
    {0,NULL}
};

static const value_string usb_bmAttributes_sync_vals[] = {
    {0x00,	"No Sync"},
    {0x04,	"Asynchronous"},
    {0x08,	"Adaptive"},
    {0x0c,	"Synchronous"},
    {0,NULL}
};

static const value_string usb_bmAttributes_behaviour_vals[] = {
    {0x00,	"Data-Endpoint"},
    {0x10,	"Explicit Feedback-Endpoint"},
    {0x20,	"Implicit Feedback-Data-Endpoint"},
    {0x30,	"Reserved"},
    {0,NULL}
};

/* from linux/include/asm-generic/errno.h */
#define	EPERM		 1	/* Operation not permitted */
#define	ENOENT		 2	/* No such file or directory */
#define	ESRCH		 3	/* No such process */
#define	EINTR		 4	/* Interrupted system call */
#define	EIO		 5	/* I/O error */
#define	ENXIO		 6	/* No such device or address */
#define	E2BIG		 7	/* Argument list too long */
#define	ENOEXEC		 8	/* Exec format error */
#define	EBADF		 9	/* Bad file number */
#define	ECHILD		10	/* No child processes */
#define	EAGAIN		11	/* Try again */
#define	ENOMEM		12	/* Out of memory */
#define	EACCES		13	/* Permission denied */
#define	EFAULT		14	/* Bad address */
#define	ENOTBLK		15	/* Block device required */
#define	EBUSY		16	/* Device or resource busy */
#define	EEXIST		17	/* File exists */
#define	EXDEV		18	/* Cross-device link */
#define	ENODEV		19	/* No such device */
#define	ENOTDIR		20	/* Not a directory */
#define	EISDIR		21	/* Is a directory */
#define	EINVAL		22	/* Invalid argument */
#define	ENFILE		23	/* File table overflow */
#define	EMFILE		24	/* Too many open files */
#define	ENOTTY		25	/* Not a typewriter */
#define	ETXTBSY		26	/* Text file busy */
#define	EFBIG		27	/* File too large */
#define	ENOSPC		28	/* No space left on device */
#define	ESPIPE		29	/* Illegal seek */
#define	EROFS		30	/* Read-only file system */
#define	EMLINK		31	/* Too many links */
#define	EPIPE		32	/* Broken pipe */
#define	EDOM		33	/* Math argument out of domain of func */
#define	ERANGE		34	/* Math result not representable */


/* from linux/include/asm-generic/errno.h*/
#define	EDEADLK		35	/* Resource deadlock would occur */
#define	ENAMETOOLONG	36	/* File name too long */
#define	ENOLCK		37	/* No record locks available */
#define	ENOSYS		38	/* Function not implemented */
#define	ENOTEMPTY	39	/* Directory not empty */
#define	ELOOP		40	/* Too many symbolic links encountered */
#define	EWOULDBLOCK	EAGAIN	/* Operation would block */
#define	ENOMSG		42	/* No message of desired type */
#define	EIDRM		43	/* Identifier removed */
#define	ECHRNG		44	/* Channel number out of range */
#define	EL2NSYNC	45	/* Level 2 not synchronized */
#define	EL3HLT		46	/* Level 3 halted */
#define	EL3RST		47	/* Level 3 reset */
#define	ELNRNG		48	/* Link number out of range */
#define	EUNATCH		49	/* Protocol driver not attached */
#define	ENOCSI		50	/* No CSI structure available */
#define	EL2HLT		51	/* Level 2 halted */
#define	EBADE		52	/* Invalid exchange */
#define	EBADR		53	/* Invalid request descriptor */
#define	EXFULL		54	/* Exchange full */
#define	ENOANO		55	/* No anode */
#define	EBADRQC		56	/* Invalid request code */
#define	EBADSLT		57	/* Invalid slot */

#define	EDEADLOCK	EDEADLK

#define	EBFONT		59	/* Bad font file format */
#define	ENOSTR		60	/* Device not a stream */
#define	ENODATA		61	/* No data available */
#define	ETIME		62	/* Timer expired */
#define	ENOSR		63	/* Out of streams resources */
#define	ENONET		64	/* Machine is not on the network */
#define	ENOPKG		65	/* Package not installed */
#define	EREMOTE		66	/* Object is remote */
#define	ENOLINK		67	/* Link has been severed */
#define	EADV		68	/* Advertise error */
#define	ESRMNT		69	/* Srmount error */
#define	ECOMM		70	/* Communication error on send */
#define	EPROTO		71	/* Protocol error */
#define	EMULTIHOP	72	/* Multihop attempted */
#define	EDOTDOT		73	/* RFS specific error */
#define	EBADMSG		74	/* Not a data message */
#define	EOVERFLOW	75	/* Value too large for defined data type */
#define	ENOTUNIQ	76	/* Name not unique on network */
#define	EBADFD		77	/* File descriptor in bad state */
#define	EREMCHG		78	/* Remote address changed */
#define	ELIBACC		79	/* Can not access a needed shared library */
#define	ELIBBAD		80	/* Accessing a corrupted shared library */
#define	ELIBSCN		81	/* .lib section in a.out corrupted */
#define	ELIBMAX		82	/* Attempting to link in too many shared libraries */
#define	ELIBEXEC	83	/* Cannot exec a shared library directly */
#define	EILSEQ		84	/* Illegal byte sequence */
#define	ERESTART	85	/* Interrupted system call should be restarted */
#define	ESTRPIPE	86	/* Streams pipe error */
#define	EUSERS		87	/* Too many users */
#define	ENOTSOCK	88	/* Socket operation on non-socket */
#define	EDESTADDRREQ	89	/* Destination address required */
#define	EMSGSIZE	90	/* Message too long */
#define	EPROTOTYPE	91	/* Protocol wrong type for socket */
#define	ENOPROTOOPT	92	/* Protocol not available */
#define	EPROTONOSUPPORT	93	/* Protocol not supported */
#define	ESOCKTNOSUPPORT	94	/* Socket type not supported */
#define	EOPNOTSUPP	95	/* Operation not supported on transport endpoint */
#define	EPFNOSUPPORT	96	/* Protocol family not supported */
#define	EAFNOSUPPORT	97	/* Address family not supported by protocol */
#define	EADDRINUSE	98	/* Address already in use */
#define	EADDRNOTAVAIL	99	/* Cannot assign requested address */
#define	ENETDOWN	100	/* Network is down */
#define	ENETUNREACH	101	/* Network is unreachable */
#define	ENETRESET	102	/* Network dropped connection because of reset */
#define	ECONNABORTED	103	/* Software caused connection abort */
#define	ECONNRESET	104	/* Connection reset by peer */
#define	ENOBUFS		105	/* No buffer space available */
#define	EISCONN		106	/* Transport endpoint is already connected */
#define	ENOTCONN	107	/* Transport endpoint is not connected */
#define	ESHUTDOWN	108	/* Cannot send after transport endpoint shutdown */
#define	ETOOMANYREFS	109	/* Too many references: cannot splice */
#define	ETIMEDOUT	110	/* Connection timed out */
#define	ECONNREFUSED	111	/* Connection refused */
#define	EHOSTDOWN	112	/* Host is down */
#define	EHOSTUNREACH	113	/* No route to host */
#define	EALREADY	114	/* Operation already in progress */
#define	EINPROGRESS	115	/* Operation now in progress */
#define	ESTALE		116	/* Stale NFS file handle */
#define	EUCLEAN		117	/* Structure needs cleaning */
#define	ENOTNAM		118	/* Not a XENIX named type file */
#define	ENAVAIL		119	/* No XENIX semaphores available */
#define	EISNAM		120	/* Is a named type file */
#define	EREMOTEIO	121	/* Remote I/O error */
#define	EDQUOT		122	/* Quota exceeded */

#define	ENOMEDIUM	123	/* No medium found */
#define	EMEDIUMTYPE	124	/* Wrong medium type */
#define	ECANCELED	125	/* Operation Canceled */
#define	ENOKEY		126	/* Required key not available */
#define	EKEYEXPIRED	127	/* Key has expired */
#define	EKEYREVOKED	128	/* Key has been revoked */
#define	EKEYREJECTED	129	/* Key was rejected by service */

/* for robust mutexes */
#define	EOWNERDEAD	130	/* Owner died */
#define	ENOTRECOVERABLE	131	/* State not recoverable */


static const value_string usb_urb_status_vals[] = {
    { 0,                "Success"},
    { -EPERM,           "Operation not permitted (-EPERM)" },
    { -ENOENT,          "No such file or directory (-ENOENT)" },
    { -ESRCH,           "No such process (-ESRCH)" },
    { -EINTR,           "Interrupted system call (-EINTR)" },
    { -EIO,             "I/O error (-EIO)" },
    { -ENXIO,           "No such device or address (-ENXIO)" },
    { -E2BIG,           "Argument list too long (-E2BIG)" },
    { -ENOEXEC,         "Exec format error (-ENOEXEC)" },
    { -EBADF,           "Bad file number (-EBADF)" },
    { -ECHILD,          "No child processes (-ECHILD)" },
    { -EAGAIN,          "Try again (-EAGAIN)" },
    { -ENOMEM,          "Out of memory (-ENOMEM)" },
    { -EACCES,          "Permission denied (-EACCES)" },
    { -EFAULT,          "Bad address (-EFAULT)" },
    { -ENOTBLK,         "Block device required (-ENOTBLK)" },
    { -EBUSY,           "Device or resource busy (-EBUSY)" },
    { -EEXIST,          "File exists (-EEXIST)" },
    { -EXDEV,           "Cross-device link (-EXDEV)" },
    { -ENODEV,          "No such device (-ENODEV)" },
    { -ENOTDIR,         "Not a directory (-ENOTDIR)" },
    { -EISDIR,          "Is a directory (-EISDIR)" },
    { -EINVAL,          "Invalid argument (-EINVAL)" },
    { -ENFILE,          "File table overflow (-ENFILE)" },
    { -EMFILE,          "Too many open files (-EMFILE)" },
    { -ENOTTY,          "Not a typewriter (-ENOTTY)" },
    { -ETXTBSY,         "Text file busy (-ETXTBSY)" },
    { -EFBIG,           "File too large (-EFBIG)" },
    { -ENOSPC,          "No space left on device (-ENOSPC)" },
    { -ESPIPE,          "Illegal seek (-ESPIPE)" },
    { -EROFS,           "Read-only file system (-EROFS)" },
    { -EMLINK,          "Too many links (-EMLINK)" },
    { -EPIPE,           "Broken pipe (-EPIPE)" },
    { -EDOM,            "Math argument out of domain of func (-EDOM)" },
    { -ERANGE,          "Math result not representable (-ERANGE)" },
    { -EDEADLK,         "Resource deadlock would occur (-EDEADLK)" },
    { -ENAMETOOLONG,    "File name too long (-ENAMETOOLONG)" },
    { -ENOLCK,          "No record locks available (-ENOLCK)" },
    { -ENOSYS,          "Function not implemented (-ENOSYS)" },
    { -ENOTEMPTY,       "Directory not empty (-ENOTEMPTY)" },
    { -ELOOP,           "Too many symbolic links encountered (-ELOOP)" },
    { -ENOMSG,          "No message of desired type (-ENOMSG)" },
    { -EIDRM,           "Identifier removed (-EIDRM)" },
    { -ECHRNG,          "Channel number out of range (-ECHRNG)" },
    { -EL2NSYNC,        "Level 2 not synchronized (-EL2NSYNC)" },
    { -EL3HLT,          "Level 3 halted (-EL3HLT)" },
    { -EL3RST,          "Level 3 reset (-EL3RST)" },
    { -ELNRNG,          "Link number out of range (-ELNRNG)" },
    { -EUNATCH,         "Protocol driver not attached (-EUNATCH)" },
    { -ENOCSI,          "No CSI structure available (-ENOCSI)" },
    { -EL2HLT,          "Level 2 halted (-EL2HLT)" },
    { -EBADE,           "Invalid exchange (-EBADE)" },
    { -EBADR,           "Invalid request descriptor (-EBADR)" },
    { -EXFULL,          "Exchange full (-EXFULL)" },
    { -ENOANO,          "No anode (-ENOANO)" },
    { -EBADRQC,         "Invalid request code (-EBADRQC)" },
    { -EBADSLT,         "Invalid slot (-EBADSLT)" },
    { -EBFONT,          "Bad font file format (-EBFONT)" },
    { -ENOSTR,          "Device not a stream (-ENOSTR)" },
    { -ENODATA,         "No data available (-ENODATA)" },
    { -ETIME,           "Timer expired (-ETIME)" },
    { -ENOSR,           "Out of streams resources (-ENOSR)" },
    { -ENONET,          "Machine is not on the network (-ENONET)" },
    { -ENOPKG,          "Package not installed (-ENOPKG)" },
    { -EREMOTE,         "Object is remote (-EREMOTE)" },
    { -ENOLINK,         "Link has been severed (-ENOLINK)" },
    { -EADV,            "Advertise error (-EADV)" },
    { -ESRMNT,          "Srmount error (-ESRMNT)" },
    { -ECOMM,           "Communication error on send (-ECOMM)" },
    { -EPROTO,          "Protocol error (-EPROTO)" },
    { -EMULTIHOP,       "Multihop attempted (-EMULTIHOP)" },
    { -EDOTDOT,         "RFS specific error (-EDOTDOT)" },
    { -EBADMSG,         "Not a data message (-EBADMSG)" },
    { -EOVERFLOW,       "Value too large for defined data type (-EOVERFLOW)" },
    { -ENOTUNIQ,        "Name not unique on network (-ENOTUNIQ)" },
    { -EBADFD,          "File descriptor in bad state (-EBADFD)" },
    { -EREMCHG,         "Remote address changed (-EREMCHG)" },
    { -ELIBACC,         "Can not access a needed shared library (-ELIBACC)" },
    { -ELIBBAD,         "Accessing a corrupted shared library (-ELIBBAD)" },
    { -ELIBSCN,         ".lib section in a.out corrupted (-ELIBSCN)" },
    { -ELIBMAX,         "Attempting to link in too many shared libraries (-ELIBMAX)" },
    { -ELIBEXEC,        "Cannot exec a shared library directly (-ELIBEXEC)" },
    { -EILSEQ,          "Illegal byte sequence (-EILSEQ)" },
    { -ERESTART,        "Interrupted system call should be restarted (-ERESTART)" },
    { -ESTRPIPE,        "Streams pipe error (-ESTRPIPE)" },
    { -EUSERS,          "Too many users (-EUSERS)" },
    { -ENOTSOCK,        "Socket operation on non-socket (-ENOTSOCK)" },
    { -EDESTADDRREQ,    "Destination address required (-EDESTADDRREQ)" },
    { -EMSGSIZE,        "Message too long (-EMSGSIZE)" },
    { -EPROTOTYPE,      "Protocol wrong type for socket (-EPROTOTYPE)" },
    { -ENOPROTOOPT,     "Protocol not available (-ENOPROTOOPT)" },
    { -EPROTONOSUPPORT, "Protocol not supported (-EPROTONOSUPPORT)" },
    { -ESOCKTNOSUPPORT, "Socket type not supported (-ESOCKTNOSUPPORT)" },
    { -EOPNOTSUPP,      "Operation not supported on transport endpoint (-EOPNOTSUPP)" },
    { -EPFNOSUPPORT,    "Protocol family not supported (-EPFNOSUPPORT)" },
    { -EAFNOSUPPORT,    "Address family not supported by protocol (-EAFNOSUPPORT)" },
    { -EADDRINUSE,      "Address already in use (-EADDRINUSE)" },
    { -EADDRNOTAVAIL,   "Cannot assign requested address (-EADDRNOTAVAIL)" },
    { -ENETDOWN,        "Network is down (-ENETDOWN)" },
    { -ENETUNREACH,     "Network is unreachable (-ENETUNREACH)" },
    { -ENETRESET,       "Network dropped connection because of reset (-ENETRESET)" },
    { -ECONNABORTED,    "Software caused connection abort (-ECONNABORTED)" },
    { -ECONNRESET,      "Connection reset by peer (-ECONNRESET)" },
    { -ENOBUFS,         "No buffer space available (-ENOBUFS)" },
    { -EISCONN,         "Transport endpoint is already connected (-EISCONN)" },
    { -ENOTCONN,        "Transport endpoint is not connected (-ENOTCONN)" },
    { -ESHUTDOWN,       "Cannot send after transport endpoint shutdown (-ESHUTDOWN)" },
    { -ETOOMANYREFS,    "Too many references: cannot splice (-ETOOMANYREFS)" },
    { -ETIMEDOUT,       "Connection timed out (-ETIMEDOUT)" },
    { -ECONNREFUSED,    "Connection refused (-ECONNREFUSED)" },
    { -EHOSTDOWN,       "Host is down (-EHOSTDOWN)" },
    { -EHOSTUNREACH,    "No route to host (-EHOSTUNREACH)" },
    { -EALREADY,        "Operation already in progress (-EALREADY)" },
    { -EINPROGRESS,     "Operation now in progress (-EINPROGRESS)" },
    { -ESTALE,          "Stale NFS file handle (-ESTALE)" },
    { -EUCLEAN,         "Structure needs cleaning (-EUCLEAN)" },
    { -ENOTNAM,         "Not a XENIX named type file (-ENOTNAM)" },
    { -ENAVAIL,         "No XENIX semaphores available (-ENAVAIL)" },
    { -EISNAM,          "Is a named type file (-EISNAM)" },
    { -EREMOTEIO,       "Remote I/O error (-EREMOTEIO)" },
    { -EDQUOT,          "Quota exceeded (-EDQUOT)" },
    { -ENOMEDIUM,       "No medium found (-ENOMEDIUM)" },
    { -EMEDIUMTYPE,     "Wrong medium type (-EMEDIUMTYPE)" },
    { -ECANCELED,       "Operation Canceled (-ECANCELED)" },
    { -ENOKEY,          "Required key not available (-ENOKEY)" },
    { -EKEYEXPIRED,     "Key has expired (-EKEYEXPIRED)" },
    { -EKEYREVOKED,     "Key has been revoked (-EKEYREVOKED)" },
    { -EKEYREJECTED,    "Key was rejected by service (-EKEYREJECTED)" },
    { -EOWNERDEAD,      "Owner died (-EOWNERDEAD)" },
    { -ENOTRECOVERABLE, "State not recoverable (-ENOTRECOVERABLE)" },
    { 0, NULL }
};


static usb_conv_info_t *
get_usb_conv_info(conversation_t *conversation)
{
    usb_conv_info_t *usb_conv_info;

    /* do we have conversation specific data ? */
    usb_conv_info = conversation_get_proto_data(conversation, proto_usb);
    if(!usb_conv_info){
        /* no not yet so create some */
        usb_conv_info = se_alloc0(sizeof(usb_conv_info_t));
        usb_conv_info->interfaceClass=IF_CLASS_UNKNOWN;
        usb_conv_info->transactions=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "usb transactions");

        conversation_add_proto_data(conversation, proto_usb, usb_conv_info);
    }

    return usb_conv_info;
}

static conversation_t *
get_usb_conversation(packet_info *pinfo, address *src_addr, address *dst_addr, guint32 src_endpoint, guint32 dst_endpoint)
{
    conversation_t *conversation;

    /*
     * Do we have a conversation for this connection?
     */
    conversation = find_conversation(pinfo->fd->num,
                               src_addr, dst_addr,
                               pinfo->ptype,
                               src_endpoint, dst_endpoint, 0);
    if(conversation){
        return conversation;
    }

    /* We don't yet have a conversation, so create one. */
    conversation = conversation_new(pinfo->fd->num,
                           src_addr, dst_addr,
                           pinfo->ptype,
                           src_endpoint, dst_endpoint, 0);
    return conversation;
}



/* SETUP dissectors */


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / CLEAR FEATURE
 */


/* 9.4.1 */
static int
dissect_usb_setup_clear_feature_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* feature selector */
    proto_tree_add_item(tree, hf_usb_wFeatureSelector, tvb, offset, 2, TRUE);
    offset += 2;

    /* zero/interface/endpoint */
    /* XXX - check based on request type */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, TRUE);
    offset += 2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_clear_feature_response(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / GET CONFIGURATION
 */


/* 9.4.2 */
static int
dissect_usb_setup_get_configuration_response(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, TRUE);
    offset++;

    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / GET DESCRIPTOR
 */


/* 9.6.2 */
static int
dissect_usb_device_qualifier_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;

    if(parent_tree){
        item=proto_tree_add_text(parent_tree, tvb, offset, -1, "DEVICE QUALIFIER DESCRIPTOR");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
    }

    /* bLength */
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, TRUE);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    offset++;

    /* bcdUSB */
    proto_tree_add_item(tree, hf_usb_bcdUSB, tvb, offset, 2, TRUE);
    offset+=2;

    /* bDeviceClass */
    proto_tree_add_item(tree, hf_usb_bDeviceClass, tvb, offset, 1, TRUE);
    offset++;

    /* bDeviceSubClass */
    proto_tree_add_item(tree, hf_usb_bDeviceSubClass, tvb, offset, 1, TRUE);
    offset++;

    /* bDeviceProtocol */
    proto_tree_add_item(tree, hf_usb_bDeviceProtocol, tvb, offset, 1, TRUE);
    offset++;

    /* bMaxPacketSize0 */
    proto_tree_add_item(tree, hf_usb_bMaxPacketSize0, tvb, offset, 1, TRUE);
    offset++;

    /* bNumConfigurations */
    proto_tree_add_item(tree, hf_usb_bNumConfigurations, tvb, offset, 1, TRUE);
    offset++;

    /* one reserved byte */
    offset++;

    if(item){
        proto_item_set_len(item, offset-old_offset);
    }

    return offset;
}

/* 9.6.1 */
static int
dissect_usb_device_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;

    if(parent_tree){
        item=proto_tree_add_text(parent_tree, tvb, offset, -1, "DEVICE DESCRIPTOR");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
    }

    /* bLength */
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, TRUE);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    offset++;

    /* bcdUSB */
    proto_tree_add_item(tree, hf_usb_bcdUSB, tvb, offset, 2, TRUE);
    offset+=2;

    /* bDeviceClass */
    proto_tree_add_item(tree, hf_usb_bDeviceClass, tvb, offset, 1, TRUE);
    offset++;

    /* bDeviceSubClass */
    proto_tree_add_item(tree, hf_usb_bDeviceSubClass, tvb, offset, 1, TRUE);
    offset++;

    /* bDeviceProtocol */
    proto_tree_add_item(tree, hf_usb_bDeviceProtocol, tvb, offset, 1, TRUE);
    offset++;

    /* bMaxPacketSize0 */
    proto_tree_add_item(tree, hf_usb_bMaxPacketSize0, tvb, offset, 1, TRUE);
    offset++;

    /* idVendor */
    proto_tree_add_item(tree, hf_usb_idVendor, tvb, offset, 2, TRUE);
    offset+=2;

    /* idProduct */
    proto_tree_add_item(tree, hf_usb_idProduct, tvb, offset, 2, TRUE);
    offset+=2;

    /* bcdDevice */
    proto_tree_add_item(tree, hf_usb_bcdDevice, tvb, offset, 2, TRUE);
    offset+=2;

    /* iManufacturer */
    proto_tree_add_item(tree, hf_usb_iManufacturer, tvb, offset, 1, TRUE);
    offset++;

    /* iProduct */
    proto_tree_add_item(tree, hf_usb_iProduct, tvb, offset, 1, TRUE);
    offset++;

    /* iSerialNumber */
    proto_tree_add_item(tree, hf_usb_iSerialNumber, tvb, offset, 1, TRUE);
    offset++;

    /* bNumConfigurations */
    proto_tree_add_item(tree, hf_usb_bNumConfigurations, tvb, offset, 1, TRUE);
    offset++;

    if(item){
        proto_item_set_len(item, offset-old_offset);
    }

    return offset;
}

/* 9.6.7 */
static int
dissect_usb_string_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint8 len;

    if(parent_tree){
        item=proto_tree_add_text(parent_tree, tvb, offset, -1, "STRING DESCRIPTOR");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
    }

    /* bLength */
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, TRUE);
    len=tvb_get_guint8(tvb, offset);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    offset++;

    if(!usb_trans_info->u.get_descriptor.index){
        /* list of languanges */
        while(len>(offset-old_offset)){
            /* wLANGID */
            proto_tree_add_item(tree, hf_usb_wLANGID, tvb, offset, 2, TRUE);
            offset+=2;
        }
    } else {
        char *str;

        /* unicode string */
        str=tvb_get_ephemeral_faked_unicode(tvb, offset, (len-2)/2, TRUE);
        proto_tree_add_string(tree, hf_usb_bString, tvb, offset, len-2, str);
        offset += len-2;
    }

    if(item){
        proto_item_set_len(item, offset-old_offset);
    }

    return offset;
}



/* 9.6.5 */
static int
dissect_usb_interface_descriptor(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint8 len;

    if(parent_tree){
        item=proto_tree_add_text(parent_tree, tvb, offset, -1, "INTERFACE DESCRIPTOR");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
    }

    /* bLength */
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, TRUE);
    len = tvb_get_guint8(tvb, offset);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    offset++;

    /* bInterfaceNumber */
    proto_tree_add_item(tree, hf_usb_bInterfaceNumber, tvb, offset, 1, TRUE);
    offset++;

    /* bAlternateSetting */
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, TRUE);
    offset++;

    /* bNumEndpoints */
    proto_tree_add_item(tree, hf_usb_bNumEndpoints, tvb, offset, 1, TRUE);
    offset++;

    /* bInterfaceClass */
    proto_tree_add_item(tree, hf_usb_bInterfaceClass, tvb, offset, 1, TRUE);
    /* save the class so we can access it later in the endpoint descriptor */
    usb_conv_info->interfaceClass=tvb_get_guint8(tvb, offset);
    if(!pinfo->fd->flags.visited){
        usb_trans_info->interface_info=se_alloc0(sizeof(usb_conv_info_t));
        usb_trans_info->interface_info->interfaceClass=tvb_get_guint8(tvb, offset);
        usb_trans_info->interface_info->transactions=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "usb transactions");
    }
    offset++;

    /* bInterfaceSubClass */
    proto_tree_add_item(tree, hf_usb_bInterfaceSubClass, tvb, offset, 1, TRUE);
    offset++;

    /* bInterfaceProtocol */
    proto_tree_add_item(tree, hf_usb_bInterfaceProtocol, tvb, offset, 1, TRUE);
    offset++;

    /* iInterface */
    proto_tree_add_item(tree, hf_usb_iInterface, tvb, offset, 1, TRUE);
    offset++;

    if(item){
        proto_item_set_len(item, len);
    }
    if (offset != old_offset + len) {
        /* unknown records */
    }
    offset = old_offset + len;

    return offset;
}

/* 9.6.6 */
static const true_false_string tfs_endpoint_direction = {
    "IN Endpoint",
    "OUT Endpoint"
};
static int
dissect_usb_endpoint_descriptor(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    proto_item *endpoint_item=NULL;
    proto_tree *endpoint_tree=NULL;
    proto_item *ep_attrib_item=NULL;
    proto_tree *ep_attrib_tree=NULL;
    int old_offset=offset;
    guint8 endpoint;
    guint8 len;

    if(parent_tree){
        item=proto_tree_add_text(parent_tree, tvb, offset, -1, "ENDPOINT DESCRIPTOR");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
    }

    /* bLength */
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, TRUE);
    len = tvb_get_guint8(tvb, offset);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    offset++;

    /* bEndpointAddress */
    if(tree){
        endpoint_item=proto_tree_add_item(tree, hf_usb_bEndpointAddress, tvb, offset, 1, TRUE);
        endpoint_tree=proto_item_add_subtree(endpoint_item, ett_configuration_bEndpointAddress);
    }
    endpoint=tvb_get_guint8(tvb, offset)&0x0f;
    proto_tree_add_item(endpoint_tree, hf_usb_bEndpointAddress_direction, tvb, offset, 1, TRUE);
    proto_item_append_text(endpoint_item, "  %s", (tvb_get_guint8(tvb, offset)&0x80)?"IN":"OUT");
    proto_tree_add_item(endpoint_tree, hf_usb_bEndpointAddress_number, tvb, offset, 1, TRUE);
    proto_item_append_text(endpoint_item, "  Endpoint:%d", endpoint);
    offset++;

    /* Together with class from the interface descriptor we know what kind
     * of class the device at endpoint is.
     * Make sure a conversation exists for this endpoint and attach a
     * usb_conv_into_t structure to it.
     *
     * All endpoints for the same interface descriptor share the same
     * usb_conv_info structure.
     */
    if((!pinfo->fd->flags.visited)&&usb_trans_info->interface_info){
        conversation_t *conversation;

        if(pinfo->destport==NO_ENDPOINT){
            static address tmp_addr;
            static usb_address_t usb_addr;

            /* Create a new address structure that points to the same device
             * but the new endpoint.
             */
            usb_addr.device=((usb_address_t *)(pinfo->src.data))->device;
            usb_addr.endpoint=endpoint;
            SET_ADDRESS(&tmp_addr, AT_USB, USB_ADDR_LEN, (char *)&usb_addr);
            conversation=get_usb_conversation(pinfo, &tmp_addr, &pinfo->dst, endpoint, pinfo->destport);
        } else {
            static address tmp_addr;
            static usb_address_t usb_addr;

            /* Create a new address structure that points to the same device
             * but the new endpoint.
             */
            usb_addr.device=((usb_address_t *)(pinfo->dst.data))->device;
            usb_addr.endpoint=endpoint;
            SET_ADDRESS(&tmp_addr, AT_USB, USB_ADDR_LEN, (char *)&usb_addr);
            conversation=get_usb_conversation(pinfo, &pinfo->src, &tmp_addr, pinfo->srcport, endpoint);
        }

        conversation_add_proto_data(conversation, proto_usb, usb_trans_info->interface_info);
    }

    /* bmAttributes */
    if (tree) {
        ep_attrib_item=proto_tree_add_item(tree, hf_usb_bmAttributes, tvb, offset, 1, TRUE);
	ep_attrib_tree=proto_item_add_subtree(ep_attrib_item, ett_endpoint_bmAttributes);
    }
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeTransfer, tvb, offset, 1, TRUE);
    /* isochronous only */
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeSynchonisation, tvb, offset, 1, TRUE);
    /* isochronous only */
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeBehaviour, tvb, offset, 1, TRUE);
    offset++;

    /* wMaxPacketSize */
    proto_tree_add_item(tree, hf_usb_wMaxPacketSize, tvb, offset, 2, TRUE);
    offset+=2;

    /* bInterval */
    proto_tree_add_item(tree, hf_usb_bInterval, tvb, offset, 1, TRUE);
    offset++;

    if(item){
        proto_item_set_len(item, len);
    }
    if (offset != old_offset + len) {
        /* unknown records */
    }
    offset = old_offset + len;

    return offset;
}

static int
dissect_usb_unknown_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint8 bLength;

    if(parent_tree){
        item=proto_tree_add_text(parent_tree, tvb, offset, -1, "UNKNOWN DESCRIPTOR");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
    }

    /* bLength */
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, TRUE);
    bLength = tvb_get_guint8(tvb, offset);
    offset++;
    if (bLength < 3) {
        if(item){
            proto_item_set_len(item, offset-old_offset);
        }

        item = proto_tree_add_text(parent_tree, tvb, offset - 1, 1,
            "Invalid bLength: %u",  bLength);
        expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR,
            "Invalid bLength: %u",  bLength);

        return offset;
    }

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    offset++;

    offset += bLength - 2;

    if(item){
        proto_item_set_len(item, offset-old_offset);
    }

    return offset;
}

/* 9.6.3 */
static const true_false_string tfs_mustbeone = {
    "Must be 1 for USB 1.1 and higher",
    "FIXME: Is this a USB 1.0 device"
};
static const true_false_string tfs_selfpowered = {
    "This device is SELF-POWERED",
    "This device is powered from the USB bus"
};
static const true_false_string tfs_remotewakeup = {
    "This device supports REMOTE WAKEUP",
    "This device does NOT support remote wakeup"
};
static int
dissect_usb_configuration_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint16 len;
    proto_item *flags_item=NULL;
    proto_tree *flags_tree=NULL;
    guint8 flags;
    proto_item *power_item=NULL;
    guint8 power;

    if(parent_tree){
        item=proto_tree_add_text(parent_tree, tvb, offset, -1, "CONFIGURATION DESCRIPTOR");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
    }

    /* bLength */
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, TRUE);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    offset++;

    /* wTotalLength */
    proto_tree_add_item(tree, hf_usb_wTotalLength, tvb, offset, 2, TRUE);
    len=tvb_get_letohs(tvb, offset);
    offset+=2;

    /* bNumInterfaces */
    proto_tree_add_item(tree, hf_usb_bNumInterfaces, tvb, offset, 1, TRUE);
    offset++;

    /* bConfigurationValue */
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, TRUE);
    offset++;

    /* iConfiguration */
    proto_tree_add_item(tree, hf_usb_iConfiguration, tvb, offset, 1, TRUE);
    offset++;

    /* bmAttributes */
    if(tree){
        flags_item=proto_tree_add_item(tree, hf_usb_configuration_bmAttributes, tvb, offset, 1, TRUE);
        flags_tree=proto_item_add_subtree(flags_item, ett_configuration_bmAttributes);
    }
    flags=tvb_get_guint8(tvb, offset);
    proto_tree_add_item(flags_tree, hf_usb_configuration_legacy10buspowered, tvb, offset, 1, TRUE);
    proto_tree_add_item(flags_tree, hf_usb_configuration_selfpowered, tvb, offset, 1, TRUE);
    proto_item_append_text(flags_item, "  %sSELF-POWERED", (flags&0x40)?"":"NOT ");
    flags&=~0x40;
    proto_tree_add_item(flags_tree, hf_usb_configuration_remotewakeup, tvb, offset, 1, TRUE);
    proto_item_append_text(flags_item, "  %sREMOTE-WAKEUP", (flags&0x20)?"":"NO ");
    flags&=~0x20;
    offset++;

    /* bMaxPower */
    power_item=proto_tree_add_item(tree, hf_usb_bMaxPower, tvb, offset, 1, TRUE);
    power=tvb_get_guint8(tvb, offset);
    proto_item_append_text(power_item, "  (%dmA)", power*2);
    offset++;

    /* initialize interface_info to NULL */
    usb_trans_info->interface_info=NULL;

    /* decode any additional interface and endpoint descriptors */
    while(len>(old_offset-offset)){
        guint8 next_type;

        if(tvb_length_remaining(tvb, offset)<2){
            break;
        }
        next_type=tvb_get_guint8(tvb, offset+1);
        switch(next_type){
        case USB_DT_INTERFACE:
            offset=dissect_usb_interface_descriptor(pinfo, parent_tree, tvb, offset, usb_trans_info, usb_conv_info);
            break;
        case USB_DT_ENDPOINT:
            offset=dissect_usb_endpoint_descriptor(pinfo, parent_tree, tvb, offset, usb_trans_info, usb_conv_info);
            break;
        default:
            offset=dissect_usb_unknown_descriptor(pinfo, parent_tree, tvb, offset, usb_trans_info, usb_conv_info);
            break;
            /* was: return offset; */
        }
    }

    if(item){
        proto_item_set_len(item, offset-old_offset);
    }

    return offset;
}

/* 9.4.3 */
static int
dissect_usb_setup_get_descriptor_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info _U_)
{
    /* descriptor index */
    proto_tree_add_item(tree, hf_usb_descriptor_index, tvb, offset, 1, TRUE);
    usb_trans_info->u.get_descriptor.index=tvb_get_guint8(tvb, offset);
    offset++;

    /* descriptor type */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    usb_trans_info->u.get_descriptor.type=tvb_get_guint8(tvb, offset);
    offset++;
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
            val_to_str(usb_trans_info->u.get_descriptor.type, descriptor_type_vals, "Unknown type %u"));
    }

    /* language id */
    proto_tree_add_item(tree, hf_usb_language_id, tvb, offset, 2, TRUE);
    offset+=2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_get_descriptor_response(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info)
{
    proto_item *item=NULL;
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
            val_to_str(usb_trans_info->u.get_descriptor.type, descriptor_type_vals, "Unknown type %u"));
    }
    switch(usb_trans_info->u.get_descriptor.type){
    case USB_DT_DEVICE:
        offset=dissect_usb_device_descriptor(pinfo, tree, tvb, offset, usb_trans_info, usb_conv_info);
        break;
    case USB_DT_CONFIG:
        offset=dissect_usb_configuration_descriptor(pinfo, tree, tvb, offset, usb_trans_info, usb_conv_info);
        break;
    case USB_DT_STRING:
        offset=dissect_usb_string_descriptor(pinfo, tree, tvb, offset, usb_trans_info, usb_conv_info);
        break;
    case USB_DT_INTERFACE:
        offset=dissect_usb_interface_descriptor(pinfo, tree, tvb, offset, usb_trans_info, usb_conv_info);
        break;
    case USB_DT_ENDPOINT:
        offset=dissect_usb_endpoint_descriptor(pinfo, tree, tvb, offset, usb_trans_info, usb_conv_info);
        break;
    case USB_DT_DEVICE_QUALIFIER:
        offset=dissect_usb_device_qualifier_descriptor(pinfo, tree, tvb, offset, usb_trans_info, usb_conv_info);
        break;
    case USB_DT_RPIPE:
        if (usb_conv_info->interfaceClass == IF_CLASS_HID) {
        	offset=dissect_usb_hid_get_report_descriptor(pinfo, tree, tvb, offset, usb_trans_info, usb_conv_info);
        	break;
        }
        /* else fall through as default/unknown */
    default:
        /* XXX dissect the descriptor coming back from the device */
        item=proto_tree_add_text(tree, tvb, offset, -1, "GET DESCRIPTOR data (unknown descriptor type)");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
        proto_tree_add_item(tree, hf_usb_data, tvb, offset, pinfo->pseudo_header->linux_usb.data_len, FALSE);
        offset += pinfo->pseudo_header->linux_usb.data_len;
        break;
    }

    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / GET INTERFACE
 */


/* 9.4.4 */
static int
dissect_usb_setup_get_interface_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* zero */
    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, TRUE);
    offset += 2;

    /* interface */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, TRUE);
    offset += 2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_get_interface_response(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* alternate setting */
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, TRUE);
    offset++;

    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / GET STATUS
 */


/* 9.4.5 */
static int
dissect_usb_setup_get_status_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* zero */
    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, TRUE);
    offset += 2;

    /* zero/interface/endpoint */
    /* XXX - check based on request type */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, TRUE);
    offset += 2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_get_status_response(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* status */
    /* XXX - show bits */
    proto_tree_add_item(tree, hf_usb_wStatus, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SET ADDRESS
 */


/* 9.4.6 */
static int
dissect_usb_setup_set_address_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* device address */
    proto_tree_add_item(tree, hf_usb_device_address, tvb, offset, 2, TRUE);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, TRUE);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_set_address_response(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SET CONFIGURATION
 */


/* 9.4.7 */
static int
dissect_usb_setup_set_configuration_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* configuration value */
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, TRUE);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, TRUE);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_set_configuration_response(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SET FEATURE
 */


/* 9.4.9 */
static int
dissect_usb_setup_set_feature_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* feature selector */
    proto_tree_add_item(tree, hf_usb_wFeatureSelector, tvb, offset, 2, TRUE);
    offset += 2;

    /* zero/interface/endpoint or test selector */
    /* XXX - check based on request type */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, TRUE);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_set_feature_response(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SET INTERFACE
 */


/* 9.4.10 */
static int
dissect_usb_setup_set_interface_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* alternate setting */
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, TRUE);
    offset += 2;

    /* interface */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, TRUE);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_set_interface_response(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SYNCH FRAME
 */


/* 9.4.11 */
static int
dissect_usb_setup_synch_frame_request(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* zero */
    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, TRUE);
    offset += 2;

    /* endpoint */
    /* XXX */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, TRUE);
    offset += 2;

    /* two */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_synch_frame_response(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* frame number */
    proto_tree_add_item(tree, hf_usb_wFrameNumber, tvb, offset, 2, TRUE);
    offset += 2;

    return offset;
}


typedef int (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info);

typedef struct _usb_setup_dissector_table_t {
    guint8 request;
    usb_setup_dissector dissector;
} usb_setup_dissector_table_t;
#define USB_SETUP_GET_STATUS		0
#define USB_SETUP_CLEAR_FEATURE		1
#define USB_SETUP_SET_FEATURE		2
#define USB_SETUP_SET_ADDRESS		5
#define USB_SETUP_GET_DESCRIPTOR	6
#define USB_SETUP_SET_DESCRIPTOR	7
#define USB_SETUP_GET_CONFIGURATION	8
#define USB_SETUP_SET_CONFIGURATION	9
#define USB_SETUP_GET_INTERFACE		10
#define USB_SETUP_SET_INTERFACE		11
#define USB_SETUP_SYNCH_FRAME		12

static const usb_setup_dissector_table_t setup_request_dissectors[] = {
    {USB_SETUP_GET_STATUS,	dissect_usb_setup_get_status_request},
    {USB_SETUP_CLEAR_FEATURE,	dissect_usb_setup_clear_feature_request},
    {USB_SETUP_SET_FEATURE,	dissect_usb_setup_set_feature_request},
    {USB_SETUP_SET_ADDRESS,	dissect_usb_setup_set_address_request},
    {USB_SETUP_GET_DESCRIPTOR,	dissect_usb_setup_get_descriptor_request},
    {USB_SETUP_SET_CONFIGURATION, dissect_usb_setup_set_configuration_request},
    {USB_SETUP_GET_INTERFACE,	dissect_usb_setup_get_interface_request},
    {USB_SETUP_SET_INTERFACE,	dissect_usb_setup_set_interface_request},
    {USB_SETUP_SYNCH_FRAME,	dissect_usb_setup_synch_frame_request},
    {0, NULL}
};

static const usb_setup_dissector_table_t setup_response_dissectors[] = {
    {USB_SETUP_GET_STATUS,	dissect_usb_setup_get_status_response},
    {USB_SETUP_CLEAR_FEATURE,	dissect_usb_setup_clear_feature_response},
    {USB_SETUP_SET_FEATURE,	dissect_usb_setup_set_feature_response},
    {USB_SETUP_SET_ADDRESS,	dissect_usb_setup_set_address_response},
    {USB_SETUP_GET_DESCRIPTOR,	dissect_usb_setup_get_descriptor_response},
    {USB_SETUP_GET_CONFIGURATION, dissect_usb_setup_get_configuration_response},
    {USB_SETUP_SET_CONFIGURATION, dissect_usb_setup_set_configuration_response},
    {USB_SETUP_GET_INTERFACE,	dissect_usb_setup_get_interface_response},
    {USB_SETUP_SET_INTERFACE,	dissect_usb_setup_set_interface_response},
    {USB_SETUP_SYNCH_FRAME,	dissect_usb_setup_synch_frame_response},
    {0, NULL}
};

/* bRequest values but only when bmRequestType.type == 0 (Device) */
static const value_string setup_request_names_vals[] = {
    {USB_SETUP_GET_STATUS,		"GET STATUS"},
    {USB_SETUP_CLEAR_FEATURE,		"CLEAR FEATURE"},
    {USB_SETUP_SET_FEATURE,		"SET FEATURE"},
    {USB_SETUP_SET_ADDRESS,		"SET ADDRESS"},
    {USB_SETUP_GET_DESCRIPTOR,		"GET DESCRIPTOR"},
    {USB_SETUP_SET_DESCRIPTOR,		"SET DESCRIPTOR"},
    {USB_SETUP_GET_CONFIGURATION,	"GET CONFIGURATION"},
    {USB_SETUP_SET_CONFIGURATION,	"SET CONFIGURATION"},
    {USB_SETUP_GET_INTERFACE,		"GET INTERFACE"},
    {USB_SETUP_SET_INTERFACE,		"SET INTERFACE"},
    {USB_SETUP_SYNCH_FRAME,		"SYNCH FRAME"},
    {0, NULL}
};


static const true_false_string tfs_bmrequesttype_direction = {
	"Device-to-host",
	"Host-to-device"
};

static const value_string bmrequesttype_type_vals[] = {
    {RQT_SETUP_TYPE_STANDARD, "Standard"},
    {RQT_SETUP_TYPE_CLASS,    "Class"},
    {RQT_SETUP_TYPE_VENDOR,   "Vendor"},
    {0, NULL}
};

static const value_string bmrequesttype_recipient_vals[] = {
    { RQT_SETUP_RECIPIENT_DEVICE, "Device" },
    { RQT_SETUP_RECIPIENT_INTERFACE, "Interface" },
    { RQT_SETUP_RECIPIENT_INTERFACE, "Endpoint" },
    { RQT_SETUP_RECIPIENT_INTERFACE, "Other" },
    { 0, NULL }
};

static int
dissect_usb_bmrequesttype(proto_tree *parent_tree, tvbuff_t *tvb, int offset,
    int *type)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint8 bmRequestType;

	if(parent_tree){
	        item=proto_tree_add_item(parent_tree, hf_usb_bmRequestType, tvb, offset, 1, TRUE);
		tree = proto_item_add_subtree(item, ett_usb_setup_bmrequesttype);
	}

	bmRequestType = tvb_get_guint8(tvb, offset);
	*type = (bmRequestType & USB_TYPE_MASK) >>5;
	proto_tree_add_item(tree, hf_usb_bmRequestType_direction, tvb, offset, 1, TRUE);
	proto_tree_add_item(tree, hf_usb_bmRequestType_type, tvb, offset, 1, TRUE);
	proto_tree_add_item(tree, hf_usb_bmRequestType_recipient, tvb, offset, 1, TRUE);

	offset++;
	return offset;
}

static void
dissect_linux_usb_pseudo_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 transfer_type;
    const gchar* val_str;

    proto_tree_add_uint64(tree, hf_usb_urb_id, tvb, 0, 0,
                          pinfo->pseudo_header->linux_usb.id);

    /* show the event type of this URB as string and as a character */
    val_str = val_to_str(pinfo->pseudo_header->linux_usb.event_type,
        usb_urb_type_vals, "Unknown %d");
    proto_tree_add_string_format_value(tree, hf_usb_urb_type, tvb, 0, 0,
        &(pinfo->pseudo_header->linux_usb.event_type),
        "%s ('%c')", val_str,
        pinfo->pseudo_header->linux_usb.event_type);

    transfer_type = pinfo->pseudo_header->linux_usb.transfer_type;
    proto_tree_add_uint(tree, hf_usb_transfer_type, tvb, 0, 0, transfer_type);

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO,
            val_to_str(transfer_type, usb_transfer_type_vals, "Unknown type %x"));
    }

    proto_tree_add_uint(tree, hf_usb_endpoint_number, tvb, 0, 0,
                        pinfo->pseudo_header->linux_usb.endpoint_number);

    proto_tree_add_uint(tree, hf_usb_device_address, tvb, 0, 0,
                        pinfo->pseudo_header->linux_usb.device_address);

    proto_tree_add_uint(tree, hf_usb_bus_id, tvb, 0, 0,
                        pinfo->pseudo_header->linux_usb.bus_id);

    /* Right after the pseudo header we always have
     * sizeof(struct usb_device_setup_hdr)=8 bytes. The content of these
     * bytes have only meaning in case setup_flag == 0.
     */
    if (pinfo->pseudo_header->linux_usb.setup_flag == 0) {
        proto_tree_add_string_format_value(tree, hf_usb_setup_flag, tvb,
            0, 0,
            &(pinfo->pseudo_header->linux_usb.setup_flag),
            "present (%d)",
            pinfo->pseudo_header->linux_usb.setup_flag);
    } else {
        proto_tree_add_string_format_value(tree, hf_usb_setup_flag, tvb,
            0, 0,
            &(pinfo->pseudo_header->linux_usb.setup_flag),
            "not present ('%c')",
            pinfo->pseudo_header->linux_usb.setup_flag);
    }

    if (pinfo->pseudo_header->linux_usb.data_flag == 0) {
        proto_tree_add_string_format_value(tree, hf_usb_data_flag, tvb,
            0, 0,
            &(pinfo->pseudo_header->linux_usb.data_flag),
            "present (%d)",
            pinfo->pseudo_header->linux_usb.data_flag);
    } else {
        proto_tree_add_string_format_value(tree, hf_usb_data_flag, tvb,
            0, 0,
            &(pinfo->pseudo_header->linux_usb.data_flag),
            "not present ('%c')",
            pinfo->pseudo_header->linux_usb.data_flag);
    }

    /* Timestamp was already processed by libpcap,
     * skip it for now:
     *   pinfo->pseudo_header->linux_usb.ts_sec
     *   pinfo->pseudo_header->linux_usb.ts_usec
     */

    proto_tree_add_int(tree, hf_usb_urb_status, tvb, 0, 0,
                        pinfo->pseudo_header->linux_usb.status);

    proto_tree_add_uint(tree, hf_usb_urb_len, tvb, 0, 0,
                        pinfo->pseudo_header->linux_usb.urb_len);

    proto_tree_add_uint(tree, hf_usb_data_len, tvb, 0, 0,
                        pinfo->pseudo_header->linux_usb.data_len);

}

static void
dissect_linux_usb_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent,
                         gboolean padded)
{
    unsigned int offset = 0;
    int type, endpoint;
    guint8 setup_flag;
    proto_tree *tree = NULL;
    guint32 src_device, dst_device, tmp_addr;
    static usb_address_t src_addr, dst_addr; /* has to be static due to SET_ADDRESS */
    guint32 src_endpoint, dst_endpoint;
    gboolean is_request=FALSE;
    usb_conv_info_t *usb_conv_info=NULL;
    usb_trans_info_t *usb_trans_info=NULL;
    conversation_t *conversation;
    usb_tap_data_t *tap_data=NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USB");

    /* add usb hdr*/
    if (parent) {
      proto_item *ti = NULL;
      ti = proto_tree_add_protocol_format(parent, proto_usb, tvb, 0, sizeof(struct usb_device_setup_hdr), "USB URB");

      tree = proto_item_add_subtree(ti, usb_hdr);
    }

    dissect_linux_usb_pseudo_header(tvb, pinfo, tree);

    type = pinfo->pseudo_header->linux_usb.transfer_type;

    endpoint = pinfo->pseudo_header->linux_usb.endpoint_number & (~URB_TRANSFER_IN);

    tmp_addr = pinfo->pseudo_header->linux_usb.device_address;
    setup_flag = pinfo->pseudo_header->linux_usb.setup_flag;

    is_request = (pinfo->pseudo_header->linux_usb.event_type == URB_SUBMIT) ? TRUE : FALSE;

    /* Set up addresses and ports. */
    if (is_request) {
        src_addr.device = src_device = 0xffffffff;
        src_addr.endpoint = src_endpoint = NO_ENDPOINT;
        dst_addr.device = dst_device = htolel(tmp_addr);
        dst_addr.endpoint = dst_endpoint = htolel(endpoint);
    } else {
        src_addr.device = src_device = htolel(tmp_addr);
        src_addr.endpoint = src_endpoint = htolel(endpoint);
        dst_addr.device = dst_device = 0xffffffff;
        dst_addr.endpoint = dst_endpoint = NO_ENDPOINT;
    }

    SET_ADDRESS(&pinfo->net_src, AT_USB, USB_ADDR_LEN, (char *)&src_addr);
    SET_ADDRESS(&pinfo->src, AT_USB, USB_ADDR_LEN, (char *)&src_addr);
    SET_ADDRESS(&pinfo->net_dst, AT_USB, USB_ADDR_LEN, (char *)&dst_addr);
    SET_ADDRESS(&pinfo->dst, AT_USB, USB_ADDR_LEN, (char *)&dst_addr);
    pinfo->ptype=PT_USB;
    pinfo->srcport=src_endpoint;
    pinfo->destport=dst_endpoint;

    conversation=get_usb_conversation(pinfo, &pinfo->src, &pinfo->dst, pinfo->srcport, pinfo->destport);

    usb_conv_info=get_usb_conv_info(conversation);
    pinfo->usb_conv_info=usb_conv_info;


    /* request/response matching so we can keep track of transaction specific
     * data.
     */
    if(is_request){
        /* this is a request */
        usb_trans_info=se_tree_lookup32(usb_conv_info->transactions, pinfo->fd->num);
        if(!usb_trans_info){
            usb_trans_info=se_alloc0(sizeof(usb_trans_info_t));
            usb_trans_info->request_in=pinfo->fd->num;
            usb_trans_info->req_time=pinfo->fd->abs_ts;
            se_tree_insert32(usb_conv_info->transactions, pinfo->fd->num, usb_trans_info);
        }
        usb_conv_info->usb_trans_info=usb_trans_info;

        if(usb_trans_info && usb_trans_info->response_in){
            proto_item *ti;

            ti=proto_tree_add_uint(tree, hf_usb_response_in, tvb, 0, 0, usb_trans_info->response_in);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    } else {
        /* this is a response */
        if(pinfo->fd->flags.visited){
            usb_trans_info=se_tree_lookup32(usb_conv_info->transactions, pinfo->fd->num);
        } else {
            usb_trans_info=se_tree_lookup32_le(usb_conv_info->transactions, pinfo->fd->num);
            if(usb_trans_info){
                usb_trans_info->response_in=pinfo->fd->num;
                se_tree_insert32(usb_conv_info->transactions, pinfo->fd->num, usb_trans_info);
            }
        }
        usb_conv_info->usb_trans_info=usb_trans_info;

        if(usb_trans_info && usb_trans_info->request_in){
            proto_item *ti;
            nstime_t t, deltat;

            ti=proto_tree_add_uint(tree, hf_usb_request_in, tvb, 0, 0, usb_trans_info->request_in);
            PROTO_ITEM_SET_GENERATED(ti);

            t = pinfo->fd->abs_ts;
            nstime_delta(&deltat, &t, &usb_trans_info->req_time);
            ti=proto_tree_add_time(tree, hf_usb_time, tvb, 0, 0, &deltat);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }

    tap_data=ep_alloc(sizeof(usb_tap_data_t));
    tap_data->urb_type=(guint8)pinfo->pseudo_header->linux_usb.event_type;
    tap_data->transfer_type=(guint8)type;
    tap_data->conv_info=usb_conv_info;
    tap_data->trans_info=usb_trans_info;
    tap_queue_packet(usb_tap, pinfo, tap_data);

    switch(type){
    case URB_BULK:
    case URB_BULK | URB_TRANSFER_IN:
        {
        proto_item *item;

        item=proto_tree_add_uint(tree, hf_usb_bInterfaceClass, tvb, 0, 0, usb_conv_info->interfaceClass);
        PROTO_ITEM_SET_GENERATED(item);

        /* Skip setup header - it's never present */
        offset += 8;

        /*
         * If this is padded (as is the case if the capture is done in
         * memory-mapped mode), skip the padding; it's padded to a multiple
         * of 64 bits *after* the pseudo-header and setup header.  The
         * pseudo-header is 40 bytes, and the setup header is 8 bytes,
         * so that's 16 bytes of padding to 64 bytes.  (The pseudo-header
         * was removed from the packet data by Wiretap, so the offset
         * is relative to the beginning of the setup header, not relative
         * to the beginning of the raw packet data, so we can't just
         * round it up to a multiple of 64.)
         */
        if (padded)
            offset += 16;

        if(tvb_reported_length_remaining(tvb, offset)){
            tvbuff_t *next_tvb;

            pinfo->usb_conv_info=usb_conv_info;
            next_tvb=tvb_new_subset_remaining(tvb, offset);
            if(dissector_try_port(usb_bulk_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, parent)){
                return;
            }
        }
        }
        break;
    case URB_CONTROL:
    case URB_CONTROL | URB_TRANSFER_IN:
        {
        const usb_setup_dissector_table_t *tmp;
        usb_setup_dissector dissector;
        proto_item *ti = NULL;
        proto_tree *setup_tree = NULL;
        int type;

        ti=proto_tree_add_uint(tree, hf_usb_bInterfaceClass, tvb, offset, 0, usb_conv_info->interfaceClass);
        PROTO_ITEM_SET_GENERATED(ti);

        if(is_request){
            if (setup_flag == 0) {
                tvbuff_t *next_tvb;

                /* this is a request */

                /* Dissect the setup header - it's present */

                ti = proto_tree_add_protocol_format(tree, proto_usb, tvb, offset, sizeof(struct usb_device_setup_hdr), "URB setup");
                setup_tree = proto_item_add_subtree(ti, usb_setup_hdr);
                usb_trans_info->requesttype=tvb_get_guint8(tvb, offset);
                offset=dissect_usb_bmrequesttype(setup_tree, tvb, offset, &type);


                /* read the request code and spawn off to a class specific
                 * dissector if found
                 */
                usb_trans_info->request=tvb_get_guint8(tvb, offset);

                switch (type) {

                case RQT_SETUP_TYPE_STANDARD:
                    /*
                     * This is a standard request which is managed by this
                     * dissector
                     */
                    proto_tree_add_item(setup_tree, hf_usb_request, tvb, offset, 1, TRUE);
                    offset += 1;

                    if (check_col(pinfo->cinfo, COL_INFO)) {
                        col_clear(pinfo->cinfo, COL_INFO);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s Request",
                             val_to_str(usb_trans_info->request, setup_request_names_vals, "Unknown type %x"));
                    }

                    dissector=NULL;
                    for(tmp=setup_request_dissectors;tmp->dissector;tmp++){
                        if(tmp->request==usb_trans_info->request){
                            dissector=tmp->dissector;
                            break;
                        }
                    }

                    if(dissector){
                        offset=dissector(pinfo, setup_tree, tvb, offset, usb_trans_info, usb_conv_info);
                    } else {
                        proto_tree_add_item(setup_tree, hf_usb_value, tvb, offset, 2, TRUE);
                        offset += 2;
                        proto_tree_add_item(setup_tree, hf_usb_index, tvb, offset, 2, TRUE);
                        offset += 2;
                        proto_tree_add_item(setup_tree, hf_usb_length, tvb, offset, 2, TRUE);
                        offset += 2;
                    }

                    /*
                     * If this is padded (as is the case if the capture
                     * is done in memory-mapped mode), skip the padding;
                     * it's padded to a multiple of 64 bits *after* the
                     * pseudo-header and setup header.  The pseudo-header
                     * is 40 bytes, and the setup header is 8 bytes, so
                     * that's 16 bytes of padding to 64 bytes.  (The
                     * pseudo-header was removed from the packet data by
                     * Wiretap, so the offset is relative to the beginning
                     * of the setup header, not relative to the beginning
                     * of the raw packet data, so we can't just round it up
                     * to a multiple of 64.)
                     */
                    if (padded)
                        offset += 16;

                    break;

                case RQT_SETUP_TYPE_CLASS:
                    /* Try to find a class specific dissector */
                    next_tvb=tvb_new_subset_remaining(tvb, offset);
                    if(dissector_try_port(usb_control_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, tree)){
                        return;
                    }
                    /* Else no class dissector, just display generic fields */
                    proto_tree_add_item(setup_tree, hf_usb_request_unknown_class, tvb, offset, 1, TRUE);
                    offset += 1;
                    proto_tree_add_item(setup_tree, hf_usb_value, tvb, offset, 2, TRUE);
                    offset += 2;
                    proto_tree_add_item(setup_tree, hf_usb_index, tvb, offset, 2, TRUE);
                    offset += 2;
                    proto_tree_add_item(setup_tree, hf_usb_length, tvb, offset, 2, TRUE);
                    offset += 2;
                    break;
                }
            } else {
                /* Skip setup header - it's not present */

                offset += 8;

                /*
                 * If this is padded (as is the case if the capture is done
                 * in memory-mapped mode), skip the padding; it's padded to
                 * a multiple of 64 bits *after* the pseudo-header and setup
                 * header.  The pseudo-header is 40 bytes, and the setup
                 * header is 8 bytes, so that's 16 bytes of padding to 64
                 * bytes.  (The pseudo-header was removed from the packet
                 * data by Wiretap, so the offset is relative to the beginning
                 * of the setup header, not relative to the beginning of the
                 * raw packet data, so we can't just round it up to a multiple
                 * of 64.)
                 */
                if (padded)
                    offset += 16;
            }
        } else {
            tvbuff_t *next_tvb;

            /* this is a response */

            /* Skip setup header - it's never present for responses */
            offset += 8;

            /*
             * If this is padded (as is the case if the capture is done in
             * memory-mapped mode), skip the padding; it's padded to a multiple
             * of 64 bits *after* the pseudo-header and setup header.  The
             * pseudo-header is 40 bytes, and the setup header is 8 bytes,
             * so that's 16 bytes of padding to 64 bytes.  (The pseudo-header
             * was removed from the packet data by Wiretap, so the offset
             * is relative to the beginning of the setup header, not relative
             * to the beginning of the raw packet data, so we can't just
             * round it up to a multiple of 64.)
             */
            if (padded)
                offset += 16;

            if(usb_trans_info){
                /* Try to find a class specific dissector */
                next_tvb=tvb_new_subset_remaining(tvb, offset);
                if(dissector_try_port(usb_control_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, tree)){
                    return;
                }

                type = (usb_trans_info->requesttype & USB_TYPE_MASK) >>5;
                switch (type) {

                case RQT_SETUP_TYPE_STANDARD:
                    /*
                     * This is a standard response which is managed by this
                     * dissector
                     */
                    if (check_col(pinfo->cinfo, COL_INFO)) {
                        col_clear(pinfo->cinfo, COL_INFO);
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s Response",
                            val_to_str(usb_conv_info->usb_trans_info->request, setup_request_names_vals, "Unknown type %x"));
                    }

                    dissector=NULL;
                    for(tmp=setup_response_dissectors;tmp->dissector;tmp++){
                        if(tmp->request==usb_conv_info->usb_trans_info->request){
                            dissector=tmp->dissector;
                            break;
                        }
                    }

                    if(dissector){
                        offset = dissector(pinfo, tree, tvb, offset, usb_conv_info->usb_trans_info, usb_conv_info);
                    } else {
                        if (tvb_reported_length_remaining(tvb, offset) != 0) {
                            proto_tree_add_text(tree, tvb, offset, -1, "CONTROL response data");
                            offset += tvb_length_remaining(tvb, offset);
                        }
                    }
                    break;
                default:
                    if (tvb_reported_length_remaining(tvb, offset) != 0) {
                        proto_tree_add_text(tree, tvb, offset, -1, "CONTROL response data");
                        offset += tvb_length_remaining(tvb, offset);
                    }
                    break;
                }
            } else {
                /* no matching request available */
                if (tvb_reported_length_remaining(tvb, offset) != 0) {
                    proto_tree_add_text(tree, tvb, offset, -1, "CONTROL response data");
                    offset += tvb_length_remaining(tvb, offset);
                }
            }
        }
        }
        break;
    default:
        /* dont know */
        if (setup_flag == 0) {
            proto_item *ti = NULL;
            proto_tree *setup_tree = NULL;
            guint8 requesttype, request;
            int type;

            /* Dissect the setup header - it's present */

            ti = proto_tree_add_protocol_format(tree, proto_usb, tvb, offset, sizeof(struct usb_device_setup_hdr), "URB setup");
            setup_tree = proto_item_add_subtree(ti, usb_setup_hdr);


            requesttype=tvb_get_guint8(tvb, offset);
            offset=dissect_usb_bmrequesttype(setup_tree, tvb, offset, &type);

            request=tvb_get_guint8(tvb, offset);
            proto_tree_add_item(setup_tree, hf_usb_request, tvb, offset, 1, TRUE);
            offset += 1;

            proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, TRUE);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, TRUE);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, TRUE);
            offset += 2;
        } else {
            /* Skip setup header - it's not present */

            offset += 8;
        }

        /*
         * If this is padded (as is the case if the capture is done in
         * memory-mapped mode), skip the padding; it's padded to a multiple
         * of 64 bits *after* the pseudo-header and setup header.  The
         * pseudo-header is 40 bytes, and the setup header is 8 bytes,
         * so that's 16 bytes of padding to 64 bytes.  (The pseudo-header
         * was removed from the packet data by Wiretap, so the offset
         * is relative to the beginning of the setup header, not relative
         * to the beginning of the raw packet data, so we can't just
         * round it up to a multiple of 64.)
         */
        if (padded)
            offset += 16;

        break;
    }

    if (tvb_reported_length_remaining(tvb, offset) != 0) {
        /* There is leftover capture data to add (padding?) */
        proto_tree_add_item(tree, hf_usb_capdata, tvb, offset, -1, FALSE);
    }
}

static void
dissect_linux_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent)
{
    dissect_linux_usb_common(tvb, pinfo, parent, FALSE);
}

static void
dissect_linux_usb_mmapped(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent)
{
    dissect_linux_usb_common(tvb, pinfo, parent, TRUE);
}

void
proto_register_usb(void)
{
    static hf_register_info hf[] = {

    /* USB packet pseudoheader members */
        { &hf_usb_urb_id,
        { "URB id", "usb.urb_id", FT_UINT64, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_urb_type,
        { "URB type", "usb.urb_type", FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_transfer_type,
        { "URB transfer type", "usb.transfer_type", FT_UINT8, BASE_HEX,
                VALS(usb_transfer_type_vals), 0x0,
                NULL, HFILL }},

        { &hf_usb_endpoint_number,
        { "Endpoint", "usb.endpoint_number", FT_UINT8, BASE_HEX, NULL, 0x0,
                "USB endpoint number", HFILL }},

        { &hf_usb_device_address,
        { "Device", "usb.device_address", FT_UINT8, BASE_DEC, NULL, 0x0,
                "USB device address", HFILL }},

        { &hf_usb_bus_id,
        { "URB bus id", "usb.bus_id", FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_setup_flag,
        { "Device setup request", "usb.setup_flag", FT_STRING, BASE_NONE,
                 NULL, 0x0,
                 "USB device setup request is present (0) or not", HFILL }},

        { &hf_usb_data_flag,
        { "Data", "usb.data_flag", FT_STRING, BASE_NONE,
                 NULL, 0x0,
                 "USB data is present (0) or not", HFILL }},

        { &hf_usb_urb_status,
        { "URB status", "usb.urb_status", FT_INT32, BASE_DEC,
                VALS(usb_urb_status_vals), 0x0,
                NULL, HFILL }},

        { &hf_usb_urb_len,
        { "URB length [bytes]", "usb.urb_len", FT_UINT32, BASE_DEC, NULL, 0x0,
                "URB length in bytes", HFILL }},

        { &hf_usb_data_len,
        { "Data length [bytes]", "usb.data_len", FT_UINT32, BASE_DEC, NULL, 0x0,
                "URB data length in bytes", HFILL }},

    /* Generated values */
        { &hf_usb_src_endpoint_number,
        { "Src Endpoint", "usb.src.endpoint", FT_UINT8, BASE_HEX, NULL, 0x0,
                "Source USB endpoint number", HFILL }},

        { &hf_usb_dst_endpoint_number,
        { "Dst Endpoint", "usb.dst.endpoint", FT_UINT8, BASE_HEX, NULL, 0x0,
                "Destination USB endpoint number", HFILL }},

    /* Fields from usb20.pdf, Table 9-2 'Format of Setup Data' */
        { &hf_usb_bmRequestType,
        { "bmRequestType", "usb.bmRequestType", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_request,
        { "bRequest", "usb.setup.bRequest", FT_UINT8, BASE_DEC, VALS(setup_request_names_vals), 0x0,
                NULL, HFILL }},

        /* Same as hf_usb_request but no descriptive text */
        { &hf_usb_request_unknown_class,
        { "bRequest", "usb.setup.bRequest", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_value,
        { "wValue", "usb.setup.wValue", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_index,
        { "wIndex", "usb.setup.wIndex", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_length,
        { "wLength", "usb.setup.wLength", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_usb_wFeatureSelector,
        { "wFeatureSelector", "usb.setup.wFeatureSelector", FT_UINT16, BASE_DEC,
	   VALS(usb_feature_selector_vals), 0x0, NULL, HFILL }},

        { &hf_usb_wInterface,
        { "wInterface", "usb.setup.wInterface", FT_UINT16, BASE_DEC,
	   NULL, 0x0, NULL, HFILL }},

        { &hf_usb_wStatus,
        { "wStatus", "usb.setup.wStatus", FT_UINT16, BASE_HEX,
	   NULL, 0x0, NULL, HFILL }},

        { &hf_usb_wFrameNumber,
        { "wFrameNumber", "usb.setup.wFrameNumber", FT_UINT16, BASE_DEC,
	   NULL, 0x0, NULL, HFILL }},

    /* --------------------------------- */
        { &hf_usb_data,
        {"Application Data", "usb.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Payload is application data", HFILL }},

        { &hf_usb_capdata,
        {"Leftover Capture Data", "usb.capdata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Padding added by the USB capture system", HFILL }},

        { &hf_usb_bmRequestType_direction,
        { "Direction", "usb.bmRequestType.direction", FT_BOOLEAN, 8,
          TFS(&tfs_bmrequesttype_direction), USB_DIR_IN, NULL, HFILL }},

        { &hf_usb_bmRequestType_type,
        { "Type", "usb.bmRequestType.type", FT_UINT8, BASE_HEX,
          VALS(bmrequesttype_type_vals), USB_TYPE_MASK, NULL, HFILL }},

        { &hf_usb_bmRequestType_recipient,
        { "Recipient", "usb.bmRequestType.recipient", FT_UINT8, BASE_HEX,
          VALS(bmrequesttype_recipient_vals), 0x1f, NULL, HFILL }},

        { &hf_usb_bDescriptorType,
        { "bDescriptorType", "usb.bDescriptorType", FT_UINT8, BASE_DEC,
          VALS(descriptor_type_vals), 0x0, NULL, HFILL }},

        { &hf_usb_descriptor_index,
        { "Descriptor Index", "usb.DescriptorIndex", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_language_id,
        { "Language Id", "usb.LanguageId", FT_UINT16, BASE_HEX,
          VALS(usb_langid_vals), 0x0, NULL, HFILL }},

        { &hf_usb_bLength,
        { "bLength", "usb.bLength", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bcdUSB,
        { "bcdUSB", "usb.bcdUSB", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bDeviceClass,
        { "bDeviceClass", "usb.bDeviceClass", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bDeviceSubClass,
        { "bDeviceSubClass", "usb.bDeviceSubClass", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bDeviceProtocol,
        { "bDeviceProtocol", "usb.bDeviceProtocol", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bMaxPacketSize0,
        { "bMaxPacketSize0", "usb.bMaxPacketSize0", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_idVendor,
        { "idVendor", "usb.idVendor", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_idProduct,
        { "idProduct", "usb.idProduct", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bcdDevice,
        { "bcdDevice", "usb.bcdDevice", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_iManufacturer,
        { "iManufacturer", "usb.iManufacturer", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_iProduct,
        { "iProduct", "usb.iProduct", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_iSerialNumber,
        { "iSerialNumber", "usb.iSerialNumber", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bNumConfigurations,
        { "bNumConfigurations", "usb.bNumConfigurations", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_wLANGID,
        { "wLANGID", "usb.wLANGID", FT_UINT16, BASE_HEX,
          VALS(usb_langid_vals), 0x0, NULL, HFILL }},

        { &hf_usb_bString,
        { "bString", "usb.bString", FT_STRING, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bInterfaceNumber,
        { "bInterfaceNumber", "usb.bInterfaceNumber", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bAlternateSetting,
        { "bAlternateSetting","usb.bAlternateSetting", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bNumEndpoints,
        { "bNumEndpoints","usb.bNumEndpoints", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bInterfaceClass,
        { "bInterfaceClass", "usb.bInterfaceClass", FT_UINT8, BASE_HEX,
          VALS(usb_interfaceclass_vals), 0x0, NULL, HFILL }},

        { &hf_usb_bInterfaceSubClass,
        { "bInterfaceSubClass", "usb.bInterfaceSubClass", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol,
        { "bInterfaceProtocol", "usb.bInterfaceProtocol", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_iInterface,
        { "iInterface", "usb.iInterface", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bEndpointAddress,
        { "bEndpointAddress", "usb.bEndpointAddress", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_configuration_bmAttributes,
        { "Configuration bmAttributes", "usb.configuration.bmAttributes", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bmAttributes,
        { "bmAttributes", "usb.bmAttributes", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bEndpointAttributeTransfer,
        { "Transfertype", "usb.bmAttributes.transfer", FT_UINT8, BASE_HEX,
          VALS(usb_bmAttributes_transfer_vals), 0x03, NULL, HFILL }},

        { &hf_usb_bEndpointAttributeSynchonisation,
        { "Synchronisationtype", "usb.bmAttributes.sync", FT_UINT8, BASE_HEX,
          VALS(usb_bmAttributes_sync_vals), 0x0c, NULL, HFILL }},

        { &hf_usb_bEndpointAttributeBehaviour,
        { "Behaviourtype", "usb.bmAttributes.behaviour", FT_UINT8, BASE_HEX,
          VALS(usb_bmAttributes_behaviour_vals), 0x30, NULL, HFILL }},

        { &hf_usb_wMaxPacketSize,
        { "wMaxPacketSize", "usb.wMaxPacketSize", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bInterval,
        { "bInterval", "usb.bInterval", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_wTotalLength,
        { "wTotalLength", "usb.wTotalLength", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bNumInterfaces,
        { "bNumInterfaces", "usb.bNumInterfaces", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bConfigurationValue,
        { "bConfigurationValue", "usb.bConfigurationValue", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_iConfiguration,
        { "iConfiguration", "usb.iConfiguration", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bMaxPower,
        { "bMaxPower", "usb.bMaxPower", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

        { &hf_usb_configuration_legacy10buspowered,
        { "Must be 1", "usb.configuration.legacy10buspowered", FT_BOOLEAN, 8,
          TFS(&tfs_mustbeone), 0x80, "Legacy USB 1.0 bus powered", HFILL }},

        { &hf_usb_configuration_selfpowered,
        { "Self-Powered", "usb.configuration.selfpowered", FT_BOOLEAN, 8,
          TFS(&tfs_selfpowered), 0x40, NULL, HFILL }},

        { &hf_usb_configuration_remotewakeup,
        { "Remote Wakeup", "usb.configuration.remotewakeup", FT_BOOLEAN, 8,
          TFS(&tfs_remotewakeup), 0x20, NULL, HFILL }},

        { &hf_usb_bEndpointAddress_number,
        { "Endpoint Number", "usb.bEndpointAddress.number", FT_UINT8, BASE_HEX,
          NULL, 0x0f, NULL, HFILL }},

        { &hf_usb_bEndpointAddress_direction,
        { "Direction", "usb.bEndpointAddress.direction", FT_BOOLEAN, 8,
          TFS(&tfs_endpoint_direction), 0x80, NULL, HFILL }},

	{ &hf_usb_request_in,
		{ "Request in", "usb.request_in", FT_FRAMENUM, BASE_NONE,
		NULL, 0, "The request to this packet is in this packet", HFILL }},

	{ &hf_usb_time,
		{ "Time from request", "usb.time", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Time between Request and Response for USB cmds", HFILL }},

	{ &hf_usb_response_in,
		{ "Response in", "usb.response_in", FT_FRAMENUM, BASE_NONE,
		NULL, 0, "The response to this packet is in this packet", HFILL }},

    };

    static gint *usb_subtrees[] = {
            &usb_hdr,
            &usb_setup_hdr,
            &ett_usb_setup_bmrequesttype,
            &ett_descriptor_device,
            &ett_configuration_bmAttributes,
            &ett_configuration_bEndpointAddress,
            &ett_endpoint_bmAttributes
    };


    proto_usb = proto_register_protocol("USB", "USB", "usb");
    proto_register_field_array(proto_usb, hf, array_length(hf));
    proto_register_subtree_array(usb_subtrees, array_length(usb_subtrees));

    usb_bulk_dissector_table = register_dissector_table("usb.bulk",
        "USB bulk endpoint", FT_UINT8, BASE_DEC);

    usb_control_dissector_table = register_dissector_table("usb.control",
        "USB control endpoint", FT_UINT8, BASE_DEC);

    usb_tap=register_tap("usb");
}

void
proto_reg_handoff_usb(void)
{
    dissector_handle_t linux_usb_handle, linux_usb_mmapped_handle;

    linux_usb_handle = create_dissector_handle(dissect_linux_usb, proto_usb);
    linux_usb_mmapped_handle = create_dissector_handle(dissect_linux_usb_mmapped,
                                                       proto_usb);

    dissector_add("wtap_encap", WTAP_ENCAP_USB_LINUX, linux_usb_handle);
    dissector_add("wtap_encap", WTAP_ENCAP_USB_LINUX_MMAPPED, linux_usb_mmapped_handle);
}
