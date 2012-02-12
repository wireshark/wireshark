/* packet-usb.c
 *
 * $Id$
 *
 * USB basic dissector
 * By Paolo Abeni <paolo.abeni@email.it>
 * Ronnie Sahlberg 2006
 *
 * http://www.usb.org/developers/docs/usb_20_122909-2.zip
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

#include <ctype.h>
#include "isprint.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>
#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include "packet-usb.h"
#include "packet-usb-hid.h"

/* protocols and header fields */
static int proto_usb = -1;

/* Linux USB pseudoheader fields */
static int hf_usb_urb_id = -1;
static int hf_usb_urb_type = -1;
static int hf_usb_transfer_type = -1;
static int hf_usb_endpoint_number = -1;
static int hf_usb_endpoint_direction = -1;
static int hf_usb_endpoint_number_value = -1;
static int hf_usb_device_address = -1;
static int hf_usb_bus_id = -1;
static int hf_usb_setup_flag = -1;
static int hf_usb_data_flag = -1;
static int hf_usb_urb_ts_sec = -1;
static int hf_usb_urb_ts_usec = -1;
static int hf_usb_urb_status = -1;
static int hf_usb_urb_len = -1;
static int hf_usb_data_len = -1;

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

static int hf_usb_iso_error_count = -1;
static int hf_usb_iso_numdesc = -1;
static int hf_usb_iso_status = -1;
static int hf_usb_iso_off = -1;
static int hf_usb_iso_len = -1;
static int hf_usb_iso_pad = -1;
static int hf_usb_iso_data = -1;

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
static gint usb_isodesc = -1;
static gint ett_usb_endpoint = -1;
static gint ett_usb_setup_bmrequesttype = -1;
static gint ett_descriptor_device = -1;
static gint ett_configuration_bmAttributes = -1;
static gint ett_configuration_bEndpointAddress = -1;
static gint ett_endpoint_bmAttributes = -1;

static const int *usb_endpoint_fields[] = {
    &hf_usb_endpoint_direction,
    &hf_usb_endpoint_number_value,
    NULL
};

static int usb_tap = -1;
static gboolean try_heuristics = TRUE;

static dissector_table_t usb_bulk_dissector_table;
static dissector_table_t usb_control_dissector_table;
static dissector_table_t usb_descriptor_dissector_table;
static heur_dissector_list_t heur_bulk_subdissector_list;
static heur_dissector_list_t heur_control_subdissector_list;

/* http://www.usb.org/developers/docs/USB_LANGIDs.pdf */
static const value_string usb_langid_vals[] = {
    {0x0000, "no language specified"},
    {0x0401, "Arabic (Saudi Arabia)"},
    {0x0402, "Bulgarian"},
    {0x0403, "Catalan"},
    {0x0404, "Chinese (Taiwan)"},
    {0x0405, "Czech"},
    {0x0406, "Danish"},
    {0x0407, "German (Standard)"},
    {0x0408, "Greek"},
    {0x0409, "English (United States)"},
    {0x040a, "Spanish (Traditional Sort)"},
    {0x040b, "Finnish"},
    {0x040c, "French (Standard)"},
    {0x040d, "Hebrew"},
    {0x040e, "Hungarian"},
    {0x040f, "Icelandic"},
    {0x0410, "Italian (Standard)"},
    {0x0411, "Japanese"},
    {0x0412, "Korean"},
    {0x0413, "Dutch (Netherlands)"},
    {0x0414, "Norwegian (Bokmal)"},
    {0x0415, "Polish"},
    {0x0416, "Portuguese (Brazil)"},
    {0x0418, "Romanian"},
    {0x0419, "Russian"},
    {0x041a, "Croatian"},
    {0x041b, "Slovak"},
    {0x041c, "Albanian"},
    {0x041d, "Swedish"},
    {0x041e, "Thai"},
    {0x041f, "Turkish"},
    {0x0420, "Urdu (Pakistan)"},
    {0x0421, "Indonesian"},
    {0x0422, "Ukrainian"},
    {0x0423, "Belarussian"},
    {0x0424, "Slovenian"},
    {0x0425, "Estonian"},
    {0x0426, "Latvian"},
    {0x0427, "Lithuanian"},
    {0x0429, "Farsi"},
    {0x042a, "Vietnamese"},
    {0x042b, "Armenian"},
    {0x042c, "Azeri (Latin)"},
    {0x042d, "Basque"},
    {0x042f, "Macedonian"},
    {0x0430, "Sutu"},
    {0x0436, "Afrikaans"},
    {0x0437, "Georgian"},
    {0x0438, "Faeroese"},
    {0x0439, "Hindi"},
    {0x043e, "Malay (Malaysian)"},
    {0x043f, "Kazakh"},
    {0x0441, "Swahili (Kenya)"},
    {0x0443, "Uzbek (Latin)"},
    {0x0444, "Tatar (Tatarstan)"},
    {0x0445, "Bengali"},
    {0x0446, "Punjabi"},
    {0x0447, "Gujarati"},
    {0x0448, "Oriya"},
    {0x0449, "Tamil"},
    {0x044a, "Telugu"},
    {0x044b, "Kannada"},
    {0x044c, "Malayalam"},
    {0x044d, "Assamese"},
    {0x044e, "Marathi"},
    {0x044f, "Sanskrit"},
    {0x0455, "Burmese"},
    {0x0457, "Konkani"},
    {0x0458, "Manipuri"},
    {0x0459, "Sindhi"},
    {0x04ff, "HID (Usage Data Descriptor)"},
    {0x0801, "Arabic (Iraq)"},
    {0x0804, "Chinese (PRC)"},
    {0x0807, "German (Switzerland)"},
    {0x0809, "English (United Kingdom)"},
    {0x080a, "Spanish (Mexican)"},
    {0x080c, "French (Belgian)"},
    {0x0810, "Italian (Switzerland)"},
    {0x0812, "Korean (Johab)"},
    {0x0813, "Dutch (Belgium)"},
    {0x0814, "Norwegian (Nynorsk)"},
    {0x0816, "Portuguese (Standard)"},
    {0x081a, "Serbian (Latin)"},
    {0x081d, "Swedish (Finland)"},
    {0x0820, "Urdu (India)"},
    {0x0827, "Lithuanian (Classic)"},
    {0x082c, "Azeri (Cyrillic)"},
    {0x083e, "Malay (Brunei Darussalam)"},
    {0x0843, "Uzbek (Cyrillic)"},
    {0x0860, "Kashmiri (India)"},
    {0x0861, "Nepali (India)"},
    {0x0c01, "Arabic (Egypt)"},
    {0x0c04, "Chinese (Hong Kong SAR, PRC)"},
    {0x0c07, "German (Austria)"},
    {0x0c09, "English (Australian)"},
    {0x0c0a, "Spanish (Modern Sort)"},
    {0x0c0c, "French (Canadian)"},
    {0x0c1a, "Serbian (Cyrillic)"},
    {0x1001, "Arabic (Libya)"},
    {0x1004, "Chinese (Singapore)"},
    {0x1007, "German (Luxembourg)"},
    {0x1009, "English (Canadian)"},
    {0x100a, "Spanish (Guatemala)"},
    {0x100c, "French (Switzerland)"},
    {0x1401, "Arabic (Algeria)"},
    {0x1404, "Chinese (Macau SAR)"},
    {0x1407, "German (Liechtenstein)"},
    {0x1409, "English (New Zealand)"},
    {0x140a, "Spanish (Costa Rica)"},
    {0x140c, "French (Luxembourg)"},
    {0x1801, "Arabic (Morocco)"},
    {0x1809, "English (Ireland)"},
    {0x180a, "Spanish (Panama)"},
    {0x180c, "French (Monaco)"},
    {0x1c01, "Arabic (Tunisia)"},
    {0x1c09, "English (South Africa)"},
    {0x1c0a, "Spanish (Dominican Republic)"},
    {0x2001, "Arabic (Oman)"},
    {0x2009, "English (Jamaica)"},
    {0x200a, "Spanish (Venezuela)"},
    {0x2401, "Arabic (Yemen)"},
    {0x2409, "English (Caribbean)"},
    {0x240a, "Spanish (Colombia)"},
    {0x2801, "Arabic (Syria)"},
    {0x2809, "English (Belize)"},
    {0x280a, "Spanish (Peru)"},
    {0x2c01, "Arabic (Jordan)"},
    {0x2c09, "English (Trinidad)"},
    {0x2c0a, "Spanish (Argentina)"},
    {0x3001, "Arabic (Lebanon)"},
    {0x3009, "English (Zimbabwe)"},
    {0x300a, "Spanish (Ecuador)"},
    {0x3401, "Arabic (Kuwait)"},
    {0x3409, "English (Philippines)"},
    {0x340a, "Spanish (Chile)"},
    {0x3801, "Arabic (U.A.E.)"},
    {0x380a, "Spanish (Uruguay)"},
    {0x3c01, "Arabic (Bahrain)"},
    {0x3c0a, "Spanish (Paraguay)"},
    {0x4001, "Arabic (Qatar)"},
    {0x400a, "Spanish (Bolivia)"},
    {0x440a, "Spanish (El Salvador)"},
    {0x480a, "Spanish (Honduras)"},
    {0x4c0a, "Spanish (Nicaragua)"},
    {0x500a, "Spanish (Puerto Rico)"},
    {0xf0ff, "HID (Vendor Defined 1)"},
    {0xf4ff, "HID (Vendor Defined 2)"},
    {0xf8ff, "HID (Vendor Defined 3)"},
    {0xfcff, "HID (Vendor Defined 4)"},
    {0, NULL}
};

static value_string_ext usb_langid_vals_ext = VALUE_STRING_EXT_INIT(usb_langid_vals);

static const value_string usb_interfaceclass_vals[] = {
    {IF_CLASS_FROM_INTERFACE_DESC,      "Use class info in Interface Descriptor"},
    {IF_CLASS_AUDIO,                    "AUDIO"},
    {IF_CLASS_COMMUNICATIONS,           "COMMUNICATIONS"},
    {IF_CLASS_HID,                      "HID"},
    {IF_CLASS_PHYSICAL,                 "PHYSICAL"},
    {IF_CLASS_IMAGE,                    "IMAGE"},
    {IF_CLASS_PRINTER,                  "PRINTER"},
    {IF_CLASS_MASSTORAGE,               "MASSTORAGE"},
    {IF_CLASS_HUB,                      "HUB"},
    {IF_CLASS_CDC_DATA,                 "CDC_DATA"},
    {IF_CLASS_SMART_CARD,               "SMART_CARD"},
    {IF_CLASS_CONTENT_SECURITY,         "CONTENT_SECURITY"},
    {IF_CLASS_VIDEO,                    "VIDEO"},
    {IF_CLASS_DIAGNOSTIC_DEVICE,        "DIAGNOSTIC_DEVICE"},
    {IF_CLASS_WIRELESS_CONTROLLER,      "WIRELESS_CONTROLLER"},
    {IF_CLASS_MISCELLANEOUS,            "MISCELLANEOUS"},
    {IF_CLASS_APPLICATION_SPECIFIC,     "APPLICATION_SPECIFIC"},
    {IF_CLASS_VENDOR_SPECIFIC,          "VENDOR_SPECIFIC"},
    {0, NULL}
};


static const value_string usb_transfer_type_vals[] = {
    {URB_CONTROL, "URB_CONTROL"},
    {URB_ISOCHRONOUS,"URB_ISOCHRONOUS"},
    {URB_INTERRUPT,"URB_INTERRUPT"},
    {URB_BULK,"URB_BULK"},
    {0, NULL}
};

static const value_string usb_transfer_type_and_direction_vals[] = {
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

static const value_string usb_endpoint_direction_vals[] = {
    {0, "OUT"},
    {1, "IN"},
    {0, NULL}
};

static const value_string usb_urb_type_vals[] = {
    {URB_SUBMIT,  "URB_SUBMIT"},
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
#define USB_DT_HID                      33
#define USB_DT_RPIPE                    34

static const value_string descriptor_type_vals[] = {
    {USB_DT_DEVICE,                     "DEVICE"},
    {USB_DT_CONFIG,                     "CONFIGURATION"},
    {USB_DT_STRING,                     "STRING"},
    {USB_DT_INTERFACE,                  "INTERFACE"},
    {USB_DT_ENDPOINT,                   "ENDPOINT"},
    {USB_DT_DEVICE_QUALIFIER,           "DEVICE QUALIFIER"},
    {USB_DT_OTHER_SPEED_CONFIG,         "OTHER_SPEED CONFIG"},
    {USB_DT_INTERFACE_POWER,            "INTERFACE POWER"},
    {USB_DT_OTG,                        "OTG"},
    {USB_DT_DEBUG,                      "DEBUG"},
    {USB_DT_INTERFACE_ASSOCIATION,      "INTERFACE ASSOCIATION"},
    {USB_DT_SECURITY,                   "SECURITY"},
    {USB_DT_KEY,                        "KEY"},
    {USB_DT_ENCRYPTION_TYPE,            "ENCRYPTION TYPE"},
    {USB_DT_BOS,                        "BOS"},
    {USB_DT_DEVICE_CAPABILITY,          "DEVICE CAPABILITY"},
    {USB_DT_WIRELESS_ENDPOINT_COMP,     "WIRELESS ENDPOINT COMP"},
    {USB_DT_HID,                        "HID"},
    {USB_DT_RPIPE,                      "RPIPE"},
    {0,NULL}
};

/*
 * Feature selectors.
 */
#define USB_FS_DEVICE_REMOTE_WAKEUP     1
#define USB_FS_ENDPOINT_HALT            0
#define USB_FS_TEST_MODE                2

static const value_string usb_feature_selector_vals[] = {
    {USB_FS_DEVICE_REMOTE_WAKEUP,       "DEVICE REMOTE WAKEUP"},
    {USB_FS_ENDPOINT_HALT,              "ENDPOINT HALT"},
    {USB_FS_TEST_MODE,                  "TEST MODE"},
    {0,NULL}
};

static const value_string usb_bmAttributes_transfer_vals[] = {
    {0x00,      "Control-Transfer"},
    {0x01,      "Isochronous-Transfer"},
    {0x02,      "Bulk-Transfer"},
    {0x03,      "Interrupt-Transfer"},
    {0,NULL}
};

static const value_string usb_bmAttributes_sync_vals[] = {
    {0x00,      "No Sync"},
    {0x01,      "Asynchronous"},
    {0x02,      "Adaptive"},
    {0x03,      "Synchronous"},
    {0,NULL}
};

static const value_string usb_bmAttributes_behaviour_vals[] = {
    {0x00,      "Data-Endpoint"},
    {0x01,      "Explicit Feedback-Endpoint"},
    {0x02,      "Implicit Feedback-Data-Endpoint"},
    {0x03,      "Reserved"},
    {0,NULL}
};

/* from linux/include/asm-generic/errno.h */
#define EPERM            1      /* Operation not permitted */
#define ENOENT           2      /* No such file or directory */
#define ESRCH            3      /* No such process */
#define EINTR            4      /* Interrupted system call */
#define EIO              5      /* I/O error */
#define ENXIO            6      /* No such device or address */
#define E2BIG            7      /* Argument list too long */
#define ENOEXEC          8      /* Exec format error */
#define EBADF            9      /* Bad file number */
#define ECHILD          10      /* No child processes */
#define EAGAIN          11      /* Try again */
#define ENOMEM          12      /* Out of memory */
#define EACCES          13      /* Permission denied */
#define EFAULT          14      /* Bad address */
#define ENOTBLK         15      /* Block device required */
#define EBUSY           16      /* Device or resource busy */
#define EEXIST          17      /* File exists */
#define EXDEV           18      /* Cross-device link */
#define ENODEV          19      /* No such device */
#define ENOTDIR         20      /* Not a directory */
#define EISDIR          21      /* Is a directory */
#define EINVAL          22      /* Invalid argument */
#define ENFILE          23      /* File table overflow */
#define EMFILE          24      /* Too many open files */
#define ENOTTY          25      /* Not a typewriter */
#define ETXTBSY         26      /* Text file busy */
#define EFBIG           27      /* File too large */
#define ENOSPC          28      /* No space left on device */
#define ESPIPE          29      /* Illegal seek */
#define EROFS           30      /* Read-only file system */
#define EMLINK          31      /* Too many links */
#define EPIPE           32      /* Broken pipe */
#define EDOM            33      /* Math argument out of domain of func */
#define ERANGE          34      /* Math result not representable */


/* from linux/include/asm-generic/errno.h*/
#define EDEADLK         35      /* Resource deadlock would occur */
#define ENAMETOOLONG    36      /* File name too long */
#define ENOLCK          37      /* No record locks available */
#define ENOSYS          38      /* Function not implemented */
#define ENOTEMPTY       39      /* Directory not empty */
#define ELOOP           40      /* Too many symbolic links encountered */
#define EWOULDBLOCK     EAGAIN  /* Operation would block */
#define ENOMSG          42      /* No message of desired type */
#define EIDRM           43      /* Identifier removed */
#define ECHRNG          44      /* Channel number out of range */
#define EL2NSYNC        45      /* Level 2 not synchronized */
#define EL3HLT          46      /* Level 3 halted */
#define EL3RST          47      /* Level 3 reset */
#define ELNRNG          48      /* Link number out of range */
#define EUNATCH         49      /* Protocol driver not attached */
#define ENOCSI          50      /* No CSI structure available */
#define EL2HLT          51      /* Level 2 halted */
#define EBADE           52      /* Invalid exchange */
#define EBADR           53      /* Invalid request descriptor */
#define EXFULL          54      /* Exchange full */
#define ENOANO          55      /* No anode */
#define EBADRQC         56      /* Invalid request code */
#define EBADSLT         57      /* Invalid slot */

#define EDEADLOCK       EDEADLK

#define EBFONT          59      /* Bad font file format */
#define ENOSTR          60      /* Device not a stream */
#define ENODATA         61      /* No data available */
#define ETIME           62      /* Timer expired */
#define ENOSR           63      /* Out of streams resources */
#define ENONET          64      /* Machine is not on the network */
#define ENOPKG          65      /* Package not installed */
#define EREMOTE         66      /* Object is remote */
#define ENOLINK         67      /* Link has been severed */
#define EADV            68      /* Advertise error */
#define ESRMNT          69      /* Srmount error */
#define ECOMM           70      /* Communication error on send */
#define EPROTO          71      /* Protocol error */
#define EMULTIHOP       72      /* Multihop attempted */
#define EDOTDOT         73      /* RFS specific error */
#define EBADMSG         74      /* Not a data message */
#define EOVERFLOW       75      /* Value too large for defined data type */
#define ENOTUNIQ        76      /* Name not unique on network */
#define EBADFD          77      /* File descriptor in bad state */
#define EREMCHG         78      /* Remote address changed */
#define ELIBACC         79      /* Can not access a needed shared library */
#define ELIBBAD         80      /* Accessing a corrupted shared library */
#define ELIBSCN         81      /* .lib section in a.out corrupted */
#define ELIBMAX         82      /* Attempting to link in too many shared libraries */
#define ELIBEXEC        83      /* Cannot exec a shared library directly */
#define EILSEQ          84      /* Illegal byte sequence */
#define ERESTART        85      /* Interrupted system call should be restarted */
#define ESTRPIPE        86      /* Streams pipe error */
#define EUSERS          87      /* Too many users */
#define ENOTSOCK        88      /* Socket operation on non-socket */
#define EDESTADDRREQ    89      /* Destination address required */
#define EMSGSIZE        90      /* Message too long */
#define EPROTOTYPE      91      /* Protocol wrong type for socket */
#define ENOPROTOOPT     92      /* Protocol not available */
#define EPROTONOSUPPORT 93      /* Protocol not supported */
#define ESOCKTNOSUPPORT 94      /* Socket type not supported */
#define EOPNOTSUPP      95      /* Operation not supported on transport endpoint */
#define EPFNOSUPPORT    96      /* Protocol family not supported */
#define EAFNOSUPPORT    97      /* Address family not supported by protocol */
#define EADDRINUSE      98      /* Address already in use */
#define EADDRNOTAVAIL   99      /* Cannot assign requested address */
#define ENETDOWN        100     /* Network is down */
#define ENETUNREACH     101     /* Network is unreachable */
#define ENETRESET       102     /* Network dropped connection because of reset */
#define ECONNABORTED    103     /* Software caused connection abort */
#define ECONNRESET      104     /* Connection reset by peer */
#define ENOBUFS         105     /* No buffer space available */
#define EISCONN         106     /* Transport endpoint is already connected */
#define ENOTCONN        107     /* Transport endpoint is not connected */
#define ESHUTDOWN       108     /* Cannot send after transport endpoint shutdown */
#define ETOOMANYREFS    109     /* Too many references: cannot splice */
#define ETIMEDOUT       110     /* Connection timed out */
#define ECONNREFUSED    111     /* Connection refused */
#define EHOSTDOWN       112     /* Host is down */
#define EHOSTUNREACH    113     /* No route to host */
#define EALREADY        114     /* Operation already in progress */
#define EINPROGRESS     115     /* Operation now in progress */
#define ESTALE          116     /* Stale NFS file handle */
#define EUCLEAN         117     /* Structure needs cleaning */
#define ENOTNAM         118     /* Not a XENIX named type file */
#define ENAVAIL         119     /* No XENIX semaphores available */
#define EISNAM          120     /* Is a named type file */
#define EREMOTEIO       121     /* Remote I/O error */
#define EDQUOT          122     /* Quota exceeded */

#define ENOMEDIUM       123     /* No medium found */
#define EMEDIUMTYPE     124     /* Wrong medium type */
#define ECANCELED       125     /* Operation Canceled */
#define ENOKEY          126     /* Required key not available */
#define EKEYEXPIRED     127     /* Key has expired */
#define EKEYREVOKED     128     /* Key has been revoked */
#define EKEYREJECTED    129     /* Key was rejected by service */

/* for robust mutexes */
#define EOWNERDEAD      130     /* Owner died */
#define ENOTRECOVERABLE 131     /* State not recoverable */


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
        usb_conv_info->interfaceSubclass = IF_SUBCLASS_UNKNOWN;
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
    proto_tree_add_item(tree, hf_usb_wFeatureSelector, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero/interface/endpoint */
    /* XXX - check based on request type */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bcdUSB */
    proto_tree_add_item(tree, hf_usb_bcdUSB, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* bDeviceClass */
    proto_tree_add_item(tree, hf_usb_bDeviceClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bDeviceSubClass */
    proto_tree_add_item(tree, hf_usb_bDeviceSubClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bDeviceProtocol */
    proto_tree_add_item(tree, hf_usb_bDeviceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bMaxPacketSize0 */
    proto_tree_add_item(tree, hf_usb_bMaxPacketSize0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bNumConfigurations */
    proto_tree_add_item(tree, hf_usb_bNumConfigurations, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bcdUSB */
    proto_tree_add_item(tree, hf_usb_bcdUSB, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* bDeviceClass */
    proto_tree_add_item(tree, hf_usb_bDeviceClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bDeviceSubClass */
    proto_tree_add_item(tree, hf_usb_bDeviceSubClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bDeviceProtocol */
    proto_tree_add_item(tree, hf_usb_bDeviceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bMaxPacketSize0 */
    proto_tree_add_item(tree, hf_usb_bMaxPacketSize0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* idVendor */
    proto_tree_add_item(tree, hf_usb_idVendor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* idProduct */
    proto_tree_add_item(tree, hf_usb_idProduct, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* bcdDevice */
    proto_tree_add_item(tree, hf_usb_bcdDevice, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* iManufacturer */
    proto_tree_add_item(tree, hf_usb_iManufacturer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iProduct */
    proto_tree_add_item(tree, hf_usb_iProduct, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iSerialNumber */
    proto_tree_add_item(tree, hf_usb_iSerialNumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bNumConfigurations */
    proto_tree_add_item(tree, hf_usb_bNumConfigurations, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    len=tvb_get_guint8(tvb, offset);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    if(!usb_trans_info->u.get_descriptor.index){
        /* list of languanges */
        while(len>(offset-old_offset)){
            /* wLANGID */
            proto_tree_add_item(tree, hf_usb_wLANGID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
    } else {
        char *str;

        /* unicode string */
        str=tvb_get_ephemeral_unicode_string(tvb, offset, (len-2)/2, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    len = tvb_get_guint8(tvb, offset);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bInterfaceNumber */
    proto_tree_add_item(tree, hf_usb_bInterfaceNumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bAlternateSetting */
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bNumEndpoints */
    proto_tree_add_item(tree, hf_usb_bNumEndpoints, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bInterfaceClass */
    proto_tree_add_item(tree, hf_usb_bInterfaceClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* save the class so we can access it later in the endpoint descriptor */
    usb_conv_info->interfaceClass=tvb_get_guint8(tvb, offset);
    if(!pinfo->fd->flags.visited){
        usb_trans_info->interface_info=se_alloc0(sizeof(usb_conv_info_t));
        usb_trans_info->interface_info->interfaceClass=tvb_get_guint8(tvb, offset);
        usb_trans_info->interface_info->transactions=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "usb transactions");
    }
    offset++;

    /* bInterfaceSubClass */
    proto_tree_add_item(tree, hf_usb_bInterfaceSubClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* save the subclass so we can access it later in class-specific descriptors */
    usb_conv_info->interfaceSubclass = tvb_get_guint8(tvb, offset);
    offset++;

    /* bInterfaceProtocol */
    proto_tree_add_item(tree, hf_usb_bInterfaceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iInterface */
    proto_tree_add_item(tree, hf_usb_iInterface, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    len = tvb_get_guint8(tvb, offset);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bEndpointAddress */
    if(tree){
        endpoint_item=proto_tree_add_item(tree, hf_usb_bEndpointAddress, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        endpoint_tree=proto_item_add_subtree(endpoint_item, ett_configuration_bEndpointAddress);
    }
    endpoint=tvb_get_guint8(tvb, offset)&0x0f;
    proto_tree_add_item(endpoint_tree, hf_usb_bEndpointAddress_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(endpoint_item, "  %s", (tvb_get_guint8(tvb, offset)&0x80)?"IN":"OUT");
    proto_tree_add_item(endpoint_tree, hf_usb_bEndpointAddress_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
        ep_attrib_item=proto_tree_add_item(tree, hf_usb_bmAttributes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        ep_attrib_tree=proto_item_add_subtree(ep_attrib_item, ett_endpoint_bmAttributes);
    }
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeTransfer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* isochronous only */
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeSynchonisation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* isochronous only */
    proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeBehaviour, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* wMaxPacketSize */
    proto_tree_add_item(tree, hf_usb_wMaxPacketSize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* bInterval */
    proto_tree_add_item(tree, hf_usb_bInterval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* wTotalLength */
    proto_tree_add_item(tree, hf_usb_wTotalLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    len=tvb_get_letohs(tvb, offset);
    offset+=2;

    /* bNumInterfaces */
    proto_tree_add_item(tree, hf_usb_bNumInterfaces, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bConfigurationValue */
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* iConfiguration */
    proto_tree_add_item(tree, hf_usb_iConfiguration, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* bmAttributes */
    if(tree){
        flags_item=proto_tree_add_item(tree, hf_usb_configuration_bmAttributes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        flags_tree=proto_item_add_subtree(flags_item, ett_configuration_bmAttributes);
    }
    flags=tvb_get_guint8(tvb, offset);
    proto_tree_add_item(flags_tree, hf_usb_configuration_legacy10buspowered, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_usb_configuration_selfpowered, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(flags_item, "  %sSELF-POWERED", (flags&0x40)?"":"NOT ");
    proto_tree_add_item(flags_tree, hf_usb_configuration_remotewakeup, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(flags_item, "  %sREMOTE-WAKEUP", (flags&0x20)?"":"NO ");
    offset++;

    /* bMaxPower */
    power_item=proto_tree_add_item(tree, hf_usb_bMaxPower, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    power=tvb_get_guint8(tvb, offset);
    proto_item_append_text(power_item, "  (%dmA)", power*2);
    offset++;

    /* initialize interface_info to NULL */
    usb_trans_info->interface_info=NULL;

    /* decode any additional interface and endpoint descriptors */
    while(len>(old_offset-offset)){
        guint8 next_type;
        tvbuff_t *next_tvb = NULL;

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
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            if (dissector_try_uint(usb_descriptor_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, parent_tree)){
                offset += tvb_get_guint8(next_tvb, 0);
            } else {
                offset=dissect_usb_unknown_descriptor(pinfo, parent_tree, tvb, offset, usb_trans_info, usb_conv_info);
            }
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
    proto_tree_add_item(tree, hf_usb_descriptor_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    usb_trans_info->u.get_descriptor.index=tvb_get_guint8(tvb, offset);
    offset++;

    /* descriptor type */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    usb_trans_info->u.get_descriptor.type=tvb_get_guint8(tvb, offset);
    offset++;
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
            val_to_str(usb_trans_info->u.get_descriptor.type, descriptor_type_vals, "Unknown type %u"));
    }

    /* language id */
    proto_tree_add_item(tree, hf_usb_language_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_get_descriptor_response(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info)
{
    proto_item *item=NULL;
    guint32 data_len;

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
        tvb_memcpy(tvb, (guint8 *)&data_len, offset, 4);
        proto_tree_add_uint(tree, hf_usb_data, tvb, offset, 4, data_len);
        offset += data_len;
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
    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* interface */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_get_interface_response(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* alternate setting */
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero/interface/endpoint */
    /* XXX - check based on request type */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_get_status_response(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* status */
    /* XXX - show bits */
    proto_tree_add_item(tree, hf_usb_wStatus, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_device_address, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_wFeatureSelector, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero/interface/endpoint or test selector */
    /* XXX - check based on request type */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* interface */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* endpoint */
    /* XXX */
    proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* two */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_synch_frame_response(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset, usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    /* frame number */
    proto_tree_add_item(tree, hf_usb_wFrameNumber, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}


typedef int (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info);

typedef struct _usb_setup_dissector_table_t {
    guint8 request;
    usb_setup_dissector dissector;
} usb_setup_dissector_table_t;
#define USB_SETUP_GET_STATUS            0
#define USB_SETUP_CLEAR_FEATURE         1
#define USB_SETUP_SET_FEATURE           2
#define USB_SETUP_SET_ADDRESS           5
#define USB_SETUP_GET_DESCRIPTOR        6
#define USB_SETUP_SET_DESCRIPTOR        7
#define USB_SETUP_GET_CONFIGURATION     8
#define USB_SETUP_SET_CONFIGURATION     9
#define USB_SETUP_GET_INTERFACE         10
#define USB_SETUP_SET_INTERFACE         11
#define USB_SETUP_SYNCH_FRAME           12

static const usb_setup_dissector_table_t setup_request_dissectors[] = {
    {USB_SETUP_GET_STATUS,      dissect_usb_setup_get_status_request},
    {USB_SETUP_CLEAR_FEATURE,   dissect_usb_setup_clear_feature_request},
    {USB_SETUP_SET_FEATURE,     dissect_usb_setup_set_feature_request},
    {USB_SETUP_SET_ADDRESS,     dissect_usb_setup_set_address_request},
    {USB_SETUP_GET_DESCRIPTOR,  dissect_usb_setup_get_descriptor_request},
    {USB_SETUP_SET_CONFIGURATION, dissect_usb_setup_set_configuration_request},
    {USB_SETUP_GET_INTERFACE,   dissect_usb_setup_get_interface_request},
    {USB_SETUP_SET_INTERFACE,   dissect_usb_setup_set_interface_request},
    {USB_SETUP_SYNCH_FRAME,     dissect_usb_setup_synch_frame_request},
    {0, NULL}
};

static const usb_setup_dissector_table_t setup_response_dissectors[] = {
    {USB_SETUP_GET_STATUS,      dissect_usb_setup_get_status_response},
    {USB_SETUP_CLEAR_FEATURE,   dissect_usb_setup_clear_feature_response},
    {USB_SETUP_SET_FEATURE,     dissect_usb_setup_set_feature_response},
    {USB_SETUP_SET_ADDRESS,     dissect_usb_setup_set_address_response},
    {USB_SETUP_GET_DESCRIPTOR,  dissect_usb_setup_get_descriptor_response},
    {USB_SETUP_GET_CONFIGURATION, dissect_usb_setup_get_configuration_response},
    {USB_SETUP_SET_CONFIGURATION, dissect_usb_setup_set_configuration_response},
    {USB_SETUP_GET_INTERFACE,   dissect_usb_setup_get_interface_response},
    {USB_SETUP_SET_INTERFACE,   dissect_usb_setup_set_interface_response},
    {USB_SETUP_SYNCH_FRAME,     dissect_usb_setup_synch_frame_response},
    {0, NULL}
};

/* bRequest values but only when bmRequestType.type == 0 (Device) */
static const value_string setup_request_names_vals[] = {
    {USB_SETUP_GET_STATUS,              "GET STATUS"},
    {USB_SETUP_CLEAR_FEATURE,           "CLEAR FEATURE"},
    {USB_SETUP_SET_FEATURE,             "SET FEATURE"},
    {USB_SETUP_SET_ADDRESS,             "SET ADDRESS"},
    {USB_SETUP_GET_DESCRIPTOR,          "GET DESCRIPTOR"},
    {USB_SETUP_SET_DESCRIPTOR,          "SET DESCRIPTOR"},
    {USB_SETUP_GET_CONFIGURATION,       "GET CONFIGURATION"},
    {USB_SETUP_SET_CONFIGURATION,       "SET CONFIGURATION"},
    {USB_SETUP_GET_INTERFACE,           "GET INTERFACE"},
    {USB_SETUP_SET_INTERFACE,           "SET INTERFACE"},
    {USB_SETUP_SYNCH_FRAME,             "SYNCH FRAME"},
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
    {RQT_SETUP_RECIPIENT_DEVICE,    "Device" },
    {RQT_SETUP_RECIPIENT_INTERFACE, "Interface" },
    {RQT_SETUP_RECIPIENT_INTERFACE, "Endpoint" },
    {RQT_SETUP_RECIPIENT_INTERFACE, "Other" },
    {0, NULL }
};

static int
dissect_usb_bmrequesttype(proto_tree *parent_tree, tvbuff_t *tvb, int offset,
    int *type)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;

    if(parent_tree){
        item=proto_tree_add_item(parent_tree, hf_usb_bmRequestType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        tree = proto_item_add_subtree(item, ett_usb_setup_bmrequesttype);
    }

    *type = USB_TYPE(tvb_get_guint8(tvb, offset));
    proto_tree_add_item(tree, hf_usb_bmRequestType_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_bmRequestType_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_bmRequestType_recipient, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    return ++offset;
}

/* Adds the Linux USB pseudo header fields to the tree.
 * NOTE: The multi-byte fields in this header, and the pseudo-header
 *       extension, are in host-endian format so we can't
 *       use proto_tree_add_item() nor the tvb_get_xyz() routines and is
 *       the reason for the tvb_memcpy() and proto_tree_add_uint[64]()
 *       pairs below. */
static void
dissect_linux_usb_pseudo_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 transfer_type;
    guint8 endpoint_number;
    guint8 transfer_type_and_direction;
    guint8 type, flag;
    guint16 val16;
    guint32 val32;
    guint64 val64;

    tvb_memcpy(tvb, (guint8 *)&val64, 0, 8);
    proto_tree_add_uint64(tree, hf_usb_urb_id, tvb, 0, 8, val64);

    /* show the event type of this URB as string and as a character */
    type = tvb_get_guint8(tvb, 8);
    proto_tree_add_uint_format_value(tree, hf_usb_urb_type, tvb, 8, 1,
        type, "%s ('%c')", val_to_str(type, usb_urb_type_vals, "Unknown %d"),
        isprint(type) ? type : '.');
    proto_tree_add_item(tree, hf_usb_transfer_type, tvb, 9, 1, ENC_BIG_ENDIAN);

    if (check_col(pinfo->cinfo, COL_INFO)) {
        transfer_type = tvb_get_guint8(tvb, 9);
        endpoint_number = tvb_get_guint8(tvb, 10);
        transfer_type_and_direction = (transfer_type & 0x7F) | (endpoint_number & 0x80);
        col_append_str(pinfo->cinfo, COL_INFO,
                       val_to_str(transfer_type_and_direction, usb_transfer_type_and_direction_vals, "Unknown type %x"));
    }

    proto_tree_add_bitmask(tree, tvb, 10, hf_usb_endpoint_number, ett_usb_endpoint, usb_endpoint_fields, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usb_device_address, tvb, 11, 1, ENC_BIG_ENDIAN);

    tvb_memcpy(tvb, (guint8 *)&val16, 12, 2);
    proto_tree_add_uint(tree, hf_usb_bus_id, tvb, 12, 2, val16);

    /* Right after the pseudo header we always have
     * sizeof(struct usb_device_setup_hdr) bytes. The content of these
     * bytes only have meaning in case setup_flag == 0.
     */
    flag = tvb_get_guint8(tvb, 14);
    if (flag == 0) {
        proto_tree_add_string(tree, hf_usb_setup_flag, tvb, 14, 1, "relevant (0)");
    } else {
        proto_tree_add_string_format_value(tree, hf_usb_setup_flag, tvb,
            14, 1, &flag, "not relevant ('%c')", isprint(flag) ? flag: '.');
    }

    flag = tvb_get_guint8(tvb, 15);
    if (flag == 0) {
        proto_tree_add_string(tree, hf_usb_data_flag, tvb, 15, 1, "present (0)");
    } else {
        proto_tree_add_string_format_value(tree, hf_usb_data_flag, tvb,
            15, 1, &flag, "not present ('%c')", isprint(flag) ? flag : '.');
    }

    tvb_memcpy(tvb, (guint8 *)&val64, 16, 8);
    proto_tree_add_uint64(tree, hf_usb_urb_ts_sec, tvb, 16, 8, val64);

    tvb_memcpy(tvb, (guint8 *)&val32, 24, 4);
    proto_tree_add_uint(tree, hf_usb_urb_ts_usec, tvb, 24, 4, val32);

    tvb_memcpy(tvb, (guint8 *)&val32, 28, 4);
    proto_tree_add_int(tree, hf_usb_urb_status, tvb, 28, 4, val32);

    tvb_memcpy(tvb, (guint8 *)&val32, 32, 4);
    proto_tree_add_uint(tree, hf_usb_urb_len, tvb, 32, 4, val32);

    tvb_memcpy(tvb, (guint8 *)&val32, 36, 4);
    proto_tree_add_uint(tree, hf_usb_data_len, tvb, 36, 4, val32);
}

/*
 * XXX - put these into the protocol tree as appropriate.
 */
static int
dissect_linux_usb_pseudo_header_ext(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo _U_,
                                    proto_tree *tree _U_)
{
    guint32 ndesc;

    offset += 4;        /* interval */
    offset += 4;        /* start_frame */
    offset += 4;        /* copy of URB's transfer flags */

    tvb_memcpy(tvb, (guint8 *)&ndesc, offset, 4);
    offset += 4;

    /*
     * Isochronous descriptors.  Each one is 16 bytes long.
     */
    offset += ndesc*16;

    return offset;
}

static void
dissect_linux_usb_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent,
                         gboolean header_len_64_bytes)
{
    unsigned int offset = 0;
    int type, endpoint;
    guint8 setup_flag;
    proto_tree *tree = NULL;
    guint32 tmp_addr;
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
      ti = proto_tree_add_protocol_format(parent, proto_usb, tvb, 0,
          header_len_64_bytes ? 64 : 48, "USB URB");
      tree = proto_item_add_subtree(ti, usb_hdr);
    }

    dissect_linux_usb_pseudo_header(tvb, pinfo, tree);
    is_request = (tvb_get_guint8(tvb, 8) == URB_SUBMIT) ? TRUE : FALSE;
    type = tvb_get_guint8(tvb, 9);
    endpoint = tvb_get_guint8(tvb, 10) & (~URB_TRANSFER_IN);
    tmp_addr = tvb_get_guint8(tvb, 11);
    setup_flag = tvb_get_guint8(tvb, 14);
    offset += 40; /* skip first part of the pseudo-header */

    /* Set up addresses and ports. */
    if (is_request) {
        src_addr.device = 0xffffffff;
        src_addr.endpoint = src_endpoint = NO_ENDPOINT;
        dst_addr.device = htolel(tmp_addr);
        dst_addr.endpoint = dst_endpoint = htolel(endpoint);
    } else {
        src_addr.device = htolel(tmp_addr);
        src_addr.endpoint = src_endpoint = htolel(endpoint);
        dst_addr.device = 0xffffffff;
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

        if(usb_trans_info->response_in){
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
    tap_data->urb_type=tvb_get_guint8(tvb, 8);
    tap_data->transfer_type=(guint8)type;
    tap_data->conv_info=usb_conv_info;
    tap_data->trans_info=usb_trans_info;
    tap_queue_packet(usb_tap, pinfo, tap_data);

    switch(type){
    case URB_BULK:
        {
        proto_item *item;

        item=proto_tree_add_uint(tree, hf_usb_bInterfaceClass, tvb, 0, 0, usb_conv_info->interfaceClass);
        PROTO_ITEM_SET_GENERATED(item);

        /* Skip setup/isochronous header - it's not applicable */
        offset += 8;

        /*
         * If this has a 64-byte header, process the extra 16 bytes of
         * pseudo-header information.
         */
        if (header_len_64_bytes)
            offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);

        if(tvb_reported_length_remaining(tvb, offset)){
            tvbuff_t *next_tvb;

            pinfo->usb_conv_info=usb_conv_info;
            next_tvb=tvb_new_subset_remaining(tvb, offset);
            if (try_heuristics && dissector_try_heuristic(heur_bulk_subdissector_list, next_tvb, pinfo, parent)) {
                return;
            }
            else if(dissector_try_uint(usb_bulk_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, parent)){
                return;
            }
        }
        }
        break;
    case URB_CONTROL:
        {
        const usb_setup_dissector_table_t *tmp;
        usb_setup_dissector dissector;
        proto_item *ti = NULL;
        proto_tree *setup_tree = NULL;
        int type_2;

        ti=proto_tree_add_uint(tree, hf_usb_bInterfaceClass, tvb, offset, 0, usb_conv_info->interfaceClass);
        PROTO_ITEM_SET_GENERATED(ti);

        if(is_request){
            if (setup_flag == 0) {
                tvbuff_t *next_tvb;

                /* this is a request */

                /* Dissect the setup header - it's applicable */

                ti = proto_tree_add_protocol_format(tree, proto_usb, tvb, offset, 8, "URB setup");
                setup_tree = proto_item_add_subtree(ti, usb_setup_hdr);
                usb_trans_info->requesttype=tvb_get_guint8(tvb, offset);
                offset=dissect_usb_bmrequesttype(setup_tree, tvb, offset, &type_2);


                /* read the request code and spawn off to a class specific
                 * dissector if found
                 */
                usb_trans_info->request=tvb_get_guint8(tvb, offset);

                switch (type_2) {

                case RQT_SETUP_TYPE_STANDARD:
                    /*
                     * This is a standard request which is managed by this
                     * dissector
                     */
                    proto_tree_add_item(setup_tree, hf_usb_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset++;

                    if (check_col(pinfo->cinfo, COL_INFO)) {
                        col_add_fstr(pinfo->cinfo, COL_INFO, "%s Request",
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
                        proto_tree_add_item(setup_tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(setup_tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(setup_tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                        offset += 2;
                    }
                    break;

                case RQT_SETUP_TYPE_CLASS:
                    /* Try to find a class specific dissector */
                    next_tvb=tvb_new_subset_remaining(tvb, offset);
                    if (try_heuristics && dissector_try_heuristic(heur_control_subdissector_list, next_tvb, pinfo, tree)) {
                        return;
                    }
                    if(dissector_try_uint(usb_control_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, tree)){
                        return;
                    }
                    /* Else no class dissector, just display generic fields */
                    proto_tree_add_item(setup_tree, hf_usb_request_unknown_class, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset++;
                    proto_tree_add_item(setup_tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(setup_tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(setup_tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                default:
                    proto_tree_add_item(setup_tree, hf_usb_request_unknown_class, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset++;
                    proto_tree_add_item(setup_tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(setup_tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(setup_tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                }
            } else {
                /* Skip setup/isochronous header - it's not applicable */
                offset += 8;
            }

            /*
             * If this has a 64-byte header, process the extra 16 bytes of
             * pseudo-header information.
             */
            if (header_len_64_bytes)
                offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);

            if (tvb_reported_length_remaining(tvb, offset) != 0) {
                tvbuff_t *next_tvb;

                next_tvb = tvb_new_subset_remaining(tvb, offset);
                if (try_heuristics && dissector_try_heuristic(heur_control_subdissector_list, next_tvb, pinfo, tree)) {
                    return;
                }
                if(dissector_try_uint(usb_control_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, tree)){
                    return;
                }
            }
        } else {
            tvbuff_t *next_tvb;

            /* this is a response */

            /* Skip setup header - it's never applicable for responses */
            offset += 8;

            /*
             * If this has a 64-byte header, process the extra 16 bytes of
             * pseudo-header information.
             */
            if (header_len_64_bytes)
                offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);

            if(usb_trans_info){
                /* Try to find a class specific dissector */
                next_tvb=tvb_new_subset_remaining(tvb, offset);
                if (try_heuristics && dissector_try_heuristic(heur_control_subdissector_list, next_tvb, pinfo, tree)) {
                    return;
                }
                if(dissector_try_uint(usb_control_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, tree)){
                    return;
                }

                type_2 = USB_TYPE(usb_trans_info->requesttype);
                switch (type_2) {

                case RQT_SETUP_TYPE_STANDARD:
                    /*
                     * This is a standard response which is managed by this
                     * dissector
                     */
                    if (check_col(pinfo->cinfo, COL_INFO)) {
                        col_add_fstr(pinfo->cinfo, COL_INFO, "%s Response",
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
    case URB_ISOCHRONOUS:
        {
        guint32 iso_numdesc = 0;
        proto_item *ti = NULL;
        ti=proto_tree_add_uint(tree, hf_usb_bInterfaceClass, tvb, offset, 0, usb_conv_info->interfaceClass);
        PROTO_ITEM_SET_GENERATED(ti);

        /* All fields which belong to Linux usbmon headers are in host-endian
         * byte order. The fields coming from the USB communication are in little
         * endian format (see usb_20.pdf, chapter 8.1 Byte/Bit ordering).
         *
         * When a capture file is transfered to a host with different endianness
         * than packet was captured then the necessary swapping happens in
         * wiretap/pcap-common.c, pcap_process_linux_usb_pseudoheader().
         */

        if (setup_flag == 0) {
            proto_tree *setup_tree = NULL;
            int type_2;

            /* Dissect the setup header - it's applicable */

            ti = proto_tree_add_protocol_format(tree, proto_usb, tvb, offset, 8, "URB setup");
            setup_tree = proto_item_add_subtree(ti, usb_setup_hdr);

            offset = dissect_usb_bmrequesttype(setup_tree, tvb, offset, &type_2);
            proto_tree_add_item(setup_tree, hf_usb_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else {

            /* Process ISO related fields (usbmon_packet.iso). The fields are
             * in host endian byte order so use tvb_memcopy() and
             * proto_tree_add_uint() pair.
             */
            guint32 val32;

            tvb_memcpy(tvb, (guint8 *)&val32, offset, 4);
            proto_tree_add_uint(tree, hf_usb_iso_error_count, tvb, offset, 4, val32);
            offset += 4;

            tvb_memcpy(tvb, (guint8 *)&iso_numdesc, offset, 4);
            proto_tree_add_uint(tree, hf_usb_iso_numdesc, tvb, offset, 4, iso_numdesc);
            offset += 4;
        }

        /*
         * If this has a 64-byte header, process the extra 16 bytes of
         * pseudo-header information.
         */
        if (header_len_64_bytes) {
            guint32 ndesc;

            offset += 4;        /* interval */
            offset += 4;        /* start_frame */
            offset += 4;        /* copy of URB's transfer flags */

            tvb_memcpy(tvb, (guint8 *)&ndesc, offset, 4);
            offset += 4;

        }

        if (setup_flag != 0) {
            proto_tree *urb_tree = NULL;
            guint32 i;
            unsigned int data_base;
            guint32 iso_status;
            guint32 iso_off;
            guint32 iso_len;
            guint32 iso_pad;

            data_base = offset + iso_numdesc * 16;
            urb_tree = tree;
            for (i = 0; i != iso_numdesc; i++) {
                if (parent) {
                    proto_item *ti = NULL;
                    ti = proto_tree_add_protocol_format(urb_tree, proto_usb, tvb, offset,
                         16, "USB isodesc %u", i);
                    tree = proto_item_add_subtree(ti, usb_isodesc);
                }

                /* Add ISO descriptor fields which are stored in host
                 * endian byte order so use tvb_memcopy() and
                 * proto_tree_add_uint()/proto_tree_add_int() pair.
                 */
                tvb_memcpy(tvb, (guint8 *)&iso_status, offset, 4);
                proto_tree_add_int(tree, hf_usb_iso_status, tvb, offset, 4, iso_status);
                offset += 4;

                tvb_memcpy(tvb, (guint8 *)&iso_off, offset, 4);
                proto_tree_add_uint(tree, hf_usb_iso_off, tvb, offset, 4, iso_off);
                offset += 4;

                tvb_memcpy(tvb, (guint8 *)&iso_len, offset, 4);
                proto_tree_add_uint(tree, hf_usb_iso_len, tvb, offset, 4, iso_len);
                offset += 4;

                /* When the ISO status is OK and there is ISO data and this ISO data is
                 * fully captured then show this data.
                 */
                if (!iso_status && iso_len && data_base + iso_off + iso_len <= tvb_length(tvb))
                    proto_tree_add_item(tree, hf_usb_iso_data, tvb, data_base + iso_off, iso_len, ENC_NA);

                tvb_memcpy(tvb, (guint8 *)&iso_pad, offset, 4);
                proto_tree_add_uint(tree, hf_usb_iso_pad, tvb, offset, 4, iso_pad);
                offset += 4;
            }
            tree = urb_tree;
        }

        }
        break;

    default:
        /* dont know */
        if (setup_flag == 0) {
            proto_item *ti = NULL;
            proto_tree *setup_tree = NULL;
            int type_2;

            /* Dissect the setup header - it's applicable */

            ti = proto_tree_add_protocol_format(tree, proto_usb, tvb, offset, 8, "URB setup");
            setup_tree = proto_item_add_subtree(ti, usb_setup_hdr);

            offset=dissect_usb_bmrequesttype(setup_tree, tvb, offset, &type_2);
            proto_tree_add_item(setup_tree, hf_usb_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        } else {
            /* Skip setup/isochronous header - it's not applicable */
            offset += 8;
        }

        /*
         * If this has a 64-byte header, process the extra 16 bytes of
         * pseudo-header information.
         */
        if (header_len_64_bytes)
            offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);

        break;
    }

    if (tvb_reported_length_remaining(tvb, offset) != 0) {
        /* There is leftover capture data to add (padding?) */
        proto_tree_add_item(tree, hf_usb_capdata, tvb, offset, -1, ENC_NA);
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
    module_t *usb_module;
    static hf_register_info hf[] = {

    /* USB packet pseudoheader members */
        { &hf_usb_urb_id,
          { "URB id", "usb.urb_id", FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_urb_type,
          { "URB type", "usb.urb_type", FT_UINT8, BASE_DEC,
            VALS(usb_urb_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_transfer_type,
          { "URB transfer type", "usb.transfer_type", FT_UINT8, BASE_HEX,
            VALS(usb_transfer_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_endpoint_number,
          { "Endpoint", "usb.endpoint_number", FT_UINT8, BASE_HEX, NULL, 0x0,
            "USB endpoint number", HFILL }},

        { &hf_usb_endpoint_direction,
          { "Direction", "usb.endpoint_number.direction", FT_UINT8, BASE_DEC,
            VALS(usb_endpoint_direction_vals), 0x80,
            "USB endpoint direction", HFILL }},

        { &hf_usb_endpoint_number_value,
          { "Endpoint value", "usb.endpoint_number.endpoint", FT_UINT8, BASE_DEC,
            NULL, 0x7F,
            "USB endpoint value", HFILL }},

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
            "USB device setup request is relevant (0) or not", HFILL }},

        { &hf_usb_data_flag,
          { "Data", "usb.data_flag", FT_STRING, BASE_NONE,
            NULL, 0x0,
            "USB data is present (0) or not", HFILL }},

        { &hf_usb_urb_ts_sec,
          { "URB sec", "usb.urb_ts_sec", FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_urb_ts_usec,
          { "URB usec", "usb.urb_ts_usec", FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }},

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
        { &hf_usb_iso_error_count,                /* host endian byte order */
          { "ISO error count", "usb.iso.error_count", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_iso_numdesc,                    /* host endian byte order */
          { "Number of ISO descriptors", "usb.iso.numdesc", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        /* fields of struct mon_bin_isodesc from linux/drivers/usb/mon/mon_bin.c */
        { &hf_usb_iso_status,                     /* host endian byte order */
          { "Status", "usb.iso.iso_status", FT_INT32, BASE_DEC,
            VALS(usb_urb_status_vals), 0x0,
            "ISO descriptor status", HFILL }},

        { &hf_usb_iso_off,                        /* host endian byte order */
          { "Offset [bytes]", "usb.iso.iso_off", FT_UINT32, BASE_DEC, NULL, 0x0,
            "ISO data offset in bytes starting from the end of the last ISO descriptor", HFILL }},

        { &hf_usb_iso_len,                        /* host endian byte order */
          { "Length [bytes]", "usb.iso.iso_len", FT_UINT32, BASE_DEC, NULL, 0x0,
            "ISO data length in bytes", HFILL }},

        { &hf_usb_iso_pad,                        /* host endian byte order */
          { "Padding", "usb.iso._pad", FT_UINT32, BASE_HEX, NULL, 0x0,
            "Padding field of ISO descriptor structure", HFILL }},

        { &hf_usb_iso_data,
          {"ISO Data", "usb.iso.data",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
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
          { "Language Id", "usb.LanguageId", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
            &usb_langid_vals_ext, 0x0, NULL, HFILL }},

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
          { "wLANGID", "usb.wLANGID", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
            &usb_langid_vals_ext, 0x0, NULL, HFILL }},

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
        &usb_isodesc,
        &ett_usb_endpoint,
        &ett_usb_setup_bmrequesttype,
        &ett_descriptor_device,
        &ett_configuration_bmAttributes,
        &ett_configuration_bEndpointAddress,
        &ett_endpoint_bmAttributes
    };


    proto_usb = proto_register_protocol("USB", "USB", "usb");
    proto_register_field_array(proto_usb, hf, array_length(hf));
    proto_register_subtree_array(usb_subtrees, array_length(usb_subtrees));
    register_dissector("usb", dissect_linux_usb, proto_usb);

    usb_bulk_dissector_table = register_dissector_table("usb.bulk",
        "USB bulk endpoint", FT_UINT8, BASE_DEC);
    register_heur_dissector_list("usb.bulk", &heur_bulk_subdissector_list);
    usb_control_dissector_table = register_dissector_table("usb.control",
        "USB control endpoint", FT_UINT8, BASE_DEC);
    register_heur_dissector_list("usb.control", &heur_control_subdissector_list);
    usb_descriptor_dissector_table = register_dissector_table("usb.descriptor",
        "USB descriptor", FT_UINT8, BASE_DEC);

    usb_module = prefs_register_protocol(proto_usb, NULL);
    prefs_register_bool_preference(usb_module, "try_heuristics",
        "Try heuristic sub-dissectors",
        "Try to decode a packet using a heuristic sub-dissector before "
        "attempting to dissect the packet using the \"usb.bulk\" or "
        "\"usb.control\" dissector tables.", &try_heuristics);

    usb_tap=register_tap("usb");
}

void
proto_reg_handoff_usb(void)
{
    dissector_handle_t linux_usb_handle, linux_usb_mmapped_handle;

    linux_usb_handle = create_dissector_handle(dissect_linux_usb, proto_usb);
    linux_usb_mmapped_handle = create_dissector_handle(dissect_linux_usb_mmapped,
                                                       proto_usb);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_LINUX, linux_usb_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_LINUX_MMAPPED, linux_usb_mmapped_handle);
}
