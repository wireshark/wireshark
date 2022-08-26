/* packet-usb.c
 *
 * USB basic dissector
 * By Paolo Abeni <paolo.abeni@email.it>
 * Ronnie Sahlberg 2006
 *
 * http://www.usb.org/developers/docs/usb_20_122909-2.zip
 *
 * https://github.com/torvalds/linux/blob/master/Documentation/usb/usbmon.rst
 *
 * http://desowin.org/usbpcap/captureformat.html
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/addr_resolv.h>
#include <epan/address_types.h>
#include <epan/conversation_table.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <wsutil/pint.h>
#include <wsutil/ws_roundup.h>

#include "packet-usb.h"
#include "packet-mausb.h"
#include "packet-usbip.h"
#include "packet-netmon.h"

/* protocols and header fields */
static int proto_usb = -1;
static int proto_usbport = -1;

/* USB pseudoheader fields, both FreeBSD and Linux */
static int hf_usb_totlen = -1;
static int hf_usb_busunit = -1;
static int hf_usb_address = -1;
static int hf_usb_mode = -1;
static int hf_usb_freebsd_urb_type = -1;
static int hf_usb_freebsd_transfer_type = -1;
static int hf_usb_xferflags = -1;
static int hf_usb_xferflags_force_short_xfer = -1;
static int hf_usb_xferflags_short_xfer_ok = -1;
static int hf_usb_xferflags_short_frames_ok = -1;
static int hf_usb_xferflags_pipe_bof = -1;
static int hf_usb_xferflags_proxy_buffer = -1;
static int hf_usb_xferflags_ext_buffer = -1;
static int hf_usb_xferflags_manual_status = -1;
static int hf_usb_xferflags_no_pipe_ok = -1;
static int hf_usb_xferflags_stall_pipe = -1;
static int hf_usb_xferstatus = -1;
static int hf_usb_xferstatus_open = -1;
static int hf_usb_xferstatus_transferring = -1;
static int hf_usb_xferstatus_did_dma_delay = -1;
static int hf_usb_xferstatus_did_close = -1;
static int hf_usb_xferstatus_draining = -1;
static int hf_usb_xferstatus_started = -1;
static int hf_usb_xferstatus_bw_reclaimed = -1;
static int hf_usb_xferstatus_control_xfr = -1;
static int hf_usb_xferstatus_control_hdr = -1;
static int hf_usb_xferstatus_control_act = -1;
static int hf_usb_xferstatus_control_stall = -1;
static int hf_usb_xferstatus_short_frames_ok = -1;
static int hf_usb_xferstatus_short_xfer_ok = -1;
static int hf_usb_xferstatus_bdma_enable = -1;
static int hf_usb_xferstatus_bdma_no_post_sync = -1;
static int hf_usb_xferstatus_bdma_setup = -1;
static int hf_usb_xferstatus_isochronous_xfr = -1;
static int hf_usb_xferstatus_curr_dma_set = -1;
static int hf_usb_xferstatus_can_cancel_immed = -1;
static int hf_usb_xferstatus_doing_callback = -1;
static int hf_usb_error = -1;
static int hf_usb_interval = -1;
static int hf_usb_nframes = -1;
static int hf_usb_packet_size = -1;
static int hf_usb_packet_count = -1;
static int hf_usb_speed = -1;
static int hf_usb_frame_length = -1;
static int hf_usb_frame_flags = -1;
static int hf_usb_frame_flags_read = -1;
static int hf_usb_frame_flags_data_follows = -1;
static int hf_usb_frame_data = -1;
static int hf_usb_urb_id = -1;
static int hf_usb_linux_urb_type = -1;
static int hf_usb_linux_transfer_type = -1;
static int hf_usb_endpoint_address = -1;
static int hf_usb_endpoint_direction = -1;
static int hf_usb_endpoint_number = -1;
static int hf_usb_device_address = -1;
static int hf_usb_bus_id = -1;
static int hf_usb_setup_flag = -1;
static int hf_usb_data_flag = -1;
static int hf_usb_urb_ts_sec = -1;
static int hf_usb_urb_ts_usec = -1;
static int hf_usb_urb_status = -1;
static int hf_usb_urb_len = -1;
static int hf_usb_urb_data_len = -1;
static int hf_usb_urb_unused_setup_header = -1;
static int hf_usb_urb_interval = -1;
static int hf_usb_urb_start_frame = -1;
static int hf_usb_urb_copy_of_transfer_flags = -1;

/* transfer_flags */
static int hf_short_not_ok = -1;
static int hf_iso_asap = -1;
static int hf_no_transfer_dma_map = -1;
static int hf_no_fsbr = -1;
static int hf_zero_packet = -1;
static int hf_no_interrupt = -1;
static int hf_free_buffer = -1;
static int hf_dir_in = -1;
static int hf_dma_map_single = -1;
static int hf_dma_map_page = -1;
static int hf_dma_map_sg = -1;
static int hf_map_local = -1;
static int hf_setup_map_single = -1;
static int hf_setup_map_local = -1;
static int hf_dma_sg_combined = -1;
static int hf_aligned_temp_buffer = -1;

static int * const transfer_flags_fields[] = {
    &hf_short_not_ok,
    &hf_iso_asap,
    &hf_no_transfer_dma_map,
    &hf_no_fsbr,
    &hf_zero_packet,
    &hf_no_interrupt,
    &hf_free_buffer,
    &hf_dir_in,
    &hf_dma_map_single,
    &hf_dma_map_page,
    &hf_dma_map_sg,
    &hf_map_local,
    &hf_setup_map_single,
    &hf_setup_map_local,
    &hf_dma_sg_combined,
    &hf_aligned_temp_buffer,
    NULL
};

/* Win32 USBPcap pseudoheader fields */
static int hf_usb_win32_header_len = -1;
static int hf_usb_irp_id = -1;
static int hf_usb_usbd_status = -1;
static int hf_usb_function = -1;
static int hf_usb_info = -1;
static int hf_usb_usbpcap_info_reserved = -1;
static int hf_usb_usbpcap_info_direction = -1;
static int hf_usb_win32_device_address = -1;
static int hf_usb_win32_transfer_type = -1;
/* hf_usb_bus_id, hf_usb_endpoint_address, hf_usb_endpoint_direction,
 * hf_usb_endpoint_number are common with
 * FreeBSD and Linux pseudoheaders */
static int hf_usb_win32_data_len = -1;
static int hf_usb_win32_control_stage = -1;
static int hf_usb_win32_iso_start_frame = -1;
static int hf_usb_win32_iso_num_packets = -1;
static int hf_usb_win32_iso_error_count = -1;
static int hf_usb_win32_iso_offset = -1;
static int hf_usb_win32_iso_length = -1;
static int hf_usb_win32_iso_status = -1;

static int hf_usb_request = -1;
static int hf_usb_request_unknown_class = -1;
static int hf_usb_value = -1;
static int hf_usb_index = -1;
static int hf_usb_length = -1;
/* static int hf_usb_data_len = -1; */
static int hf_usb_capdata = -1;
static int hf_usb_device_wFeatureSelector = -1;
static int hf_usb_interface_wFeatureSelector = -1;
static int hf_usb_endpoint_wFeatureSelector = -1;
static int hf_usb_wInterface = -1;
static int hf_usb_wEndpoint = -1;
static int hf_usb_wStatus = -1;
static int hf_usb_wFrameNumber = -1;

static int hf_usb_iso_error_count = -1;
static int hf_usb_iso_numdesc = -1;
static int hf_usb_iso_status = -1;
static int hf_usb_iso_off = -1;
static int hf_usb_iso_len = -1;
static int hf_usb_iso_actual_len = -1;
static int hf_usb_iso_pad = -1;
static int hf_usb_iso_data = -1;

static int hf_usb_bmRequestType = -1;
static int hf_usb_control_response_generic = -1;
static int hf_usb_bmRequestType_direction = -1;
static int hf_usb_bmRequestType_type = -1;
static int hf_usb_bmRequestType_recipient = -1;
static int hf_usb_bDescriptorType = -1;
static int hf_usb_get_descriptor_resp_generic = -1;
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
static int hf_usb_bInterfaceSubClass_audio = -1;
static int hf_usb_bInterfaceSubClass_cdc = -1;
static int hf_usb_bInterfaceSubClass_massstorage = -1;
static int hf_usb_bInterfaceSubClass_hid = -1;
static int hf_usb_bInterfaceSubClass_misc = -1;
static int hf_usb_bInterfaceSubClass_app = -1;
static int hf_usb_bInterfaceProtocol = -1;
static int hf_usb_bInterfaceProtocol_cdc = -1;
static int hf_usb_bInterfaceProtocol_massstorage = -1;
static int hf_usb_bInterfaceProtocol_cdc_data = -1;
static int hf_usb_bInterfaceProtocol_hid_boot = -1;
static int hf_usb_bInterfaceProtocol_app_dfu = -1;
static int hf_usb_bInterfaceProtocol_app_irda = -1;
static int hf_usb_bInterfaceProtocol_app_usb_test_and_measurement = -1;
static int hf_usb_iInterface = -1;
static int hf_usb_bEndpointAddress = -1;
static int hf_usb_bmAttributes = -1;
static int hf_usb_bEndpointAttributeTransfer = -1;
static int hf_usb_bEndpointAttributeSynchonisation = -1;
static int hf_usb_bEndpointAttributeBehaviour = -1;
static int hf_usb_wMaxPacketSize = -1;
static int hf_usb_wMaxPacketSize_size = -1;
static int hf_usb_wMaxPacketSize_slots = -1;
static int hf_usb_bInterval = -1;
static int hf_usb_bMaxBurst = -1;
static int hf_usb_audio_bRefresh = -1;
static int hf_usb_audio_bSynchAddress = -1;
static int hf_usb_bSSEndpointAttributeBulkMaxStreams = -1;
static int hf_usb_bSSEndpointAttributeIsoMult = -1;
static int hf_usb_wBytesPerInterval = -1;
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
static int hf_usb_bFirstInterface = -1;
static int hf_usb_bInterfaceCount = -1;
static int hf_usb_bFunctionClass = -1;
static int hf_usb_bFunctionSubClass = -1;
static int hf_usb_bFunctionProtocol = -1;
static int hf_usb_iFunction = -1;
static int hf_usb_data_fragment = -1;
static int hf_usb_src = -1;
static int hf_usb_dst = -1;
static int hf_usb_addr = -1;

/* macOS */
static int hf_usb_darwin_bcd_version = -1;
static int hf_usb_darwin_header_len = -1;
static int hf_usb_darwin_request_type = -1;
static int hf_usb_darwin_io_len = -1;
static int hf_usb_darwin_io_status = -1;
static int hf_usb_darwin_iso_num_packets = -1;
static int hf_usb_darwin_io_id = -1;
static int hf_usb_darwin_device_location = -1;
static int hf_usb_darwin_speed = -1;
static int hf_usb_darwin_device_address = -1;
static int hf_usb_darwin_endpoint_address = -1;
static int hf_usb_darwin_endpoint_type = -1;
static int hf_usb_darwin_iso_status = -1;
static int hf_usb_darwin_iso_frame_number = -1;
static int hf_usb_darwin_iso_timestamp = -1;

/* NetMon */
static int hf_usbport_event_id = -1;
static int hf_usbport_device_object = -1;
static int hf_usbport_pci_bus = -1;
static int hf_usbport_pci_device = -1;
static int hf_usbport_pci_function = -1;
static int hf_usbport_pci_vendor_id = -1;
static int hf_usbport_pci_device_id = -1;
static int hf_usbport_port_path_depth = -1;
static int hf_usbport_port_path0 = -1;
static int hf_usbport_port_path1 = -1;
static int hf_usbport_port_path2 = -1;
static int hf_usbport_port_path3 = -1;
static int hf_usbport_port_path4 = -1;
static int hf_usbport_port_path5 = -1;
static int hf_usbport_device_handle = -1;
static int hf_usbport_device_speed = -1;
static int hf_usbport_endpoint = -1;
static int hf_usbport_pipehandle = -1;
static int hf_usbport_endpoint_desc_length = -1;
static int hf_usbport_endpoint_desc_type = -1;
static int hf_usbport_endpoint_address = -1;
static int hf_usbport_bm_attributes = -1;
static int hf_usbport_max_packet_size = -1;
static int hf_usbport_interval = -1;
static int hf_usbport_irp = -1;
static int hf_usbport_urb = -1;
static int hf_usbport_urb_transfer_data = -1;
static int hf_usbport_urb_header_length = -1;
static int hf_usbport_urb_header_function = -1;
static int hf_usbport_urb_header_status = -1;
static int hf_usbport_urb_header_usbddevice_handle = -1;
static int hf_usbport_urb_header_usbdflags = -1;
static int hf_usbport_urb_configuration_desc = -1;
static int hf_usbport_urb_configuration_handle = -1;
static int hf_usbport_urb_pipe_handle = -1;
static int hf_usbport_urb_xferflags = -1;
static int hf_usbport_urb_transfer_buffer_length = -1;
static int hf_usbport_urb_transfer_buffer = -1;
static int hf_usbport_urb_transfer_buffer_mdl = -1;
static int hf_usbport_urb_reserved_mbz = -1;
static int hf_usbport_urb_reserved_hcd = -1;
static int hf_usbport_urb_reserved = -1;
static int hf_usbport_keyword = -1;
static int hf_usbport_keyword_diagnostic = -1;
static int hf_usbport_keyword_power_diagnostics = -1;
static int hf_usbport_keyword_perf_diagnostics = -1;
static int hf_usbport_keyword_reserved1 = -1;

static gint ett_usb_hdr = -1;
static gint ett_usb_setup_hdr = -1;
static gint ett_usb_isodesc = -1;
static gint ett_usb_win32_iso_packet = -1;
static gint ett_usb_endpoint = -1;
static gint ett_usb_setup_bmrequesttype = -1;
static gint ett_usb_usbpcap_info = -1;
static gint ett_descriptor_device = -1;
static gint ett_configuration_bmAttributes = -1;
static gint ett_configuration_bEndpointAddress = -1;
static gint ett_endpoint_bmAttributes = -1;
static gint ett_endpoint_wMaxPacketSize = -1;
static gint ett_usb_xferflags = -1;
static gint ett_usb_xferstatus = -1;
static gint ett_usb_frame = -1;
static gint ett_usb_frame_flags = -1;
static gint ett_usbport = -1;
static gint ett_usbport_host_controller = -1;
static gint ett_usbport_path = -1;
static gint ett_usbport_device = -1;
static gint ett_usbport_endpoint = -1;
static gint ett_usbport_endpoint_desc = -1;
static gint ett_usbport_urb = -1;
static gint ett_usbport_keyword = -1;
static gint ett_transfer_flags = -1;

static expert_field ei_usb_undecoded = EI_INIT;
static expert_field ei_usb_bLength_even = EI_INIT;
static expert_field ei_usb_bLength_too_short = EI_INIT;
static expert_field ei_usb_desc_length_invalid = EI_INIT;
static expert_field ei_usb_invalid_setup = EI_INIT;
static expert_field ei_usb_ss_ep_companion_before_ep = EI_INIT;
static expert_field ei_usb_usbpcap_unknown_urb = EI_INIT;
static expert_field ei_usb_bad_length = EI_INIT;
static expert_field ei_usb_invalid_max_packet_size = EI_INIT;
static expert_field ei_usb_invalid_max_packet_size0 = EI_INIT;
static expert_field ei_usb_invalid_endpoint_type = EI_INIT;

static expert_field ei_usbport_invalid_path_depth = EI_INIT;

static int usb_address_type = -1;

static int * const usb_endpoint_fields[] = {
    &hf_usb_endpoint_direction,
    &hf_usb_endpoint_number,
    NULL
};

static int * const usb_usbpcap_info_fields[] = {
    &hf_usb_usbpcap_info_reserved,
    &hf_usb_usbpcap_info_direction,
    NULL
};

static int usb_tap = -1;
static gboolean try_heuristics = TRUE;

static dissector_table_t usb_bulk_dissector_table;
static dissector_table_t usb_control_dissector_table;
static dissector_table_t usb_interrupt_dissector_table;
static dissector_table_t usb_descriptor_dissector_table;

static heur_dissector_list_t heur_bulk_subdissector_list;
static heur_dissector_list_t heur_control_subdissector_list;
static heur_dissector_list_t heur_interrupt_subdissector_list;

static wmem_tree_t *device_to_protocol_table = NULL;
static wmem_tree_t *device_to_product_table  = NULL;
static wmem_tree_t *usbpcap_setup_data       = NULL;

static dissector_table_t device_to_dissector;
static dissector_table_t protocol_to_dissector;
static dissector_table_t product_to_dissector;

typedef struct _device_product_data_t {
    guint16  vendor;
    guint16  product;
    guint16  device;
    guint  bus_id;
    guint  device_address;
} device_product_data_t;

typedef struct _device_protocol_data_t {
    guint32  protocol;
    guint  bus_id;
    guint  device_address;
} device_protocol_data_t;

typedef struct _usb_alt_setting_t {
    guint8 altSetting;
    guint8 interfaceClass;
    guint8 interfaceSubclass;
    guint8 interfaceProtocol;
    guint8 interfaceNum;
} usb_alt_setting_t;

typedef struct {
    guint64 usb_id;
    guint8 setup_data[8];
} usbpcap_setup_data_t;

static const value_string usb_speed_vals[] = {
    {USB_SPEED_UNKNOWN, "Unknown Speed"},
    {USB_SPEED_LOW,     "Low-Speed"},
    {USB_SPEED_FULL,    "Full-Speed"},
    {USB_SPEED_HIGH,    "High-Speed"},
    {0, NULL}
};

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
value_string_ext usb_langid_vals_ext = VALUE_STRING_EXT_INIT(usb_langid_vals);

static const value_string usb_class_vals[] = {
    {IF_CLASS_DEVICE,                   "Device"},
    {IF_CLASS_AUDIO,                    "Audio"},
    {IF_CLASS_COMMUNICATIONS,           "Communications and CDC Control"},
    {IF_CLASS_HID,                      "HID"},
    {IF_CLASS_PHYSICAL,                 "Physical"},
    {IF_CLASS_IMAGE,                    "Imaging"},
    {IF_CLASS_PRINTER,                  "Printer"},
    {IF_CLASS_MASS_STORAGE,             "Mass Storage"},
    {IF_CLASS_HUB,                      "Hub"},
    {IF_CLASS_CDC_DATA,                 "CDC-Data"},
    {IF_CLASS_SMART_CARD,               "Smart Card"},
    {IF_CLASS_CONTENT_SECURITY,         "Content Security"},
    {IF_CLASS_VIDEO,                    "Video"},
    {IF_CLASS_PERSONAL_HEALTHCARE,      "Personal Healthcare"},
    {IF_CLASS_AUDIO_VIDEO,              "Audio/Video Devices"},
    {IF_CLASS_DIAGNOSTIC_DEVICE,        "Diagnostic Device"},
    {IF_CLASS_WIRELESS_CONTROLLER,      "Wireless Controller"},
    {IF_CLASS_MISCELLANEOUS,            "Miscellaneous"},
    {IF_CLASS_APPLICATION_SPECIFIC,     "Application Specific"},
    {IF_CLASS_VENDOR_SPECIFIC,          "Vendor Specific"},
    {0, NULL}
};
value_string_ext usb_class_vals_ext = VALUE_STRING_EXT_INIT(usb_class_vals);

/* use usb class, subclass and protocol id together
  http://www.usb.org/developers/defined_class
  USB Class Definitions for Communications Devices, Revision 1.2 December 6, 2012
*/
static const value_string usb_protocols[] = {
    {0x000000,    "Use class code info from Interface Descriptors"},
    {0x060101,    "Still Imaging"},
    {0x090000,    "Full speed Hub"},
    {0x090001,    "Hi-speed hub with single TT"},
    {0x090002,    "Hi-speed hub with multiple TTs"},
    {0x0D0000,    "Content Security"},
    {0x100100,    "AVControl Interface"},
    {0x100200,    "AVData Video Streaming Interface"},
    {0x100300,    "AVData Audio Streaming Interface"},
    {0xDC0101,    "USB2 Compliance Device"},
    {0xE00101,    "Bluetooth Programming Interface"},
    {0xE00102,    "UWB Radio Control Interface"},
    {0xE00103,    "Remote NDIS"},
    {0xE00104,    "Bluetooth AMP Controller"},
    {0xE00201,    "Host Wire Adapter Control/Data interface"},
    {0xE00202,    "Device Wire Adapter Control/Data interface"},
    {0xE00203,    "Device Wire Adapter Isochronous interface"},
    {0xEF0101,    "Active Sync device"},
    {0xEF0102,    "Palm Sync"},
    {0xEF0201,    "Interface Association Descriptor"},
    {0xEF0202,    "Wire Adapter Multifunction Peripheral programming interface"},
    {0xEF0301,    "Cable Based Association Framework"},
    {0xFE0101,    "Device Firmware Upgrade"},
    {0xFE0200,    "IRDA Bridge device"},
    {0xFE0300,    "USB Test and Measurement Device"},
    {0xFE0301,    "USB Test and Measurement Device conforming to the USBTMC USB488"},
    {0, NULL}
};
static value_string_ext usb_protocols_ext = VALUE_STRING_EXT_INIT(usb_protocols);

/* FreeBSD header */

/* Transfer mode */
#define FREEBSD_MODE_HOST       0
#define FREEBSD_MODE_DEVICE     1
static const value_string usb_freebsd_transfer_mode_vals[] = {
    {FREEBSD_MODE_HOST,   "Host"},
    {FREEBSD_MODE_DEVICE, "Device"},
    {0, NULL}
};

/* Type */
#define FREEBSD_URB_SUBMIT   0
#define FREEBSD_URB_COMPLETE 1
static const value_string usb_freebsd_urb_type_vals[] = {
    {FREEBSD_URB_SUBMIT,   "URB_SUBMIT"},
    {FREEBSD_URB_COMPLETE, "URB_COMPLETE"},
    {0, NULL}
};

/* Transfer type */
#define FREEBSD_URB_CONTROL     0
#define FREEBSD_URB_ISOCHRONOUS 1
#define FREEBSD_URB_BULK        2
#define FREEBSD_URB_INTERRUPT   3

static const value_string usb_freebsd_transfer_type_vals[] = {
    {FREEBSD_URB_CONTROL,     "URB_CONTROL"},
    {FREEBSD_URB_ISOCHRONOUS, "URB_ISOCHRONOUS"},
    {FREEBSD_URB_BULK,        "URB_BULK"},
    {FREEBSD_URB_INTERRUPT,   "URB_INTERRUPT"},
    {0, NULL}
};

/* Transfer flags */
#define FREEBSD_FLAG_FORCE_SHORT_XFER 0x00000001
#define FREEBSD_FLAG_SHORT_XFER_OK    0x00000002
#define FREEBSD_FLAG_SHORT_FRAMES_OK  0x00000004
#define FREEBSD_FLAG_PIPE_BOF         0x00000008
#define FREEBSD_FLAG_PROXY_BUFFER     0x00000010
#define FREEBSD_FLAG_EXT_BUFFER       0x00000020
#define FREEBSD_FLAG_MANUAL_STATUS    0x00000040
#define FREEBSD_FLAG_NO_PIPE_OK       0x00000080
#define FREEBSD_FLAG_STALL_PIPE       0x00000100

static int * const usb_xferflags_fields[] = {
    &hf_usb_xferflags_force_short_xfer,
    &hf_usb_xferflags_short_xfer_ok,
    &hf_usb_xferflags_short_frames_ok,
    &hf_usb_xferflags_pipe_bof,
    &hf_usb_xferflags_proxy_buffer,
    &hf_usb_xferflags_ext_buffer,
    &hf_usb_xferflags_manual_status,
    &hf_usb_xferflags_no_pipe_ok,
    &hf_usb_xferflags_stall_pipe,
    NULL
};

/* Transfer status */
#define FREEBSD_STATUS_OPEN              0x00000001
#define FREEBSD_STATUS_TRANSFERRING      0x00000002
#define FREEBSD_STATUS_DID_DMA_DELAY     0x00000004
#define FREEBSD_STATUS_DID_CLOSE         0x00000008
#define FREEBSD_STATUS_DRAINING          0x00000010
#define FREEBSD_STATUS_STARTED           0x00000020
#define FREEBSD_STATUS_BW_RECLAIMED      0x00000040
#define FREEBSD_STATUS_CONTROL_XFR       0x00000080
#define FREEBSD_STATUS_CONTROL_HDR       0x00000100
#define FREEBSD_STATUS_CONTROL_ACT       0x00000200
#define FREEBSD_STATUS_CONTROL_STALL     0x00000400
#define FREEBSD_STATUS_SHORT_FRAMES_OK   0x00000800
#define FREEBSD_STATUS_SHORT_XFER_OK     0x00001000
#define FREEBSD_STATUS_BDMA_ENABLE       0x00002000
#define FREEBSD_STATUS_BDMA_NO_POST_SYNC 0x00004000
#define FREEBSD_STATUS_BDMA_SETUP        0x00008000
#define FREEBSD_STATUS_ISOCHRONOUS_XFR   0x00010000
#define FREEBSD_STATUS_CURR_DMA_SET      0x00020000
#define FREEBSD_STATUS_CAN_CANCEL_IMMED  0x00040000
#define FREEBSD_STATUS_DOING_CALLBACK    0x00080000

static int * const usb_xferstatus_fields[] = {
    &hf_usb_xferstatus_open,
    &hf_usb_xferstatus_transferring,
    &hf_usb_xferstatus_did_dma_delay,
    &hf_usb_xferstatus_did_close,
    &hf_usb_xferstatus_draining,
    &hf_usb_xferstatus_started,
    &hf_usb_xferstatus_bw_reclaimed,
    &hf_usb_xferstatus_control_xfr,
    &hf_usb_xferstatus_control_hdr,
    &hf_usb_xferstatus_control_act,
    &hf_usb_xferstatus_control_stall,
    &hf_usb_xferstatus_short_frames_ok,
    &hf_usb_xferstatus_short_xfer_ok,
    &hf_usb_xferstatus_bdma_enable,
    &hf_usb_xferstatus_bdma_no_post_sync,
    &hf_usb_xferstatus_bdma_setup,
    &hf_usb_xferstatus_isochronous_xfr,
    &hf_usb_xferstatus_curr_dma_set,
    &hf_usb_xferstatus_can_cancel_immed,
    &hf_usb_xferstatus_doing_callback,
    NULL
};

/* USB errors */
#define FREEBSD_ERR_NORMAL_COMPLETION 0
#define FREEBSD_ERR_PENDING_REQUESTS  1
#define FREEBSD_ERR_NOT_STARTED       2
#define FREEBSD_ERR_INVAL             3
#define FREEBSD_ERR_NOMEM             4
#define FREEBSD_ERR_CANCELLED         5
#define FREEBSD_ERR_BAD_ADDRESS       6
#define FREEBSD_ERR_BAD_BUFSIZE       7
#define FREEBSD_ERR_BAD_FLAG          8
#define FREEBSD_ERR_NO_CALLBACK       9
#define FREEBSD_ERR_IN_USE            10
#define FREEBSD_ERR_NO_ADDR           11
#define FREEBSD_ERR_NO_PIPE           12
#define FREEBSD_ERR_ZERO_NFRAMES      13
#define FREEBSD_ERR_ZERO_MAXP         14
#define FREEBSD_ERR_SET_ADDR_FAILED   15
#define FREEBSD_ERR_NO_POWER          16
#define FREEBSD_ERR_TOO_DEEP          17
#define FREEBSD_ERR_IOERROR           18
#define FREEBSD_ERR_NOT_CONFIGURED    19
#define FREEBSD_ERR_TIMEOUT           20
#define FREEBSD_ERR_SHORT_XFER        21
#define FREEBSD_ERR_STALLED           22
#define FREEBSD_ERR_INTERRUPTED       23
#define FREEBSD_ERR_DMA_LOAD_FAILED   24
#define FREEBSD_ERR_BAD_CONTEXT       25
#define FREEBSD_ERR_NO_ROOT_HUB       26
#define FREEBSD_ERR_NO_INTR_THREAD    27
#define FREEBSD_ERR_NOT_LOCKED        28

static const value_string usb_freebsd_err_vals[] = {
    {FREEBSD_ERR_NORMAL_COMPLETION, "Normal completion"},
    {FREEBSD_ERR_PENDING_REQUESTS,  "Pending requests"},
    {FREEBSD_ERR_NOT_STARTED,       "Not started"},
    {FREEBSD_ERR_INVAL,             "Invalid"},
    {FREEBSD_ERR_NOMEM,             "No memory"},
    {FREEBSD_ERR_CANCELLED,         "Cancelled"},
    {FREEBSD_ERR_BAD_ADDRESS,       "Bad address"},
    {FREEBSD_ERR_BAD_BUFSIZE,       "Bad buffer size"},
    {FREEBSD_ERR_BAD_FLAG,          "Bad flag"},
    {FREEBSD_ERR_NO_CALLBACK,       "No callback"},
    {FREEBSD_ERR_IN_USE,            "In use"},
    {FREEBSD_ERR_NO_ADDR,           "No address"},
    {FREEBSD_ERR_NO_PIPE,           "No pipe"},
    {FREEBSD_ERR_ZERO_NFRAMES,      "Number of frames is zero"},
    {FREEBSD_ERR_ZERO_MAXP,         "MAXP is zero"},
    {FREEBSD_ERR_SET_ADDR_FAILED,   "Set address failed"},
    {FREEBSD_ERR_NO_POWER,          "No power"},
    {FREEBSD_ERR_TOO_DEEP,          "Too deep"},
    {FREEBSD_ERR_IOERROR,           "I/O error"},
    {FREEBSD_ERR_NOT_CONFIGURED,    "Not configured"},
    {FREEBSD_ERR_TIMEOUT,           "Timeout"},
    {FREEBSD_ERR_SHORT_XFER,        "Short transfer"},
    {FREEBSD_ERR_STALLED,           "Stalled"},
    {FREEBSD_ERR_INTERRUPTED,       "Interrupted"},
    {FREEBSD_ERR_DMA_LOAD_FAILED,   "DMA load failed"},
    {FREEBSD_ERR_BAD_CONTEXT,       "Bad context"},
    {FREEBSD_ERR_NO_ROOT_HUB,       "No root hub"},
    {FREEBSD_ERR_NO_INTR_THREAD,    "No interrupt thread"},
    {FREEBSD_ERR_NOT_LOCKED,        "Not locked"},
    {0, NULL}
};

/* USB speeds */
#define FREEBSD_SPEED_VARIABLE 0
#define FREEBSD_SPEED_LOW      1
#define FREEBSD_SPEED_FULL     2
#define FREEBSD_SPEED_HIGH     3
#define FREEBSD_SPEED_SUPER    4

static const value_string usb_freebsd_speed_vals[] = {
    {FREEBSD_SPEED_VARIABLE, "Variable"},
    {FREEBSD_SPEED_LOW,      "Low"},
    {FREEBSD_SPEED_FULL,     "Full"},
    {FREEBSD_SPEED_HIGH,     "High"},
    {FREEBSD_SPEED_SUPER,    "Super"},
    {0, NULL}
};

/* Frame flags */
#define FREEBSD_FRAMEFLAG_READ         0x00000001
#define FREEBSD_FRAMEFLAG_DATA_FOLLOWS 0x00000002

static int * const usb_frame_flags_fields[] = {
    &hf_usb_frame_flags_read,
    &hf_usb_frame_flags_data_follows,
    NULL
};

static const value_string usb_linux_urb_type_vals[] = {
    {URB_SUBMIT,   "URB_SUBMIT"},
    {URB_COMPLETE, "URB_COMPLETE"},
    {URB_ERROR,    "URB_ERROR"},
    {0, NULL}
};

static const value_string usb_linux_transfer_type_vals[] = {
    {URB_CONTROL,                       "URB_CONTROL"},
    {URB_ISOCHRONOUS,                   "URB_ISOCHRONOUS"},
    {URB_INTERRUPT,                     "URB_INTERRUPT"},
    {URB_BULK,                          "URB_BULK"},
    {0, NULL}
};

static const value_string usb_transfer_type_and_direction_vals[] = {
    {URB_CONTROL,                       "URB_CONTROL out"},
    {URB_ISOCHRONOUS,                   "URB_ISOCHRONOUS out"},
    {URB_INTERRUPT,                     "URB_INTERRUPT out"},
    {URB_BULK,                          "URB_BULK out"},
    {URB_CONTROL | URB_TRANSFER_IN,     "URB_CONTROL in"},
    {URB_ISOCHRONOUS | URB_TRANSFER_IN, "URB_ISOCHRONOUS in"},
    {URB_INTERRUPT | URB_TRANSFER_IN,   "URB_INTERRUPT in"},
    {URB_BULK | URB_TRANSFER_IN,        "URB_BULK in"},
    {0, NULL}
};

static const value_string usb_endpoint_direction_vals[] = {
    {0, "OUT"},
    {1, "IN"},
    {0, NULL}
};

extern value_string_ext ext_usb_vendors_vals;
extern value_string_ext ext_usb_products_vals;
extern value_string_ext ext_usb_audio_subclass_vals;
extern value_string_ext ext_usb_com_subclass_vals;
extern value_string_ext ext_usb_massstorage_subclass_vals;
extern value_string_ext linux_negative_errno_vals_ext;

/*
 * Standard descriptor types.
 *
 * all class specific descriptor types were removed from this list
 * a descriptor type is not globally unique
 * dissectors for the USB classes should provide their own value string
 *  and pass it to dissect_usb_descriptor_header()
 *
 */
#define USB_DT_DEVICE                          1
#define USB_DT_CONFIG                          2
#define USB_DT_STRING                          3
#define USB_DT_INTERFACE                       4
#define USB_DT_ENDPOINT                        5
#define USB_DT_DEVICE_QUALIFIER                6
#define USB_DT_OTHER_SPEED_CONFIG              7
#define USB_DT_INTERFACE_POWER                 8
/* these are from a minor usb 2.0 revision (ECN) */
#define USB_DT_OTG                             9
#define USB_DT_DEBUG                          10
#define USB_DT_INTERFACE_ASSOCIATION          11
/* these are from usb 3.0 specification */
#define USB_DT_BOS                          0x0F
#define USB_DT_DEVICE_CAPABILITY            0x10
#define USB_DT_SUPERSPEED_EP_COMPANION      0x30
/* these are from usb 3.1 specification */
#define USB_DT_SUPERSPEED_ISO_EP_COMPANION  0x31

/* There are only Standard Descriptor Types, Class-specific types are
   provided by "usb.descriptor" descriptors table*/
static const value_string std_descriptor_type_vals[] = {
    {USB_DT_DEVICE,                         "DEVICE"},
    {USB_DT_CONFIG,                         "CONFIGURATION"},
    {USB_DT_STRING,                         "STRING"},
    {USB_DT_INTERFACE,                      "INTERFACE"},
    {USB_DT_ENDPOINT,                       "ENDPOINT"},
    {USB_DT_DEVICE_QUALIFIER,               "DEVICE QUALIFIER"},
    {USB_DT_OTHER_SPEED_CONFIG,             "OTHER SPEED CONFIG"},
    {USB_DT_INTERFACE_POWER,                "INTERFACE POWER"},
    {USB_DT_OTG,                            "OTG"},
    {USB_DT_DEBUG,                          "DEBUG"},
    {USB_DT_INTERFACE_ASSOCIATION,          "INTERFACE ASSOCIATION"},
    {USB_DT_BOS,                            "BOS"},
    {USB_DT_DEVICE_CAPABILITY,              "DEVICE CAPABILITY"},
    {USB_DT_SUPERSPEED_EP_COMPANION,        "SUPERSPEED USB ENDPOINT COMPANION"},
    {USB_DT_SUPERSPEED_ISO_EP_COMPANION,    "SUPERSPEED PLUS ISOCHRONOUS ENDPOINT COMPANION"},
    {0,NULL}
};
static value_string_ext std_descriptor_type_vals_ext =
               VALUE_STRING_EXT_INIT(std_descriptor_type_vals);

/*
 * Feature selectors.
 * Per USB 3.1 spec, Table 9-7
 */
#define USB_FS_ENDPOINT_HALT            0
#define USB_FS_FUNCTION_SUSPEND         0 /* same as ENDPOINT_HALT */
#define USB_FS_DEVICE_REMOTE_WAKEUP     1
#define USB_FS_TEST_MODE                2
#define USB_FS_B_HNP_ENABLE             3
#define USB_FS_A_HNP_SUPPORT            4
#define USB_FS_A_ALT_HNP_SUPPORT        5
#define USB_FS_WUSB_DEVICE              6
#define USB_FS_U1_ENABLE                48
#define USB_FS_U2_ENABLE                49
#define USB_FS_LTM_ENABLE               50
#define USB_FS_B3_NTF_HOST_REL          51
#define USB_FS_B3_RSP_ENABLE            52
#define USB_FS_LDM_ENABLE               53

static const value_string usb_endpoint_feature_selector_vals[] = {
    {USB_FS_ENDPOINT_HALT,              "ENDPOINT HALT"},
    {0, NULL}
};

static const value_string usb_interface_feature_selector_vals[] = {
    {USB_FS_FUNCTION_SUSPEND,           "FUNCTION SUSPEND"},
    {0, NULL}
};

static const value_string usb_device_feature_selector_vals[] = {
    {USB_FS_DEVICE_REMOTE_WAKEUP,       "DEVICE REMOTE WAKEUP"},
    {USB_FS_TEST_MODE,                  "TEST MODE"},
    {USB_FS_B_HNP_ENABLE,               "B HNP ENABLE"},
    {USB_FS_A_HNP_SUPPORT,              "A HNP SUPPORT"},
    {USB_FS_A_ALT_HNP_SUPPORT,          "A ALT HNP SUPPORT"},
    {USB_FS_WUSB_DEVICE,                "WUSB DEVICE"},
    {USB_FS_U1_ENABLE,                  "U1 ENABLE"},
    {USB_FS_U2_ENABLE,                  "U2 ENABLE"},
    {USB_FS_LTM_ENABLE,                 "LTM ENABLE"},
    {USB_FS_B3_NTF_HOST_REL,            "B3 NTF HOST REL"},
    {USB_FS_B3_RSP_ENABLE,              "B3 RSP ENABLE"},
    {USB_FS_LDM_ENABLE,                 "LDM ENABLE"},
    {0, NULL}
};


/* the transfer type in the endpoint descriptor, i.e. the type of the endpoint
   (this is not the same as the URB transfer type) */
#define USB_EP_CONTROL     0x00
#define USB_EP_ISOCHRONOUS 0x01
#define USB_EP_BULK        0x02
#define USB_EP_INTERRUPT   0x03

static const value_string usb_bmAttributes_transfer_vals[] = {
    {USB_EP_CONTROL,     "Control-Transfer"},
    {USB_EP_ISOCHRONOUS, "Isochronous-Transfer"},
    {USB_EP_BULK,        "Bulk-Transfer"},
    {USB_EP_INTERRUPT,   "Interrupt-Transfer"},
    {0, NULL}
};

static const value_string usb_bmAttributes_sync_vals[] = {
    {0x00,      "No Sync"},
    {0x01,      "Asynchronous"},
    {0x02,      "Adaptive"},
    {0x03,      "Synchronous"},
    {0, NULL}
};

static const value_string usb_bmAttributes_behaviour_vals[] = {
    {0x00,      "Data-Endpoint"},
    {0x01,      "Explicit Feedback-Endpoint"},
    {0x02,      "Implicit Feedback-Data-Endpoint"},
    {0x03,      "Reserved"},
    {0, NULL}
};

static const value_string usb_wMaxPacketSize_slots_vals[]  = {
    {0x00,      "1"},
    {0x01,      "2"},
    {0x02,      "3"},
    {0x03,      "Reserved"},
    {0, NULL}
};

/* USBPcap versions up to 1.4.1.0 captures USB control as 2 or 3 packets:
 *   * SETUP with 8 bytes of Setup data
 *   * DATA with optional data (either OUT or IN)
 *   * STATUS without any USB payload, only the pseudoheader
 *
 * USBPcap versions 1.5.0.0 and up captures USB control as 2 packets:
 *   * SETUP with 8 bytes of Setup data and optional DATA OUT
 *   * COMPLETE with optional DATA IN
 *
 * The SETUP/COMPLETE matches the way control transfers are captured by
 * usbmon on Linux.
 */
#define USB_CONTROL_STAGE_SETUP    0x00
#define USB_CONTROL_STAGE_DATA     0x01
#define USB_CONTROL_STAGE_STATUS   0x02
#define USB_CONTROL_STAGE_COMPLETE 0x03

static const value_string usb_control_stage_vals[] = {
    {USB_CONTROL_STAGE_SETUP,    "Setup"},
    {USB_CONTROL_STAGE_DATA,     "Data"},
    {USB_CONTROL_STAGE_STATUS,   "Status"},
    {USB_CONTROL_STAGE_COMPLETE, "Complete"},
    {0, NULL}
};

/* Extra URB code to indicate relevant USB IRPs that don't directly
 * have any matching USB transfer.
 */
#define USBPCAP_URB_IRP_INFO 0xFE

static const value_string win32_usb_transfer_type_vals[] = {
    {URB_CONTROL,                       "URB_CONTROL"},
    {URB_ISOCHRONOUS,                   "URB_ISOCHRONOUS"},
    {URB_INTERRUPT,                     "URB_INTERRUPT"},
    {URB_BULK,                          "URB_BULK"},
    {USBPCAP_URB_IRP_INFO,              "USB IRP Info"},
    {0, NULL}
};

static const value_string win32_urb_function_vals[] = {
    {0x0000, "URB_FUNCTION_SELECT_CONFIGURATION"},
    {0x0001, "URB_FUNCTION_SELECT_INTERFACE"},
    {0x0002, "URB_FUNCTION_ABORT_PIPE"},
    {0x0003, "URB_FUNCTION_TAKE_FRAME_LENGTH_CONTROL"},
    {0x0004, "URB_FUNCTION_RELEASE_FRAME_LENGTH_CONTROL"},
    {0x0005, "URB_FUNCTION_GET_FRAME_LENGTH"},
    {0x0006, "URB_FUNCTION_SET_FRAME_LENGTH"},
    {0x0007, "URB_FUNCTION_GET_CURRENT_FRAME_NUMBER"},
    {0x0008, "URB_FUNCTION_CONTROL_TRANSFER"},
    {0x0009, "URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER"},
    {0x000A, "URB_FUNCTION_ISOCH_TRANSFER"},
    {0x000B, "URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE"},
    {0x000C, "URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE"},
    {0x000D, "URB_FUNCTION_SET_FEATURE_TO_DEVICE"},
    {0x000E, "URB_FUNCTION_SET_FEATURE_TO_INTERFACE"},
    {0x000F, "URB_FUNCTION_SET_FEATURE_TO_ENDPOINT"},
    {0x0010, "URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE"},
    {0x0011, "URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE"},
    {0x0012, "URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT"},
    {0x0013, "URB_FUNCTION_GET_STATUS_FROM_DEVICE"},
    {0x0014, "URB_FUNCTION_GET_STATUS_FROM_INTERFACE"},
    {0x0015, "URB_FUNCTION_GET_STATUS_FROM_ENDPOINT"},
    {0x0016, "URB_FUNCTION_RESERVED_0X0016"},
    {0x0017, "URB_FUNCTION_VENDOR_DEVICE"},
    {0x0018, "URB_FUNCTION_VENDOR_INTERFACE"},
    {0x0019, "URB_FUNCTION_VENDOR_ENDPOINT"},
    {0x001A, "URB_FUNCTION_CLASS_DEVICE"},
    {0x001B, "URB_FUNCTION_CLASS_INTERFACE"},
    {0x001C, "URB_FUNCTION_CLASS_ENDPOINT"},
    {0x001D, "URB_FUNCTION_RESERVE_0X001D"},
    {0x001E, "URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL"},
    {0x001F, "URB_FUNCTION_CLASS_OTHER"},
    {0x0020, "URB_FUNCTION_VENDOR_OTHER"},
    {0x0021, "URB_FUNCTION_GET_STATUS_FROM_OTHER"},
    {0x0022, "URB_FUNCTION_CLEAR_FEATURE_TO_OTHER"},
    {0x0023, "URB_FUNCTION_SET_FEATURE_TO_OTHER"},
    {0x0024, "URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT"},
    {0x0025, "URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT"},
    {0x0026, "URB_FUNCTION_GET_CONFIGURATION"},
    {0x0027, "URB_FUNCTION_GET_INTERFACE"},
    {0x0028, "URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE"},
    {0x0029, "URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE"},
    {0x002A, "URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR"},
    {0x002B, "URB_FUNCTION_RESERVE_0X002B"},
    {0x002C, "URB_FUNCTION_RESERVE_0X002C"},
    {0x002D, "URB_FUNCTION_RESERVE_0X002D"},
    {0x002E, "URB_FUNCTION_RESERVE_0X002E"},
    {0x002F, "URB_FUNCTION_RESERVE_0X002F"},
    {0x0030, "URB_FUNCTION_SYNC_RESET_PIPE"},
    {0x0031, "URB_FUNCTION_SYNC_CLEAR_STALL"},
    {0x0032, "URB_FUNCTION_CONTROL_TRANSFER_EX"},
    {0x0033, "URB_FUNCTION_RESERVE_0X0033"},
    {0x0034, "URB_FUNCTION_RESERVE_0X0034"},
    {0, NULL}
};
static value_string_ext win32_urb_function_vals_ext = VALUE_STRING_EXT_INIT(win32_urb_function_vals);

static const value_string win32_usbd_status_vals[] = {
    {0x00000000, "USBD_STATUS_SUCCESS"},
    {0x40000000, "USBD_STATUS_PENDING"},

    {0x80000200, "USBD_STATUS_INVALID_URB_FUNCTION"},
    {0x80000300, "USBD_STATUS_INVALID_PARAMETER"},
    {0x80000400, "USBD_STATUS_ERROR_BUSY"},
    {0x80000600, "USBD_STATUS_INVALID_PIPE_HANDLE"},
    {0x80000700, "USBD_STATUS_NO_BANDWIDTH"},
    {0x80000800, "USBD_STATUS_INTERNAL_HC_ERROR"},
    {0x80000900, "USBD_STATUS_ERROR_SHORT_TRANSFER"},

    {0xC0000001, "USBD_STATUS_CRC"},
    {0xC0000002, "USBD_STATUS_BTSTUFF"},
    {0xC0000003, "USBD_STATUS_DATA_TOGGLE_MISMATCH"},
    {0xC0000004, "USBD_STATUS_STALL_PID"},
    {0xC0000005, "USBD_STATUS_DEV_NOT_RESPONDING"},
    {0xC0000006, "USBD_STATUS_PID_CHECK_FAILURE"},
    {0xC0000007, "USBD_STATUS_UNEXPECTED_PID"},
    {0xC0000008, "USBD_STATUS_DATA_OVERRUN"},
    {0xC0000009, "USBD_STATUS_DATA_UNDERRUN"},
    {0xC000000A, "USBD_STATUS_RESERVED1"},
    {0xC000000B, "USBD_STATUS_RESERVED2"},
    {0xC000000C, "USBD_STATUS_BUFFER_OVERRUN"},
    {0xC000000D, "USBD_STATUS_BUFFER_UNDERRUN"},
    {0xC000000F, "USBD_STATUS_NOT_ACCESSED"},
    {0xC0000010, "USBD_STATUS_FIFO"},
    {0xC0000011, "USBD_STATUS_XACT_ERROR"},
    {0xC0000012, "USBD_STATUS_BABBLE_DETECTED"},
    {0xC0000013, "USBD_STATUS_DATA_BUFFER_ERROR"},
    {0xC0000030, "USBD_STATUS_ENDPOINT_HALTED"},

    {0xC0000A00, "USBD_STATUS_BAD_START_FRAME"},
    {0xC0000B00, "USBD_STATUS_ISOCH_REQUEST_FAILED"},
    {0xC0000C00, "USBD_STATUS_FRAME_CONTROL_OWNED"},
    {0xC0000D00, "USBD_STATUS_FRAME_CONTROL_NOT_OWNED"},
    {0xC0000E00, "USBD_STATUS_NOT_SUPPORTED"},
    {0xC0000F00, "USBD_STATUS_INVALID_CONFIGURATION_DESCRIPTOR"},
    {0xC0001000, "USBD_STATUS_INSUFFICIENT_RESOURCES"},
    {0xC0002000, "USBD_STATUS_SET_CONFIG_FAILED"},
    {0xC0003000, "USBD_STATUS_BUFFER_TOO_SMALL"},
    {0xC0004000, "USBD_STATUS_INTERFACE_NOT_FOUND"},
    {0xC0005000, "USBD_STATUS_INVALID_PIPE_FLAGS"},
    {0xC0006000, "USBD_STATUS_TIMEOUT"},
    {0xC0007000, "USBD_STATUS_DEVICE_GONE"},
    {0xC0008000, "USBD_STATUS_STATUS_NOT_MAPPED"},
    {0xC0009000, "USBD_STATUS_HUB_INTERNAL_ERROR"},
    {0xC0010000, "USBD_STATUS_CANCELED"},
    {0xC0020000, "USBD_STATUS_ISO_NOT_ACCESSED_BY_HW"},
    {0xC0030000, "USBD_STATUS_ISO_TD_ERROR"},
    {0xC0040000, "USBD_STATUS_ISO_NA_LATE_USBPORT"},
    {0xC0050000, "USBD_STATUS_ISO_NOT_ACCESSED_LATE"},
    {0xC0100000, "USBD_STATUS_BAD_DESCRIPTOR"},
    {0xC0100001, "USBD_STATUS_BAD_DESCRIPTOR_BLEN"},
    {0xC0100002, "USBD_STATUS_BAD_DESCRIPTOR_TYPE"},
    {0xC0100003, "USBD_STATUS_BAD_INTERFACE_DESCRIPTOR"},
    {0xC0100004, "USBD_STATUS_BAD_ENDPOINT_DESCRIPTOR"},
    {0xC0100005, "USBD_STATUS_BAD_INTERFACE_ASSOC_DESCRIPTOR"},
    {0xC0100006, "USBD_STATUS_BAD_CONFIG_DESC_LENGTH"},
    {0xC0100007, "USBD_STATUS_BAD_NUMBER_OF_INTERFACES"},
    {0xC0100008, "USBD_STATUS_BAD_NUMBER_OF_ENDPOINTS"},
    {0xC0100009, "USBD_STATUS_BAD_ENDPOINT_ADDRESS"},
    {0, NULL}
};
static value_string_ext win32_usbd_status_vals_ext = VALUE_STRING_EXT_INIT(win32_usbd_status_vals);

static const value_string win32_usb_info_direction_vals[] = {
    {0, "FDO -> PDO"},
    {1, "PDO -> FDO"},
    {0, NULL}
};

static const value_string usb_cdc_protocol_vals[] = {
    {0x00, "No class specific protocol required"},
    {0x01, "AT Commands: V.250 etc"},
    {0x02, "AT Commands defined by PCCA-101"},
    {0x03, "AT Commands defined by PCCA-101 & Annex O"},
    {0x04, "AT Commands defined by GSM 07.07"},
    {0x05, "AT Commands defined by 3GPP 27.007"},
    {0x06, "AT Commands defined by TIA for CDMA"},
    {0x07, "Ethernet Emulation Model"},
    {0xFE, "External Protocol: Commands defined by Command Set Functional Descriptor"},
    {0xFF, "Vendor-specific"},
    {0, NULL}
};
static value_string_ext usb_cdc_protocol_vals_ext = VALUE_STRING_EXT_INIT(usb_cdc_protocol_vals);

extern value_string_ext usb_massstorage_protocol_vals_ext;

static const value_string usb_cdc_data_protocol_vals[] = {
    {0x00, "No class specific protocol required"},
    {0x01, "Network Transfer Block"},
    {0x02, "Network Transfer Block (IP + DSS)"},
    {0x30, "Physical interface protocol for ISDN BRI"},
    {0x31, "HDLC"},
    {0x32, "Transparent"},
    {0x50, "Management protocol for Q.921 data link protocol"},
    {0x51, "Data link protocol for Q.931"},
    {0x52, "TEI-multiplexor for Q.921 data link protocol"},
    {0x90, "Data compression procedures"},
    {0x91, "Euro-ISDN protocol control"},
    {0x92, "V.24 rate adaptation to ISDN"},
    {0x93, "CAPI Commands"},
    {0xFE, "The protocol(s) are described using a Protocol Unit Functional Descriptors on Communications Class Interface"},
    {0xFF, "Vendor-specific"},
    {0, NULL}
};
static value_string_ext usb_cdc_data_protocol_vals_ext = VALUE_STRING_EXT_INIT(usb_cdc_data_protocol_vals);

static const value_string usb_hid_subclass_vals[] = {
    {0, "No Subclass"},
    {1, "Boot Interface"},
    {0, NULL}
};
static value_string_ext usb_hid_subclass_vals_ext = VALUE_STRING_EXT_INIT(usb_hid_subclass_vals);

static const value_string usb_hid_boot_protocol_vals[] = {
    {0, "None"},
    {1, "Keyboard"},
    {2, "Mouse"},
    {0, NULL}
};
static value_string_ext usb_hid_boot_protocol_vals_ext = VALUE_STRING_EXT_INIT(usb_hid_boot_protocol_vals);

static const value_string usb_misc_subclass_vals[] = {
    {0x03, "Cable Based Association Framework"},
    {0x04, "RNDIS"},
    {IF_SUBCLASS_MISC_U3V, "USB3 Vision"},
    {0x06, "Stream Transport Efficient Protocol"},
    {0, NULL}
};
static value_string_ext usb_misc_subclass_vals_ext = VALUE_STRING_EXT_INIT(usb_misc_subclass_vals);


static const value_string usb_app_subclass_vals[] = {
    {0x01, "Device Firmware Upgrade"},
    {0x02, "IRDA Bridge"},
    {0x03, "USB Test and Measurement Device"},
    {0, NULL}
};
static value_string_ext usb_app_subclass_vals_ext = VALUE_STRING_EXT_INIT(usb_app_subclass_vals);


static const value_string usb_app_dfu_protocol_vals[] = {
    {0x01, "Runtime protocol"},
    {0x02, "DFU mode protocol"},
    {0, NULL}
};
static value_string_ext usb_app_dfu_protocol_vals_ext = VALUE_STRING_EXT_INIT(usb_app_dfu_protocol_vals);

static const value_string usb_app_irda_protocol_vals[] = {
    {0x00, "IRDA Bridge device"},
    {0, NULL}
};
static value_string_ext usb_app_irda_protocol_vals_ext = VALUE_STRING_EXT_INIT(usb_app_irda_protocol_vals);

static const value_string usb_app_usb_test_and_measurement_protocol_vals[] = {
    {0x00, "USB Test and Measurement Device"},
    {0x01, "USB Test and Measurement Device conforming to the USBTMC USB488 Subclass Specification"},
    {0, NULL}
};
static value_string_ext usb_app_usb_test_and_measurement_protocol_vals_ext = VALUE_STRING_EXT_INIT(usb_app_usb_test_and_measurement_protocol_vals);

/* macOS */

/* Request Type */
#define DARWIN_IO_SUBMIT   0
#define DARWIN_IO_COMPLETE 1


static const value_string usb_darwin_request_type_vals[] = {
    {DARWIN_IO_SUBMIT,   "SUBMIT"},
    {DARWIN_IO_COMPLETE, "COMPLETE"},
    {0, NULL}
};

/* Transfer type */
static const value_string usb_darwin_endpoint_type_vals[] = {
    {USB_EP_CONTROL,     "Control"},
    {USB_EP_ISOCHRONOUS, "Isochronous"},
    {USB_EP_BULK,        "Bulk"},
    {USB_EP_INTERRUPT,   "Interrupt"},
    {0, NULL}
};

/* USB speeds */
#define DARWIN_SPEED_LOW         0
#define DARWIN_SPEED_FULL        1
#define DARWIN_SPEED_HIGH        2
#define DARWIN_SPEED_SUPER       3
#define DARWIN_SPEED_SUPERPLUS   4

static const value_string usb_darwin_speed_vals[] = {
    {DARWIN_SPEED_LOW,       "Low"},
    {DARWIN_SPEED_FULL,      "Full"},
    {DARWIN_SPEED_HIGH,      "High"},
    {DARWIN_SPEED_SUPER,     "Super"},
    {DARWIN_SPEED_SUPERPLUS, "Super+"},
    {0, NULL}
};

static const value_string darwin_usb_status_vals[] = {
    {0x00000000, "kIOReturnSuccess"},
    {0xe00002bc, "kIOReturnError"},
    {0xe00002bd, "kIOReturnNoMemory"},
    {0xe00002be, "kIOReturnNoResources"},
    {0xe00002bf, "kIOReturnIPCError"},
    {0xe00002c0, "kIOReturnNoDevice"},
    {0xe00002c1, "kIOReturnNotPrivileged"},
    {0xe00002c2, "kIOReturnBadArgument"},
    {0xe00002c3, "kIOReturnLockedRead"},
    {0xe00002c4, "kIOReturnLockedWrite"},
    {0xe00002c5, "kIOReturnExclusiveAccess"},
    {0xe00002c6, "kIOReturnBadMessageID"},
    {0xe00002c7, "kIOReturnUnsupported"},
    {0xe00002c8, "kIOReturnVMError"},
    {0xe00002c9, "kIOReturnInternalError"},
    {0xe00002ca, "kIOReturnIOError"},

    {0xe00002cc, "kIOReturnCannotLock"},
    {0xe00002cd, "kIOReturnNotOpen"},
    {0xe00002ce, "kIOReturnNotReadable"},
    {0xe00002cf, "kIOReturnNotWritable"},
    {0xe00002d0, "kIOReturnNotAligned"},
    {0xe00002d1, "kIOReturnBadMedia"},
    {0xe00002d2, "kIOReturnStillOpen"},
    {0xe00002d3, "kIOReturnRLDError"},
    {0xe00002d4, "kIOReturnDMAError"},
    {0xe00002d5, "kIOReturnBusy"},
    {0xe00002d6, "kIOReturnTimeout"},
    {0xe00002d7, "kIOReturnOffline"},
    {0xe00002d8, "kIOReturnNotReady"},
    {0xe00002d9, "kIOReturnNotAttached"},
    {0xe00002da, "kIOReturnNoChannels"},
    {0xe00002db, "kIOReturnNoSpace"},

    {0xe00002eb, "kIOReturnAborted"},
    {0, NULL}
};

static const guint32 darwin_endpoint_to_linux[] =
{
    URB_CONTROL,
    URB_ISOCHRONOUS,
    URB_BULK,
    URB_INTERRUPT,
    URB_UNKNOWN
};

static value_string_ext usb_darwin_status_vals_ext = VALUE_STRING_EXT_INIT(darwin_usb_status_vals);


static const value_string netmon_event_id_vals[] = {
    {1, "USBPORT_ETW_EVENT_HC_ADD USBPORT_ETW_EVENT_HC_ADD"},
    {2, "USBPORT_ETW_EVENT_HC_REMOVAL USBPORT_ETW_EVENT_HC_REMOVAL"},
    {3, "USBPORT_ETW_EVENT_HC_INFORMATION USBPORT_ETW_EVENT_HC_INFORMATION"},
    {4, "USBPORT_ETW_EVENT_HC_START USBPORT_ETW_EVENT_HC_START"},
    {5, "USBPORT_ETW_EVENT_HC_STOP USBPORT_ETW_EVENT_HC_STOP"},
    {6, "USBPORT_ETW_EVENT_HC_SUSPEND USBPORT_ETW_EVENT_HC_SUSPEND"},
    {7, "USBPORT_ETW_EVENT_HC_RESUME USBPORT_ETW_EVENT_HC_RESUME"},
    {8, "USBPORT_ETW_EVENT_HC_ASYNC_SCHEDULE_ENABLE"},
    {9, "USBPORT_ETW_EVENT_HC_ASYNC_SCHEDULE_DISABLE"},
    {10, "USBPORT_ETW_EVENT_HC_PERIODIC_SCHEDULE_ENABLE"},
    {11, "USBPORT_ETW_EVENT_HC_PERIODIC_SCHEDULE_DISABLE"},
    {12, "USBPORT_ETW_EVENT_DEVICE_CREATE"},
    {13, "USBPORT_ETW_EVENT_DEVICE_INITIALIZE"},
    {14, "USBPORT_ETW_EVENT_DEVICE_REMOVAL"},
    {15, "USBPORT_ETW_EVENT_DEVICE_INFORMATION"},
    {16, "USBPORT_ETW_EVENT_DEVICE_IDLE_STATE_SET"},
    {17, "USBPORT_ETW_EVENT_DEVICE_IDLE_STATE_CLEAR"},
    {18, "USBPORT_ETW_EVENT_ENDPOINT_OPEN"},
    {19, "USBPORT_ETW_EVENT_ENDPOINT_CLOSE USBPORT_ETW_EVENT_ENDPOINT_CLOSE"},
    {20, "USBPORT_ETW_EVENT_ENDPOINT_INFORMATION"},
    {21, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SELECT_CONFIGURATION"},
    {22, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SELECT_INTERFACE"},
    {23, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_CURRENT_FRAME_NUMBER"},
    {24, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CONTROL_TRANSFER"},
    {25, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CONTROL_TRANSFER_EX"},
    {26, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER"},
    {27, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_ISOCH_TRANSFER"},
    {28, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE"},
    {29, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE"},
    {30, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT"},
    {31, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT"},
    {32, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE"},
    {33, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE"},
    {34, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SET_FEATURE_TO_DEVICE"},
    {35, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SET_FEATURE_TO_INTERFACE"},
    {36, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SET_FEATURE_TO_ENDPOINT"},
    {37, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE"},
    {38, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE"},
    {39, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT"},
    {40, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CLEAR_FEATURE_TO_OTHER"},
    {41, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SET_FEATURE_TO_OTHER"},
    {42, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_STATUS_FROM_DEVICE"},
    {43, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_STATUS_FROM_INTERFACE"},
    {44, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_STATUS_FROM_ENDPOINT"},
    {45, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_STATUS_FROM_OTHER"},
    {46, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_VENDOR_DEVICE"},
    {47, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_VENDOR_INTERFACE"},
    {48, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_VENDOR_ENDPOINT"},
    {49, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CLASS_DEVICE"},
    {50, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CLASS_INTERFACE"},
    {51, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CLASS_ENDPOINT"},
    {52, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_CLASS_OTHER"},
    {53, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_VENDOR_OTHER"},
    {54, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_ABORT_PIPE"},
    {55, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL"},
    {56, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SYNC_RESET_PIPE"},
    {57, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SYNC_CLEAR_STALL"},
    {58, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_CONFIGURATION"},
    {59, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_INTERFACE"},
    {60, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR"},
    {61, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_TAKE_FRAME_LENGTH_CONTROL"},
    {62, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_RELEASE_FRAME_LENGTH_CONTROL"},
    {63, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_GET_FRAME_LENGTH"},
    {64, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_SET_FRAME_LENGTH"},
    {65, "USBPORT_ETW_EVENT_DISPATCH_URB_FUNCTION_RESERVED"},
    {66, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_CONTROL_TRANSFER"},
    {67, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_CONTROL_TRANSFER_EX"},
    {68, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_CONTROL_TRANSFER_DATA"},
    {69, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_CONTROL_TRANSFER_EX_DATA"},
    {70, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER"},
    {71, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER_DATA"},
    {72, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_ISOCH_TRANSFER"},
    {73, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_ISOCH_TRANSFER_DATA"},
    {74, "USBPORT_ETW_EVENT_INTERNAL_URB_FUNCTION_CONTROL_TRANSFER"},
    {75, "USBPORT_ETW_EVENT_COMPLETE_INTERNAL_URB_FUNCTION_CONTROL_TRANSFER"},
    {76, "USBPORT_ETW_EVENT_COMPLETE_INTERNAL_URB_FUNCTION_CONTROL_TRANSFER_DATA"},
    {77, "USBPORT_ETW_EVENT_COMPLETE_URB_FUNCTION_ABORT_PIPE"},
    {78, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_HEADER_LENGTH_WARNING"},
    {79, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_FUNCTION"},
    {80, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_HEADER_LENGTH"},
    {81, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_DEVICE_HANDLE"},
    {82, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_FUNCTION_NOT_SUPPORTED"},
    {83, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_FUNCTION_RESERVED"},
    {84, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_DUE_TO_HC_SUSPEND"},
    {85, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_URB_LINK"},
    {86, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_PIPE_HANDLE"},
    {87, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_ZERO_BW_PIPE_HANDLE"},
    {88, "USBPORT_ETW_EVENT_DISPATCH_URB_NOP_ZERO_BW_PIPE_HANDLE_REQUEST"},
    {89, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_CONTROL_TRANSFER_ENDPOINT"},
    {90, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_CONTROL_TRANSFER_BUFFER_LENGTH"},
    {91, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_BULK_OR_INTERRUPT_TRANSFER_ENDPOINT"},
    {92, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_BULK_OR_INTERRUPT_TRANSFER_BUFFER_LENGTH"},
    {93, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_ISOCHRONOUS_TRANSFER_ENDPOINT"},
    {94, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_NULL_TRANSFER_BUFFER_AND_MDL"},
    {95, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_NON_NULL_TRANSFER_BUFFER_MDL"},
    {96, "USBPORT_ETW_EVENT_DISPATCH_URB_ALLOCATE_MDL_FAILURE"},
    {97, "USBPORT_ETW_EVENT_DISPATCH_URB_ALLOCATE_TRANSFER_CONTEXT_FAILURE"},
    {98, "USBPORT_ETW_EVENT_DISPATCH_URB_NOP_ROOTHUB_PIPE_HANDLE_REQUEST"},
    {99, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_ISOCHRONOUS_ZERO_LENGTH"},
    {100, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_ISOCHRONOUS_NUM_PACKETS"},
    {101, "USBPORT_ETW_EVENT_DISPATCH_URB_INVALID_ISOCHRONOUS_START_FRAME"},
    {102, "USBPORT_ETW_EVENT_IRP_CANCEL"},
    {103, "USBPORT_ETW_EVENT_USBUSER_OP_RAW_RESET_PORT_DISPATCH"},
    {104, "USBPORT_ETW_EVENT_USBUSER_OP_RAW_RESET_PORT_STATUS1"},
    {105, "USBPORT_ETW_EVENT_USBUSER_OP_RAW_RESET_PORT_STATUS2"},
    {106, "USBPORT_ETW_EVENT_USBUSER_OP_RAW_RESET_PORT_STATUS3"},
    {107, "USBPORT_ETW_EVENT_USBUSER_OP_RAW_RESET_PORT_COMPLETE"},
    {108, "USBPORT_ETW_EVENT_USBUSER_OP_SEND_ONE_PACKET_DISPATCH"},
    {109, "USBPORT_ETW_EVENT_USBUSER_OP_SEND_ONE_PACKET_DISPATCH_DATA"},
    {110, "USBPORT_ETW_EVENT_USBUSER_OP_SEND_ONE_PACKET_TIMEOUT"},
    {111, "USBPORT_ETW_EVENT_USBUSER_OP_SEND_ONE_PACKET_COMPLETE"},
    {112, "USBPORT_ETW_EVENT_USBUSER_OP_SEND_ONE_PACKET_COMPLETE_DATA"},
    {113, "USBPORT_ETW_EVENT_CODE_EXECUTION_TIME"},
    {114, "USBPORT_ETW_EVENT_PUT_SGLIST_EXECUTION_TIME"},
    {115, "USBPORT_ETW_EVENT_BUILD_SGLIST_EXECUTION_TIME"},
    {1024, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_START_DISPATCH"},
    {1025, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_START_COMPLETE"},
    {1026, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_START_COMPLETE_ERROR_1"},
    {1027, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_START_COMPLETE_ERROR_2"},
    {1028, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_START_COMPLETE_ERROR_3"},
    {1029, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_START_COMPLETE_ERROR_4"},
    {1030, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_START_COMPLETE_ERROR_5"},
    {1031, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_STOP_DISPATCH"},
    {1032, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_STOP_COMPLETE"},
    {1033, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_SUSPEND_DISPATCH"},
    {1034, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_SUSPEND_COMPLETE"},
    {1035, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_RESUME_DISPATCH"},
    {1036, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_RESUME_COMPLETE"},
    {1037, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_RESUME_COMPLETE_ERROR_1"},
    {1038, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_RESUME_COMPLETE_ERROR_2"},
    {1039, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_RESUME_COMPLETE_ERROR_3"},
    {1040, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_RESUME_COMPLETE_ERROR_4"},
    {1041, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_RESUME_COMPLETE_ERROR_5"},
    {1042, "USBPORT_ETW_EVENT_HC_EHCI_MINIPORT_RESUME_COMPLETE_ERROR_6"},
    {2048, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_START_DISPATCH"},
    {2049, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_START_COMPLETE"},
    {2050, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_START_COMPLETE_ERROR_1"},
    {2051, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_START_COMPLETE_ERROR_2"},
    {2052, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_START_COMPLETE_ERROR_3"},
    {2053, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_START_COMPLETE_ERROR_4"},
    {2054, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_START_COMPLETE_ERROR_5"},
    {2055, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_STOP_DISPATCH"},
    {2056, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_STOP_COMPLETE"},
    {2057, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_SUSPEND_DISPATCH"},
    {2058, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_SUSPEND_COMPLETE"},
    {2059, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_RESUME_DISPATCH"},
    {2060, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_RESUME_COMPLETE"},
    {2061, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_RESUME_COMPLETE_ERROR_1"},
    {2062, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_RESUME_COMPLETE_ERROR_2"},
    {2063, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_RESUME_COMPLETE_ERROR_3"},
    {2064, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_RESUME_COMPLETE_ERROR_4"},
    {2065, "USBPORT_ETW_EVENT_HC_OHCI_MINIPORT_RESUME_COMPLETE_ERROR_5"},
    {3072, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_START_DISPATCH"},
    {3073, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_START_COMPLETE"},
    {3074, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_START_COMPLETE_ERROR_1"},
    {3075, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_START_COMPLETE_ERROR_2"},
    {3076, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_START_COMPLETE_ERROR_3"},
    {3077, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_START_COMPLETE_ERROR_4"},
    {3078, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_STOP_DISPATCH"},
    {3079, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_STOP_COMPLETE"},
    {3080, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_SUSPEND_DISPATCH"},
    {3081, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_SUSPEND_COMPLETE"},
    {3082, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_RESUME_DISPATCH"},
    {3083, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_RESUME_COMPLETE"},
    {3084, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_RESUME_COMPLETE_ERROR_1"},
    {3085, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_RESUME_COMPLETE_ERROR_2"},
    {3086, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_RESUME_COMPLETE_ERROR_3"},
    {3087, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_RESUME_COMPLETE_ERROR_4"},
    {3088, "USBPORT_ETW_EVENT_HC_UHCI_MINIPORT_RESUME_COMPLETE_ERROR_5"},
    {3089, "USBPORT_ETW_EVENT_RTPM_TRANSITION"},
    {3090, "USBPORT_ETW_EVENT_DISPATCH_WAIT_WAKE"},
    {3091, "USBPORT_ETW_EVENT_COMPLETE_WAIT_WAKE"},
    {0, NULL}
};
static value_string_ext netmon_event_id_vals_ext = VALUE_STRING_EXT_INIT(netmon_event_id_vals);

static const value_string netmon_urb_function_vals[] = {
    {0x0000, "SELECT_CONFIGURATION"},
    {0x0001, "SELECT_INTERFACE"},
    {0x0002, "ABORT_PIPE"},
    {0x0003, "TAKE_FRAME_LENGTH_CONTROL"},
    {0x0004, "RELEASE_FRAME_LENGTH_CONTROL"},
    {0x0005, "GET_FRAME_LENGTH"},
    {0x0006, "SET_FRAME_LENGTH"},
    {0x0007, "GET_CURRENT_FRAME_NUMBER"},
    {0x0008, "CONTROL_TRANSFER"},
    {0x0009, "BULK_OR_INTERRUPT_TRANSFER"},
    {0x000A, "ISOCH_TRANSFER"},
    {0x000B, "GET_DESCRIPTOR_FROM_DEVICE"},
    {0x000C, "SET_DESCRIPTOR_TO_DEVICE"},
    {0x000D, "SET_FEATURE_TO_DEVICE"},
    {0x000E, "SET_FEATURE_TO_INTERFACE"},
    {0x000F, "SET_FEATURE_TO_ENDPOINT"},
    {0x0010, "CLEAR_FEATURE_TO_DEVICE"},
    {0x0011, "CLEAR_FEATURE_TO_INTERFACE"},
    {0x0012, "CLEAR_FEATURE_TO_ENDPOINT"},
    {0x0013, "GET_STATUS_FROM_DEVICE"},
    {0x0014, "GET_STATUS_FROM_INTERFACE"},
    {0x0015, "GET_STATUS_FROM_ENDPOINT"},
    {0x0016, "RESERVED"},
    {0x0017, "VENDOR_DEVICE"},
    {0x0018, "VENDOR_INTERFACE"},
    {0x0019, "VENDOR_ENDPOINT"},
    {0x001A, "CLASS_DEVICE"},
    {0x001B, "CLASS_INTERFACE"},
    {0x001C, "CLASS_ENDPOINT"},
    {0x001D, "RESERVE_0X001D"},
    {0x001E, "SYNC_RESET_PIPE_AND_CLEAR_STALL"},
    {0x001F, "CLASS_OTHER"},
    {0x0020, "VENDOR_OTHER"},
    {0x0021, "GET_STATUS_FROM_OTHER"},
    {0x0022, "CLEAR_FEATURE_TO_OTHER"},
    {0x0023, "SET_FEATURE_TO_OTHER"},
    {0x0024, "GET_DESCRIPTOR_FROM_ENDPOINT"},
    {0x0025, "SET_DESCRIPTOR_TO_ENDPOINT"},
    {0x0026, "GET_CONFIGURATION"},
    {0x0027, "GET_INTERFACE"},
    {0x0028, "GET_DESCRIPTOR_FROM_INTERFACE"},
    {0x0029, "SET_DESCRIPTOR_TO_INTERFACE"},
    {0x002A, "GET_MS_FEATURE_DESCRIPTOR"},
    {0x0030, "SYNC_RESET_PIPE"},
    {0x0031, "SYNC_CLEAR_STALL"},
    {0x0032, "CONTROL_TRANSFER_EX"},
    {0x0035, "OPEN_STATIC_STREAMS"},
    {0x0036, "CLOSE_STATIC_STREAMS"},
    {0x0037, "BULK_OR_INTERRUPT_TRANSFER_USING_CHAINED_MDL"},
    {0x0038, "ISOCH_TRANSFER_USING_CHAINED_MDL"},
    {0, NULL}
};
static value_string_ext netmon_urb_function_vals_ext = VALUE_STRING_EXT_INIT(netmon_urb_function_vals);


void proto_register_usb(void);
void proto_reg_handoff_usb(void);

/* USB address handling */
static int usb_addr_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    const guint8 *addrp = (const guint8 *)addr->data;

    if(pletoh32(&addrp[0])==0xffffffff){
        (void) g_strlcpy(buf, "host", buf_len);
    } else {
        snprintf(buf, buf_len, "%d.%d.%d", pletoh16(&addrp[8]),
                        pletoh32(&addrp[0]), pletoh32(&addrp[4]));
    }

    return (int)(strlen(buf)+1);
}

static int usb_addr_str_len(const address* addr _U_)
{
    return 50;
}


/* This keys provide information for DecodeBy and other dissector via
   per packet data: p_get_proto_data()/p_add_proto_data() */
#define USB_BUS_ID           0
#define USB_DEVICE_ADDRESS   1
#define USB_VENDOR_ID        2
#define USB_PRODUCT_ID       3
#define USB_DEVICE_CLASS     4
#define USB_DEVICE_SUBCLASS  5
#define USB_DEVICE_PROTOCOL  6

static void
usb_device_prompt(packet_info *pinfo, gchar* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Bus ID %u \nDevice Address %u\nas ",
            GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_BUS_ID)),
            GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_ADDRESS)));
}

static gpointer
usb_device_value(packet_info *pinfo)
{
    guint32 value = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_BUS_ID)) << 16;
    value |= GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_ADDRESS));
    return GUINT_TO_POINTER(value);
}

static void
usb_product_prompt(packet_info *pinfo, gchar* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Vendor ID 0x%04x \nProduct ID 0x%04x\nas ",
            GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_VENDOR_ID)),
            GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_PRODUCT_ID)));
}

static gpointer
usb_product_value(packet_info *pinfo)
{
    guint32 value = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_VENDOR_ID)) << 16;
    value |= GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_PRODUCT_ID));
    return GUINT_TO_POINTER(value);
}

static void
usb_protocol_prompt(packet_info *pinfo, gchar* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Class ID 0x%04x \nSubclass ID 0x%04x\nProtocol 0x%04x\nas ",
            GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_CLASS)),
            GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_SUBCLASS)),
            GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_PROTOCOL)));
}

static gpointer
usb_protocol_value(packet_info *pinfo)
{
    guint32 value = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_CLASS)) << 16;
    value |= GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_SUBCLASS)) << 8;
    value |= GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_PROTOCOL));
    return GUINT_TO_POINTER(value);
}

static build_valid_func   usb_product_da_build_value[1] = {usb_product_value};
static decode_as_value_t  usb_product_da_values         = {usb_product_prompt, 1, usb_product_da_build_value};
static decode_as_t        usb_product_da = {
        "usb", "usb.product",
        1, 0, &usb_product_da_values, NULL, NULL,
        decode_as_default_populate_list, decode_as_default_reset,
        decode_as_default_change, NULL};

static build_valid_func   usb_device_da_build_value[1] = {usb_device_value};
static decode_as_value_t  usb_device_da_values         = {usb_device_prompt, 1, usb_device_da_build_value};
static decode_as_t        usb_device_da = {
        "usb", "usb.device",
        1, 0, &usb_device_da_values, NULL, NULL,
        decode_as_default_populate_list, decode_as_default_reset,
        decode_as_default_change, NULL};

static build_valid_func   usb_protocol_da_build_value[1] = {usb_protocol_value};
static decode_as_value_t  usb_protocol_da_values         = {usb_protocol_prompt, 1, usb_protocol_da_build_value};
static decode_as_t        usb_protocol_da = {
        "usb", "usb.protocol",
        1, 0, &usb_protocol_da_values, NULL, NULL,
        decode_as_default_populate_list, decode_as_default_reset,
        decode_as_default_change, NULL};


static usb_conv_info_t *
get_usb_conv_info(conversation_t *conversation)
{
    usb_conv_info_t *usb_conv_info;

    /* do we have conversation specific data ? */
    usb_conv_info = (usb_conv_info_t *)conversation_get_proto_data(conversation, proto_usb);
    if (!usb_conv_info) {
        /* no not yet so create some */
        usb_conv_info = wmem_new0(wmem_file_scope(), usb_conv_info_t);
        usb_conv_info->interfaceClass    = IF_CLASS_UNKNOWN;
        usb_conv_info->interfaceSubclass = IF_SUBCLASS_UNKNOWN;
        usb_conv_info->interfaceProtocol = IF_PROTOCOL_UNKNOWN;
        usb_conv_info->deviceVendor      = DEV_VENDOR_UNKNOWN;
        usb_conv_info->deviceProduct     = DEV_PRODUCT_UNKNOWN;
        usb_conv_info->deviceVersion     = DEV_VERSION_UNKNOWN;
        usb_conv_info->alt_settings      = wmem_array_new(wmem_file_scope(), sizeof(usb_alt_setting_t));
        usb_conv_info->transactions      = wmem_tree_new(wmem_file_scope());
        usb_conv_info->descriptor_transfer_type = URB_UNKNOWN;
        usb_conv_info->max_packet_size   = 0;

        conversation_add_proto_data(conversation, proto_usb, usb_conv_info);
    }

    return usb_conv_info;
}


/* usb_conv_info_t contains some components that are valid only for one specific packet
   clear_usb_conv_tmp_data() clears these components, it should be called
   before we dissect a new packet */
static void clear_usb_conv_tmp_data(usb_conv_info_t *usb_conv_info)
{
    /* caller must have checked that usb_conv_info!= NULL */

    usb_conv_info->direction = P2P_DIR_UNKNOWN;
    usb_conv_info->transfer_type = URB_UNKNOWN;
    usb_conv_info->is_request = FALSE;
    usb_conv_info->is_setup = FALSE;
    usb_conv_info->setup_requesttype = 0;
    usb_conv_info->speed = USB_SPEED_UNKNOWN;

    /* when we parse the configuration, interface and endpoint
       descriptors, we store the current interface class in endpoint 0's
       conversation

       this must be cleared since endpoint 0 does not belong to any
       interface class

       we used to clear these info in dissect_usb_configuration_descriptor()
       this doesn't work when the descriptor parsing throws an exception */

    if (usb_conv_info->endpoint==0) {
        usb_conv_info->interfaceClass    = IF_CLASS_UNKNOWN;
        usb_conv_info->interfaceSubclass = IF_SUBCLASS_UNKNOWN;
        usb_conv_info->interfaceProtocol = IF_PROTOCOL_UNKNOWN;
    }
}

static conversation_t *
get_usb_conversation(packet_info *pinfo,
                     address *src_addr, address *dst_addr,
                     guint32 src_endpoint, guint32 dst_endpoint)
{
    conversation_t *conversation;

    /*
     * Do we have a conversation for this connection?
     */
    conversation = find_conversation(pinfo->num,
                               src_addr, dst_addr,
                               conversation_pt_to_conversation_type(pinfo->ptype),
                               src_endpoint, dst_endpoint, 0);
    if (conversation) {
        return conversation;
    }

    /* We don't yet have a conversation, so create one. */
    conversation = conversation_new(pinfo->num,
                           src_addr, dst_addr,
                           conversation_pt_to_conversation_type(pinfo->ptype),
                           src_endpoint, dst_endpoint, 0);
    return conversation;
}

/* Fetch or create usb_conv_info for a specified interface. */
usb_conv_info_t *
get_usb_iface_conv_info(packet_info *pinfo, guint8 interface_num)
{
    conversation_t *conversation;
    guint32 if_port;

    if_port = GUINT32_TO_LE(INTERFACE_PORT | interface_num);

    if (pinfo->srcport == NO_ENDPOINT) {
        conversation = get_usb_conversation(pinfo, &pinfo->src, &pinfo->dst, pinfo->srcport, if_port);
    } else {
        conversation = get_usb_conversation(pinfo, &pinfo->src, &pinfo->dst, if_port, pinfo->destport);
    }

    return get_usb_conv_info(conversation);
}

/* Fetch usb_conv_info for specified endpoint, return NULL if not found */
usb_conv_info_t *
get_existing_usb_ep_conv_info(packet_info* pinfo, guint16 bus_id, guint16 device_address, int endpoint)
{
    usb_address_t   *src_addr = wmem_new0(pinfo->pool, usb_address_t),
                    *dst_addr = wmem_new0(pinfo->pool, usb_address_t);
    address          src, dst;
    conversation_t  *conversation;
    usb_conv_info_t *usb_conv_info = NULL;

    src_addr->bus_id   = GUINT16_TO_LE(bus_id);
    src_addr->device   = GUINT16_TO_LE(device_address);
    src_addr->endpoint = GUINT32_TO_LE(endpoint);

    dst_addr->bus_id   = GUINT16_TO_LE(bus_id);
    dst_addr->device   = 0xffffffff;
    dst_addr->endpoint = NO_ENDPOINT;

    set_address(&src, usb_address_type, USB_ADDR_LEN, (char *)src_addr);
    set_address(&dst, usb_address_type, USB_ADDR_LEN, (char *)dst_addr);

    conversation = find_conversation(pinfo->num, &src, &dst,
                                     conversation_pt_to_conversation_type(PT_USB),
                                     src_addr->endpoint, dst_addr->endpoint, 0);
    if (conversation) {
        usb_conv_info = (usb_conv_info_t *)conversation_get_proto_data(conversation, proto_usb);
    }
    return usb_conv_info;
}

static const char* usb_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == usb_address_type))
        return "usb.src";

    if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == usb_address_type))
        return "usb.dst";

    if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == usb_address_type))
        return "usb.addr";

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t usb_ct_dissector_info = {&usb_conv_get_filter_type};

static tap_packet_status
usb_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

    add_conversation_table_data(hash, &pinfo->src, &pinfo->dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &usb_ct_dissector_info, CONVERSATION_NONE);

    return TAP_PACKET_REDRAW;
}

static const char* usb_endpoint_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_ANY_ADDRESS) && (endpoint->myaddress.type == usb_address_type))
        return "usb.addr";

    return CONV_FILTER_INVALID;
}

static const char*
usb_col_filter_str(const address* addr _U_, gboolean is_src)
{
    return is_src ? "usb.src" : "usb.dst";
}

static et_dissector_info_t usb_endpoint_dissector_info = {&usb_endpoint_get_filter_type};

static tap_packet_status
usb_endpoint_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip _U_, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

    /* Take two "add" passes per packet, adding for each direction, ensures that all
       packets are counted properly (even if address is sending to itself)
       XXX - this could probably be done more efficiently inside endpoint_table */
    add_endpoint_table_data(hash, &pinfo->src, 0, TRUE, 1, pinfo->fd->pkt_len, &usb_endpoint_dissector_info, ENDPOINT_NONE);
    add_endpoint_table_data(hash, &pinfo->dst, 0, FALSE, 1, pinfo->fd->pkt_len, &usb_endpoint_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

/* SETUP dissectors */


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / CLEAR FEATURE
 */


/* 9.4.1 */
static int
dissect_usb_setup_clear_feature_request(packet_info *pinfo _U_, proto_tree *tree,
                                        tvbuff_t *tvb, int offset,
                                        usb_conv_info_t  *usb_conv_info)
{
    guint8 recip;

    if (usb_conv_info) {
        recip = USB_RECIPIENT(usb_conv_info->usb_trans_info->setup.requesttype);

        /* feature selector, zero/interface/endpoint */
        switch (recip) {
        case RQT_SETUP_RECIPIENT_DEVICE:
            proto_tree_add_item(tree, hf_usb_device_wFeatureSelector, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

        case RQT_SETUP_RECIPIENT_INTERFACE:
            proto_tree_add_item(tree, hf_usb_interface_wFeatureSelector, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

        case RQT_SETUP_RECIPIENT_ENDPOINT:
            proto_tree_add_item(tree, hf_usb_endpoint_wFeatureSelector, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_wEndpoint, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

        case RQT_SETUP_RECIPIENT_OTHER:
        default:
            proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        }
    } else {
        /* No conversation information, so recipient type is unknown */
        proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    offset += 2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_clear_feature_response(packet_info *pinfo _U_, proto_tree *tree _U_,
                                         tvbuff_t *tvb _U_, int offset,
                                         usb_conv_info_t  *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / GET CONFIGURATION
 */


/* 9.4.2 */
static int
dissect_usb_setup_get_configuration_response(packet_info *pinfo _U_, proto_tree *tree _U_,
                                             tvbuff_t *tvb _U_, int offset,
                                             usb_conv_info_t  *usb_conv_info _U_)
{
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / GET DESCRIPTOR
 */

proto_item * dissect_usb_descriptor_header(proto_tree *tree,
                                           tvbuff_t *tvb, int offset,
                                           value_string_ext *type_val_str)
{
    guint8      desc_type;
    proto_item *length_item;


    length_item = proto_tree_add_item(tree, hf_usb_bLength,
          tvb, offset, 1,  ENC_LITTLE_ENDIAN);
    offset++;

    desc_type = tvb_get_guint8(tvb, offset);
    /* if the caller provided no class specific value string, we're
     * using the standard descriptor types */
    if (!type_val_str)
        type_val_str = &std_descriptor_type_vals_ext;

    proto_tree_add_uint_format_value(tree, hf_usb_bDescriptorType,
        tvb, offset, 1, desc_type, "0x%02x (%s)", desc_type,
        val_to_str_ext(desc_type, type_val_str, "unknown"));

    return length_item;
}

static void
dissect_max_packet_size0(packet_info *pinfo, proto_tree *tree,
                         tvbuff_t *tvb, int offset,
                         usb_conv_info_t *usb_conv_info, gboolean other_speed)
{
    proto_item  *item;
    guint32      max_packet_size;
    unsigned int sanitized_max_packet_size;
    usb_speed_t  speed = usb_conv_info->speed;

    item = proto_tree_add_item_ret_uint(tree, hf_usb_bMaxPacketSize0, tvb, offset, 1, ENC_LITTLE_ENDIAN, &max_packet_size);
    if (other_speed) {
        if (speed == USB_SPEED_FULL)
            speed = USB_SPEED_HIGH;
        else if (speed == USB_SPEED_HIGH)
            speed = USB_SPEED_FULL;
    }
    sanitized_max_packet_size = sanitize_usb_max_packet_size(ENDPOINT_TYPE_CONTROL, speed, max_packet_size);
    if (sanitized_max_packet_size != max_packet_size) {
        expert_add_info_format(pinfo, item, &ei_usb_invalid_max_packet_size0,
            "%s endpoint zero max packet size cannot be %u, using %d instead.",
            try_val_to_str(speed, usb_speed_vals), max_packet_size, sanitized_max_packet_size);
    }
}

/* 9.6.2 */
static int
dissect_usb_device_qualifier_descriptor(packet_info *pinfo, proto_tree *parent_tree,
                                        tvbuff_t *tvb, int offset,
                                        usb_conv_info_t  *usb_conv_info)
{
    proto_item *item;
    proto_tree *tree;
    proto_item *nitem;
    int         old_offset = offset;
    guint32     protocol;
    const gchar *description;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "DEVICE QUALIFIER DESCRIPTOR");

    dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += 2;

    /* bcdUSB */
    proto_tree_add_item(tree, hf_usb_bcdUSB, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    protocol = tvb_get_ntoh24(tvb, offset);
    description = val_to_str_ext_const(protocol, &usb_protocols_ext, "");

    /* bDeviceClass */
    proto_tree_add_item(tree, hf_usb_bDeviceClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bDeviceSubClass */
    proto_tree_add_item(tree, hf_usb_bDeviceSubClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bDeviceProtocol */
    nitem = proto_tree_add_item(tree, hf_usb_bDeviceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    if (*description)
        proto_item_append_text(nitem, " (%s)", description);
    offset += 1;

    if (!pinfo->fd->visited) {
        guint                   k_bus_id;
        guint                   k_device_address;
        guint                   k_frame_number;
        wmem_tree_key_t         key[4];
        device_protocol_data_t  *device_protocol_data;

        k_frame_number = pinfo->num;
        k_device_address = usb_conv_info->device_address;
        k_bus_id = usb_conv_info->bus_id;

        key[0].length = 1;
        key[0].key    = &k_device_address;
        key[1].length = 1;
        key[1].key    = &k_bus_id;
        key[2].length = 1;
        key[2].key    = &k_frame_number;
        key[3].length = 0;
        key[3].key    = NULL;

        device_protocol_data = wmem_new(wmem_file_scope(), device_protocol_data_t);
        device_protocol_data->protocol = protocol;
        device_protocol_data->bus_id = usb_conv_info->bus_id;
        device_protocol_data->device_address = usb_conv_info->device_address;
        wmem_tree_insert32_array(device_to_protocol_table, key, device_protocol_data);
    }

    /* bMaxPacketSize0 */
    dissect_max_packet_size0(pinfo, tree, tvb, offset, usb_conv_info, TRUE);
    offset += 1;

    /* bNumConfigurations */
    proto_tree_add_item(tree, hf_usb_bNumConfigurations, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* one reserved byte */
    offset += 1;

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

/* 9.6.1 */
static int
dissect_usb_device_descriptor(packet_info *pinfo, proto_tree *parent_tree,
                              tvbuff_t *tvb, int offset,
                              usb_conv_info_t *usb_conv_info)
{
    proto_item        *item;
    proto_tree        *tree;
    proto_item        *nitem;
    int                old_offset = offset;
    guint32            protocol;
    const gchar       *description;
    guint32            vendor_id;
    guint32            product;
    guint16            product_id;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "DEVICE DESCRIPTOR");

    dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += 2;

    /* bcdUSB */
    proto_tree_add_item(tree, hf_usb_bcdUSB, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    protocol = tvb_get_ntoh24(tvb, offset);
    description = val_to_str_ext_const(protocol, &usb_protocols_ext, "");

    /* bDeviceClass */
    proto_tree_add_item(tree, hf_usb_bDeviceClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bDeviceSubClass */
    proto_tree_add_item(tree, hf_usb_bDeviceSubClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bDeviceProtocol */
    nitem = proto_tree_add_item(tree, hf_usb_bDeviceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    if (*description)
        proto_item_append_text(nitem, " (%s)", description);
    offset += 1;

    /* bMaxPacketSize0 */
    dissect_max_packet_size0(pinfo, tree, tvb, offset, usb_conv_info, FALSE);
    offset += 1;

    /* if request was only for the first 8 bytes */
    /* per 5.5.3 of USB2.0 Spec */
    if (8 == usb_conv_info->usb_trans_info->setup.wLength) {
        proto_item_set_len(item, offset-old_offset);
        return offset;
    }

    /* idVendor */
    proto_tree_add_item_ret_uint(tree, hf_usb_idVendor, tvb, offset, 2, ENC_LITTLE_ENDIAN, &vendor_id);
    usb_conv_info->deviceVendor = (guint16)vendor_id;
    offset += 2;

    /* idProduct */
    product_id = tvb_get_letohs(tvb, offset);
    usb_conv_info->deviceProduct = product_id;
    product = (guint16)vendor_id << 16 | product_id;

    proto_tree_add_uint_format_value(tree, hf_usb_idProduct, tvb, offset, 2, product_id, "%s (0x%04x)",
                                     val_to_str_ext_const(product, &ext_usb_products_vals, "Unknown"),
                                     product_id);
    offset += 2;

    /* bcdDevice */
    usb_conv_info->deviceVersion = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_usb_bcdDevice, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (!pinfo->fd->visited) {
        guint                   k_bus_id;
        guint                   k_device_address;
        guint                   k_frame_number;
        wmem_tree_key_t         key[4];
        device_product_data_t   *device_product_data;
        device_protocol_data_t  *device_protocol_data;

        k_frame_number = pinfo->num;
        k_device_address = usb_conv_info->device_address;
        k_bus_id = usb_conv_info->bus_id;

        key[0].length = 1;
        key[0].key    = &k_device_address;
        key[1].length = 1;
        key[1].key    = &k_bus_id;
        key[2].length = 1;
        key[2].key    = &k_frame_number;
        key[3].length = 0;
        key[3].key    = NULL;

        device_product_data = wmem_new(wmem_file_scope(), device_product_data_t);
        device_product_data->vendor = vendor_id;
        device_product_data->product = product_id;
        device_product_data->device = usb_conv_info->deviceVersion;
        device_product_data->bus_id = usb_conv_info->bus_id;
        device_product_data->device_address = usb_conv_info->device_address;
        wmem_tree_insert32_array(device_to_product_table, key, device_product_data);

        device_protocol_data = wmem_new(wmem_file_scope(), device_protocol_data_t);
        device_protocol_data->protocol = protocol;
        device_protocol_data->bus_id = usb_conv_info->bus_id;
        device_protocol_data->device_address = usb_conv_info->device_address;

        wmem_tree_insert32_array(device_to_protocol_table, key, device_protocol_data);
    }

    /* iManufacturer */
    proto_tree_add_item(tree, hf_usb_iManufacturer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* iProduct */
    proto_tree_add_item(tree, hf_usb_iProduct, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* iSerialNumber */
    usb_conv_info->iSerialNumber = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_iSerialNumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bNumConfigurations */
    proto_tree_add_item(tree, hf_usb_bNumConfigurations, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

/* 9.6.7 */
static int
dissect_usb_string_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree,
                              tvbuff_t *tvb, int offset,
                              usb_conv_info_t  *usb_conv_info)
{
    proto_item *item;
    proto_tree *tree;
    int         old_offset = offset;
    guint8      len;
    proto_item *len_item;
    usb_trans_info_t *usb_trans_info;

    usb_trans_info = usb_conv_info->usb_trans_info;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "STRING DESCRIPTOR");

    len = tvb_get_guint8(tvb, offset);
    /* The USB spec says that the languages / the string are UTF16 and not
       0-terminated, i.e. the length field must contain an even number */
    if (len & 0x1) {
        /* bLength */
        len_item = proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        expert_add_info(pinfo, len_item, &ei_usb_bLength_even);

        /* bDescriptorType */
        proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
    }
    else
       len_item = dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += 2;

    /* Report an error, and give up, if the length is < 2 */
    if (len < 2) {
        expert_add_info(pinfo, len_item, &ei_usb_bLength_too_short);
        return offset;
    }

    if (!usb_trans_info->u.get_descriptor.usb_index) {
        /* list of languanges */
        while (offset >= old_offset && len > (offset - old_offset)) {
            /* wLANGID */
            proto_tree_add_item(tree, hf_usb_wLANGID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;
        }
    } else {
        /* UTF-16 string */
        /* handle case of host requesting only substring */
        guint8 len_str = MIN(len-2, usb_trans_info->setup.wLength -2);
        proto_tree_add_item(tree, hf_usb_bString, tvb, offset, len_str, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += len_str;
    }

    proto_item_set_len(item, offset-old_offset);

    return offset;
}



/* 9.6.5 */
static int
dissect_usb_interface_descriptor(packet_info *pinfo, proto_tree *parent_tree,
                                 tvbuff_t *tvb, int offset,
                                 usb_conv_info_t  *usb_conv_info)
{
    proto_item       *item;
    proto_tree       *tree;
    const char       *class_str  = NULL;
    int               old_offset = offset;
    guint8            len;
    guint8            interface_num;
    guint8            alt_setting;
    usb_trans_info_t *usb_trans_info;

    usb_trans_info = usb_conv_info->usb_trans_info;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "INTERFACE DESCRIPTOR");

    len = tvb_get_guint8(tvb, offset);
    dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += 2;

    /* bInterfaceNumber */
    interface_num = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_bInterfaceNumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    usb_conv_info->interfaceNum = interface_num;
    offset += 1;

    /* bAlternateSetting */
    alt_setting = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bNumEndpoints */
    proto_tree_add_item(tree, hf_usb_bNumEndpoints, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bInterfaceClass */
    proto_tree_add_item(tree, hf_usb_bInterfaceClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    /* save the class so we can access it later in the endpoint descriptor */
    usb_conv_info->interfaceClass = tvb_get_guint8(tvb, offset);

    class_str = val_to_str_ext(usb_conv_info->interfaceClass, &usb_class_vals_ext, "unknown (0x%X)");
    proto_item_append_text(item, " (%u.%u): class %s", interface_num, alt_setting, class_str);

    if (!pinfo->fd->visited) {
        usb_alt_setting_t alternate_setting;

        /* Register conversation for this interface in case CONTROL messages are sent to it */
        usb_trans_info->interface_info = get_usb_iface_conv_info(pinfo, interface_num);
        usb_trans_info->interface_info->bus_id = usb_conv_info->bus_id;
        usb_trans_info->interface_info->device_address = usb_conv_info->device_address;

        alternate_setting.altSetting = alt_setting;
        alternate_setting.interfaceClass = tvb_get_guint8(tvb, offset);
        alternate_setting.interfaceSubclass = tvb_get_guint8(tvb, offset+1);
        alternate_setting.interfaceProtocol = tvb_get_guint8(tvb, offset+2);
        alternate_setting.interfaceNum = interface_num;
        wmem_array_append_one(usb_trans_info->interface_info->alt_settings, alternate_setting);

        if (alt_setting == 0) {
            /* By default let's assume alternate setting 0 will be used */

            /* in interface conversations, endpoint has no meaning */
            usb_trans_info->interface_info->endpoint = NO_ENDPOINT8;

            usb_trans_info->interface_info->interfaceClass = alternate_setting.interfaceClass;
            usb_trans_info->interface_info->interfaceSubclass = alternate_setting.interfaceSubclass;
            usb_trans_info->interface_info->interfaceProtocol = alternate_setting.interfaceProtocol;
            usb_trans_info->interface_info->interfaceNum      = alternate_setting.interfaceNum;
            usb_trans_info->interface_info->deviceVendor      = usb_conv_info->deviceVendor;
            usb_trans_info->interface_info->deviceProduct     = usb_conv_info->deviceProduct;
            usb_trans_info->interface_info->deviceVersion     = usb_conv_info->deviceVersion;
        }
    }
    offset += 1;

    /* bInterfaceSubClass */
    switch (usb_conv_info->interfaceClass) {
    case IF_CLASS_AUDIO:
        proto_tree_add_item(tree, hf_usb_bInterfaceSubClass_audio, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case IF_CLASS_COMMUNICATIONS:
        proto_tree_add_item(tree, hf_usb_bInterfaceSubClass_cdc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case IF_CLASS_MASS_STORAGE:
        proto_tree_add_item(tree, hf_usb_bInterfaceSubClass_massstorage, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case IF_CLASS_HID:
        proto_tree_add_item(tree, hf_usb_bInterfaceSubClass_hid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case IF_CLASS_MISCELLANEOUS:
        proto_tree_add_item(tree, hf_usb_bInterfaceSubClass_misc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case IF_CLASS_APPLICATION_SPECIFIC:
        proto_tree_add_item(tree, hf_usb_bInterfaceSubClass_app, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    default:
        proto_tree_add_item(tree, hf_usb_bInterfaceSubClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }

    /* save the subclass so we can access it later in class-specific descriptors */
    usb_conv_info->interfaceSubclass = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* bInterfaceProtocol */
    switch (usb_conv_info->interfaceClass) {
    case IF_CLASS_COMMUNICATIONS:
        proto_tree_add_item(tree, hf_usb_bInterfaceProtocol_cdc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case IF_CLASS_MASS_STORAGE:
        proto_tree_add_item(tree, hf_usb_bInterfaceProtocol_massstorage, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case IF_CLASS_CDC_DATA:
        proto_tree_add_item(tree, hf_usb_bInterfaceProtocol_cdc_data, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case IF_CLASS_APPLICATION_SPECIFIC:
        switch (usb_conv_info->interfaceSubclass) {
        case 0x01:
            proto_tree_add_item(tree, hf_usb_bInterfaceProtocol_app_dfu, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;
        case 0x02:
            proto_tree_add_item(tree, hf_usb_bInterfaceProtocol_app_irda, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;
        case 0x03:
            proto_tree_add_item(tree, hf_usb_bInterfaceProtocol_app_usb_test_and_measurement, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(tree, hf_usb_bInterfaceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        break;
    case IF_CLASS_HID:
        if (usb_conv_info->interfaceSubclass == 1) {
            proto_tree_add_item(tree, hf_usb_bInterfaceProtocol_hid_boot, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;
        }

        proto_tree_add_item(tree, hf_usb_bInterfaceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        break;
    default:
        proto_tree_add_item(tree, hf_usb_bInterfaceProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }

    usb_conv_info->interfaceProtocol = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* iInterface */
    proto_tree_add_item(tree, hf_usb_iInterface, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_item_set_len(item, len);

    if (offset < old_offset+len) {
        /* skip unknown records */
        offset = old_offset + len;
    }

    return offset;
}

/* 9.6.6 */
const true_false_string tfs_endpoint_direction = {
    "IN Endpoint",
    "OUT Endpoint"
};

void dissect_usb_endpoint_address(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_item *endpoint_item;
    proto_tree *endpoint_tree;
    guint8      endpoint;

    endpoint_item = proto_tree_add_item(tree, hf_usb_bEndpointAddress, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    endpoint_tree = proto_item_add_subtree(endpoint_item, ett_configuration_bEndpointAddress);

    endpoint = tvb_get_guint8(tvb, offset)&0x0f;
    proto_tree_add_item(endpoint_tree, hf_usb_bEndpointAddress_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(endpoint_item, "  %s", (tvb_get_guint8(tvb, offset)&0x80)?"IN":"OUT");
    proto_tree_add_item(endpoint_tree, hf_usb_bEndpointAddress_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(endpoint_item, "  Endpoint:%d", endpoint);
}

unsigned int
sanitize_usb_max_packet_size(guint8 ep_type, usb_speed_t speed,
                             unsigned int max_packet_size)
{
    unsigned int sanitized = max_packet_size;
    switch (speed) {
    case USB_SPEED_LOW:
        switch (ep_type) {
            case ENDPOINT_TYPE_CONTROL:
                /* 8 is the only allowed value */
                sanitized = 8;
                break;
            case ENDPOINT_TYPE_INTERRUPT:
                if (max_packet_size > 8)
                    sanitized = 8;
                break;
            default:
                /* Not allowed */
                break;
        }
        break;
    case USB_SPEED_FULL:
        switch (ep_type) {
        case ENDPOINT_TYPE_CONTROL:
        case ENDPOINT_TYPE_BULK:
            /* Allowed values are: 8, 16, 32 and 64 */
            if (max_packet_size > 32)
                sanitized = 64;
            else if (max_packet_size > 16)
                sanitized = 32;
            else if (max_packet_size > 8)
                sanitized = 16;
            else
                sanitized = 8;
            break;
        case ENDPOINT_TYPE_INTERRUPT:
            if (max_packet_size > 64)
                sanitized = 64;
            break;
        case ENDPOINT_TYPE_ISOCHRONOUS:
            if (max_packet_size > 1023)
                sanitized = 1023;
            break;
        default:
            break;
        }
        break;
    case USB_SPEED_HIGH:
        switch (ep_type) {
        case ENDPOINT_TYPE_CONTROL:
            /* 64 is the only allowed value */
            sanitized = 64;
            break;
        case ENDPOINT_TYPE_BULK:
            /* 512 is the only allowed value */
            sanitized = 512;
            break;
        case ENDPOINT_TYPE_INTERRUPT:
        case ENDPOINT_TYPE_ISOCHRONOUS:
            if (max_packet_size > 1024)
                sanitized = 1024;
            break;
        default:
            break;
        }
        break;
    case USB_SPEED_UNKNOWN:
    default:
        break;
    }

    return sanitized;
}

int
dissect_usb_endpoint_descriptor(packet_info *pinfo, proto_tree *parent_tree,
                                tvbuff_t *tvb, int offset,
                                usb_conv_info_t  *usb_conv_info,
                                guint8 *out_ep_type, usb_speed_t speed)
{
    proto_item       *item;
    proto_tree       *tree;
    proto_item       *ep_attrib_item;
    proto_tree       *ep_attrib_tree;
    proto_item       *ep_type_item;
    proto_item       *ep_pktsize_item;
    proto_tree       *ep_pktsize_tree;
    int               old_offset     = offset;
    guint8            endpoint;
    guint8            ep_type;
    guint8            len;
    guint32           max_packet_size;
    unsigned int      sanitized_max_packet_size;
    usb_trans_info_t *usb_trans_info = NULL;
    conversation_t   *conversation   = NULL;

    if (usb_conv_info)
        usb_trans_info = usb_conv_info->usb_trans_info;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "ENDPOINT DESCRIPTOR");

    len = tvb_get_guint8(tvb, offset);
    dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += 2;

    endpoint = tvb_get_guint8(tvb, offset)&0x0f;
    dissect_usb_endpoint_address(tree, tvb, offset);
    offset += 1;

    /* Together with class from the interface descriptor we know what kind
     * of class the device at endpoint is.
     * Make sure a conversation exists for this endpoint and attach a
     * usb_conv_into_t structure to it.
     *
     * All endpoints for the same interface descriptor share the same
     * usb_conv_info structure.
     */
    if ((!pinfo->fd->visited) && usb_trans_info && usb_trans_info->interface_info) {
        if (pinfo->destport == NO_ENDPOINT) {
            address tmp_addr;
            usb_address_t *usb_addr = wmem_new0(pinfo->pool, usb_address_t);

            /* packet is sent from a USB device's endpoint 0 to the host
             * replace endpoint 0 with the endpoint of this descriptor
             * and find the corresponding conversation
             */
            usb_addr->bus_id = ((const usb_address_t *)(pinfo->src.data))->bus_id;
            usb_addr->device = ((const usb_address_t *)(pinfo->src.data))->device;
            usb_addr->endpoint = GUINT32_TO_LE(endpoint);
            set_address(&tmp_addr, usb_address_type, USB_ADDR_LEN, (char *)usb_addr);
            conversation = get_usb_conversation(pinfo, &tmp_addr, &pinfo->dst, usb_addr->endpoint, pinfo->destport);
        }

        if (conversation) {
            usb_trans_info->interface_info->endpoint = endpoint;
            conversation_add_proto_data(conversation, proto_usb, usb_trans_info->interface_info);
        }
    }

    /* bmAttributes */
    ep_type = ENDPOINT_TYPE(tvb_get_guint8(tvb, offset));
    if (out_ep_type) {
        *out_ep_type = ep_type;
    }

    ep_attrib_item = proto_tree_add_item(tree, hf_usb_bmAttributes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    ep_attrib_tree = proto_item_add_subtree(ep_attrib_item, ett_endpoint_bmAttributes);

    ep_type_item = proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeTransfer, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    if (ep_type==USB_EP_ISOCHRONOUS) {
        proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeSynchonisation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ep_attrib_tree, hf_usb_bEndpointAttributeBehaviour, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }

    /* At Low-Speed, only control and interrupt transfers are allowed */
    if ((speed == USB_SPEED_LOW) && !((ep_type == USB_EP_CONTROL) || (ep_type == USB_EP_INTERRUPT))) {
        expert_add_info(pinfo, ep_type_item, &ei_usb_invalid_endpoint_type);
    }
    offset += 1;

    /* wMaxPacketSize */
    ep_pktsize_item = proto_tree_add_item(tree, hf_usb_wMaxPacketSize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    ep_pktsize_tree = proto_item_add_subtree(ep_pktsize_item, ett_endpoint_wMaxPacketSize);
    if ((ep_type == ENDPOINT_TYPE_INTERRUPT) || (ep_type == ENDPOINT_TYPE_ISOCHRONOUS)) {
        proto_tree_add_item(ep_pktsize_tree, hf_usb_wMaxPacketSize_slots, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item_ret_uint(ep_pktsize_tree, hf_usb_wMaxPacketSize_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &max_packet_size);
    sanitized_max_packet_size = sanitize_usb_max_packet_size(ep_type, speed, max_packet_size);
    if (sanitized_max_packet_size != max_packet_size) {
        expert_add_info_format(pinfo, ep_pktsize_item, &ei_usb_invalid_max_packet_size,
            "%s %s endpoint max packet size cannot be %u, using %d instead.",
            try_val_to_str(speed, usb_speed_vals), try_val_to_str(ep_type, usb_bmAttributes_transfer_vals),
            max_packet_size, sanitized_max_packet_size);
        max_packet_size = sanitized_max_packet_size;
    }
    offset+=2;

    if (conversation) {
        usb_conv_info_t* endpoint_conv_info = get_usb_conv_info(conversation);
        guint8 transfer_type;

        switch(ep_type) {
        case ENDPOINT_TYPE_CONTROL:
            transfer_type = URB_CONTROL;
            break;
        case ENDPOINT_TYPE_ISOCHRONOUS:
            transfer_type = URB_ISOCHRONOUS;
            break;
        case ENDPOINT_TYPE_BULK:
            transfer_type = URB_BULK;
            break;
        case ENDPOINT_TYPE_INTERRUPT:
            transfer_type = URB_INTERRUPT;
            break;
        default:
            transfer_type = URB_UNKNOWN;
            break;
        }
        endpoint_conv_info->descriptor_transfer_type = transfer_type;
        endpoint_conv_info->max_packet_size = max_packet_size;
    }

    /* bInterval */
    proto_tree_add_item(tree, hf_usb_bInterval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bRefresh and bSynchAddress are present only in the Audio 1.0
     * Endpoint Descriptors, so observe the descriptor size  */
    if (usb_conv_info && (usb_conv_info->interfaceClass == IF_CLASS_AUDIO)
            && (len >= 9)) {
        proto_tree_add_item(tree, hf_usb_audio_bRefresh, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_usb_audio_bSynchAddress, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    proto_item_set_len(item, len);

    if (offset < old_offset+len) {
        /* mark unknown records as undecoded */
        proto_tree_add_expert(tree, pinfo, &ei_usb_undecoded, tvb, offset, old_offset + len - offset);
        offset = old_offset + len;
    }

    return offset;
}

static int
dissect_usb_endpoint_companion_descriptor(packet_info *pinfo, proto_tree *parent_tree,
                                          tvbuff_t *tvb, int offset,
                                          usb_conv_info_t *usb_conv_info _U_,
                                          guint8 ep_type)
{
    proto_item       *item;
    proto_tree       *tree;
    proto_item       *ep_attrib_item;
    proto_tree       *ep_attrib_tree;
    int               old_offset = offset;
    guint8            len;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "SUPERSPEED ENDPOINT COMPANION DESCRIPTOR");

    len = tvb_get_guint8(tvb, offset);
    dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += 2;

    /* bMaxBurst */
    proto_tree_add_item(tree, hf_usb_bMaxBurst, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bmAttributes */
    ep_attrib_item = proto_tree_add_item(tree, hf_usb_bmAttributes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    switch (ep_type) {
    case ENDPOINT_TYPE_CONTROL:
        break;
    case ENDPOINT_TYPE_ISOCHRONOUS:
        ep_attrib_tree = proto_item_add_subtree(ep_attrib_item, ett_endpoint_bmAttributes);
        proto_tree_add_item(ep_attrib_tree, hf_usb_bSSEndpointAttributeIsoMult, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case ENDPOINT_TYPE_BULK:
        ep_attrib_tree = proto_item_add_subtree(ep_attrib_item, ett_endpoint_bmAttributes);
        proto_tree_add_item(ep_attrib_tree, hf_usb_bSSEndpointAttributeBulkMaxStreams, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case ENDPOINT_TYPE_INTERRUPT:
        break;
    default:
        expert_add_info(pinfo, ep_attrib_item, &ei_usb_ss_ep_companion_before_ep);
        break;
    }
    offset += 1;

    /* wBytesPerInterval */
    proto_tree_add_item(tree, hf_usb_wBytesPerInterval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_item_set_len(item, len);

    if (offset < old_offset + len) {
        /* mark unknown records as undecoded */
        proto_tree_add_expert(tree, pinfo, &ei_usb_undecoded, tvb, offset, old_offset + len - offset);
        offset = old_offset + len;
    }

    return offset;
}

/* ECN */
static int
dissect_usb_interface_assn_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree,
                                      tvbuff_t *tvb, int offset,
                                      usb_conv_info_t  *usb_conv_info _U_)
{
    proto_item *item;
    proto_tree *tree;
    int         old_offset = offset;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "INTERFACE ASSOCIATION DESCRIPTOR");

    dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += 2;

    /* bFirstInterface */
    proto_tree_add_item(tree, hf_usb_bFirstInterface, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bInterfaceCount */
    proto_tree_add_item(tree, hf_usb_bInterfaceCount, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bFunctionClass */
    proto_tree_add_item(tree, hf_usb_bFunctionClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bFunctionSubclass */
    proto_tree_add_item(tree, hf_usb_bFunctionSubClass, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bFunctionProtocol */
    proto_tree_add_item(tree, hf_usb_bFunctionProtocol, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* iFunction */
    proto_tree_add_item(tree, hf_usb_iFunction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

int
dissect_usb_unknown_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree,
                               tvbuff_t *tvb, int offset,
                               usb_conv_info_t  *usb_conv_info _U_)
{
    proto_item *item;
    proto_tree *tree;
    guint8      bLength;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "UNKNOWN DESCRIPTOR");

    bLength = tvb_get_guint8(tvb, offset);
    dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += bLength;

    proto_item_set_len(item, bLength);

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
dissect_usb_configuration_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree,
                                     tvbuff_t *tvb, int offset,
                                     usb_conv_info_t  *usb_conv_info, usb_speed_t speed)
{
    proto_item *item;
    proto_tree *tree;
    int         old_offset = offset;
    guint16     len;
    proto_item *flags_item;
    proto_tree *flags_tree;
    guint8      flags;
    guint8      last_ep_type = ENDPOINT_TYPE_NOT_SET;
    proto_item *power_item;
    guint8      power;
    gboolean    truncation_expected;
    usb_trans_info_t *usb_trans_info;

    usb_trans_info = usb_conv_info->usb_trans_info;

    usb_conv_info->interfaceClass    = IF_CLASS_UNKNOWN;
    usb_conv_info->interfaceSubclass = IF_SUBCLASS_UNKNOWN;
    usb_conv_info->interfaceProtocol = IF_PROTOCOL_UNKNOWN;

    tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1, ett_descriptor_device, &item, "CONFIGURATION DESCRIPTOR");

    dissect_usb_descriptor_header(tree, tvb, offset, NULL);
    offset += 2;

    /* wTotalLength */
    proto_tree_add_item(tree, hf_usb_wTotalLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    len = tvb_get_letohs(tvb, offset);
    offset+=2;

    /* bNumInterfaces */
    proto_tree_add_item(tree, hf_usb_bNumInterfaces, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bConfigurationValue */
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* iConfiguration */
    proto_tree_add_item(tree, hf_usb_iConfiguration, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* bmAttributes */
    flags_item = proto_tree_add_item(tree, hf_usb_configuration_bmAttributes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    flags_tree = proto_item_add_subtree(flags_item, ett_configuration_bmAttributes);

    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(flags_tree, hf_usb_configuration_legacy10buspowered, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(flags_tree, hf_usb_configuration_selfpowered, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(flags_item, "  %sSELF-POWERED", (flags&0x40)?"":"NOT ");
    proto_tree_add_item(flags_tree, hf_usb_configuration_remotewakeup, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(flags_item, "  %sREMOTE-WAKEUP", (flags&0x20)?"":"NO ");
    offset += 1;

    /* bMaxPower */
    power_item = proto_tree_add_item(tree, hf_usb_bMaxPower, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    power = tvb_get_guint8(tvb, offset);
    proto_item_append_text(power_item, "  (%dmA)", power*2);
    offset += 1;

    /* initialize interface_info to NULL */
    usb_trans_info->interface_info = NULL;

    truncation_expected = (usb_trans_info->setup.wLength < len);

    /* decode any additional interface and endpoint descriptors */
    while(len>(offset-old_offset)) {
        guint8 next_type;
        guint8 next_len = 0;
        gint remaining_tvb, remaining_len;
        tvbuff_t *next_tvb = NULL;

        /* Handle truncated descriptors appropriately */
        remaining_tvb = tvb_reported_length_remaining(tvb, offset);
        if (remaining_tvb > 0) {
            next_len  = tvb_get_guint8(tvb, offset);
            remaining_len = len - (offset - old_offset);
            if ((next_len < 3) || (next_len > remaining_len)) {
                proto_tree_add_expert_format(parent_tree, pinfo, &ei_usb_desc_length_invalid,
                    tvb, offset, 1, "Invalid descriptor length: %u",  next_len);
                item = NULL;
                break;
            }
        }

        if ((remaining_tvb == 0) || (next_len > remaining_tvb)) {
            if (truncation_expected)
                break;
        }

        next_type = tvb_get_guint8(tvb, offset+1);
        switch(next_type) {
        case USB_DT_INTERFACE:
            offset = dissect_usb_interface_descriptor(pinfo, parent_tree, tvb, offset, usb_conv_info);
            break;
        case USB_DT_ENDPOINT:
            offset = dissect_usb_endpoint_descriptor(pinfo, parent_tree, tvb, offset, usb_conv_info, &last_ep_type, speed);
            break;
        case USB_DT_INTERFACE_ASSOCIATION:
            offset = dissect_usb_interface_assn_descriptor(pinfo, parent_tree, tvb, offset, usb_conv_info);
            break;
        case USB_DT_SUPERSPEED_EP_COMPANION:
            offset = dissect_usb_endpoint_companion_descriptor(pinfo, parent_tree, tvb, offset, usb_conv_info, last_ep_type);
            break;
        default:
            next_tvb = tvb_new_subset_length(tvb, offset, next_len);
            if (dissector_try_uint_new(usb_descriptor_dissector_table, usb_conv_info->interfaceClass, next_tvb, pinfo, parent_tree, TRUE, usb_conv_info)) {
                offset += next_len;
            } else {
                offset = dissect_usb_unknown_descriptor(pinfo, parent_tree, tvb, offset, usb_conv_info);
            }
            break;
            /* was: return offset; */
        }
    }

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

/* 9.4.3 */
static int
dissect_usb_setup_get_descriptor_request(packet_info *pinfo, proto_tree *tree,
                                         tvbuff_t *tvb, int offset,
                                         usb_conv_info_t  *usb_conv_info)
{
    usb_trans_info_t *usb_trans_info, trans_info;

    if (usb_conv_info)
        usb_trans_info = usb_conv_info->usb_trans_info;
    else
        usb_trans_info = &trans_info;

    /* descriptor index */
    proto_tree_add_item(tree, hf_usb_descriptor_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    usb_trans_info->u.get_descriptor.usb_index = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* descriptor type */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    usb_trans_info->u.get_descriptor.type = tvb_get_guint8(tvb, offset);
    offset += 1;
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
        val_to_str_ext(usb_trans_info->u.get_descriptor.type, &std_descriptor_type_vals_ext, "Unknown type %u"));

    /* language id */
    proto_tree_add_item(tree, hf_usb_language_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_get_descriptor_response(packet_info *pinfo, proto_tree *tree,
                                          tvbuff_t *tvb, int offset,
                                          usb_conv_info_t  *usb_conv_info)
{
    usb_trans_info_t *usb_trans_info;
    usb_speed_t       speed;

    usb_trans_info = usb_conv_info->usb_trans_info;
    speed = usb_conv_info->speed;

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
        val_to_str_ext(usb_trans_info->u.get_descriptor.type, &std_descriptor_type_vals_ext, "Unknown type %u"));

    switch(usb_trans_info->u.get_descriptor.type) {
        case USB_DT_INTERFACE:
        case USB_DT_ENDPOINT:
            /* an interface or an endpoint descriptor can only be accessed
               as part of a configuration descriptor */
            break;
        case USB_DT_DEVICE:
            offset = dissect_usb_device_descriptor(pinfo, tree, tvb, offset, usb_conv_info);
            break;
        case USB_DT_OTHER_SPEED_CONFIG:
            /* USB 2.0 Specification: 9.2.6.6 Speed Dependent Descriptors */
            if (speed == USB_SPEED_FULL)
                speed = USB_SPEED_HIGH;
            else if (speed == USB_SPEED_HIGH)
                speed = USB_SPEED_FULL;
            /* fall-through */
        case USB_DT_CONFIG:
            offset = dissect_usb_configuration_descriptor(pinfo, tree, tvb, offset, usb_conv_info, speed);
            break;
        case USB_DT_STRING:
            offset = dissect_usb_string_descriptor(pinfo, tree, tvb, offset, usb_conv_info);
            break;
        case USB_DT_DEVICE_QUALIFIER:
            offset = dissect_usb_device_qualifier_descriptor(pinfo, tree, tvb, offset, usb_conv_info);
            break;
        default:
            /* XXX dissect the descriptor coming back from the device */
            {
                guint len = tvb_reported_length_remaining(tvb, offset);
                proto_tree_add_bytes_format(tree, hf_usb_get_descriptor_resp_generic, tvb, offset, len, NULL,
                                            "GET DESCRIPTOR Response data (unknown descriptor type %u): %s",
                                            usb_trans_info->u.get_descriptor.type,
                                            tvb_bytes_to_str(pinfo->pool, tvb, offset, len));
                offset = offset + len;
            }
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
dissect_usb_setup_get_interface_request(packet_info *pinfo _U_, proto_tree *tree,
                                        tvbuff_t *tvb, int offset,
                                        usb_conv_info_t  *usb_conv_info _U_)
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
dissect_usb_setup_get_interface_response(packet_info *pinfo _U_, proto_tree *tree,
                                         tvbuff_t *tvb, int offset,
                                         usb_conv_info_t  *usb_conv_info _U_)
{
    /* alternate setting */
    proto_tree_add_item(tree, hf_usb_bAlternateSetting, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / GET STATUS
 */


/* 9.4.5 */
static int
dissect_usb_setup_get_status_request(packet_info *pinfo _U_, proto_tree *tree,
                                     tvbuff_t *tvb, int offset,
                                     usb_conv_info_t  *usb_conv_info _U_)
{
    /* zero */
    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* zero/interface/endpoint */
    if (usb_conv_info) {
        guint8 recip;

        recip = USB_RECIPIENT(usb_conv_info->usb_trans_info->setup.requesttype);

        switch (recip) {
        case RQT_SETUP_RECIPIENT_INTERFACE:
            proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

        case RQT_SETUP_RECIPIENT_ENDPOINT:
            proto_tree_add_item(tree, hf_usb_wEndpoint, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

        case RQT_SETUP_RECIPIENT_DEVICE:
        case RQT_SETUP_RECIPIENT_OTHER:
        default:
            proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        }
    } else {
        proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    offset += 2;

    /* length */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_get_status_response(packet_info *pinfo _U_, proto_tree *tree,
                                      tvbuff_t *tvb, int offset,
                                      usb_conv_info_t  *usb_conv_info _U_)
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
dissect_usb_setup_set_address_request(packet_info *pinfo _U_, proto_tree *tree,
                                      tvbuff_t *tvb, int offset,
                                      usb_conv_info_t  *usb_conv_info _U_)
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
dissect_usb_setup_set_address_response(packet_info *pinfo _U_, proto_tree *tree _U_,
                                       tvbuff_t *tvb _U_, int offset,
                                       usb_conv_info_t  *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SET CONFIGURATION
 */


/* 9.4.7 */
static int
dissect_usb_setup_set_configuration_request(packet_info *pinfo _U_, proto_tree *tree,
                                            tvbuff_t *tvb, int offset,
                                            usb_conv_info_t  *usb_conv_info _U_)
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
dissect_usb_setup_set_configuration_response(packet_info *pinfo _U_, proto_tree *tree _U_,
                                             tvbuff_t *tvb _U_, int offset,
                                             usb_conv_info_t  *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SET FEATURE
 */


/* 9.4.9 */
static int
dissect_usb_setup_set_feature_request(packet_info *pinfo _U_, proto_tree *tree,
                                      tvbuff_t *tvb, int offset,
                                      usb_conv_info_t  *usb_conv_info)
{
    guint8 recip;

    if (usb_conv_info) {
        recip = USB_RECIPIENT(usb_conv_info->usb_trans_info->setup.requesttype);

        /* feature selector, zero/interface/endpoint */
        switch (recip) {
        case RQT_SETUP_RECIPIENT_DEVICE:
            proto_tree_add_item(tree, hf_usb_device_wFeatureSelector, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

        case RQT_SETUP_RECIPIENT_INTERFACE:
            proto_tree_add_item(tree, hf_usb_interface_wFeatureSelector, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_wInterface, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

        case RQT_SETUP_RECIPIENT_ENDPOINT:
            proto_tree_add_item(tree, hf_usb_endpoint_wFeatureSelector, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_wEndpoint, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;

        case RQT_SETUP_RECIPIENT_OTHER:
        default:
            proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            break;
        }
    } else {
        /* No conversation information, so recipient type is unknown */
        proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_set_feature_response(packet_info *pinfo _U_, proto_tree *tree _U_,
                                       tvbuff_t *tvb _U_, int offset,
                                       usb_conv_info_t  *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SET INTERFACE
 */


/* 9.4.10 */
static int
dissect_usb_setup_set_interface_request(packet_info *pinfo, proto_tree *tree,
                                        tvbuff_t *tvb, int offset,
                                        usb_conv_info_t  *usb_conv_info _U_)
{
    guint8 alt_setting, interface_num;

    /* alternate setting */
    alt_setting = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_usb_bAlternateSetting, tvb, offset, 2, alt_setting);
    offset += 2;

    /* interface */
    interface_num = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_usb_wInterface, tvb, offset, 2, interface_num);
    offset += 2;

    /* zero */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (!PINFO_FD_VISITED(pinfo)) {
        guint i, count;
        usb_conv_info_t *iface_conv_info = get_usb_iface_conv_info(pinfo, interface_num);

        /* update the conversation info with the selected alternate setting */
        count = wmem_array_get_count(iface_conv_info->alt_settings);
        for (i = 0; i < count; i++) {
            usb_alt_setting_t *alternate_setting = (usb_alt_setting_t *)wmem_array_index(iface_conv_info->alt_settings, i);

            if (alternate_setting->altSetting == alt_setting) {
                iface_conv_info->interfaceClass = alternate_setting->interfaceClass;
                iface_conv_info->interfaceSubclass = alternate_setting->interfaceSubclass;
                iface_conv_info->interfaceProtocol = alternate_setting->interfaceProtocol;
                iface_conv_info->interfaceNum = alternate_setting->interfaceNum;
                break;
            }
        }
    }

    return offset;
}

static int
dissect_usb_setup_set_interface_response(packet_info *pinfo _U_, proto_tree *tree _U_,
                                         tvbuff_t *tvb _U_, int offset,
                                         usb_conv_info_t  *usb_conv_info _U_)
{
    return offset;
}


/*
 * These dissectors are used to dissect the setup part and the data
 * for URB_CONTROL_INPUT / SYNCH FRAME
 */


/* 9.4.11 */
static int
dissect_usb_setup_synch_frame_request(packet_info *pinfo _U_, proto_tree *tree,
                                      tvbuff_t *tvb, int offset,
                                      usb_conv_info_t  *usb_conv_info _U_)
{
    /* zero */
    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* endpoint */
    proto_tree_add_item(tree, hf_usb_wEndpoint, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* two */
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_usb_setup_synch_frame_response(packet_info *pinfo _U_, proto_tree *tree _U_,
                                       tvbuff_t *tvb _U_, int offset,
                                       usb_conv_info_t  *usb_conv_info _U_)
{
    /* frame number */
    proto_tree_add_item(tree, hf_usb_wFrameNumber, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

/* Dissector used for unknown USB setup request/responses */
static int
dissect_usb_setup_generic(packet_info *pinfo _U_, proto_tree *tree ,
                                       tvbuff_t *tvb, int offset,
                                       usb_conv_info_t  *usb_conv_info _U_)
{

    proto_tree_add_item(tree, hf_usb_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}



typedef int (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree,
                                   tvbuff_t *tvb, int offset,
                                   usb_conv_info_t  *usb_conv_info);

typedef struct _usb_setup_dissector_table_t {
    guint8 request;
    usb_setup_dissector dissector;

} usb_setup_dissector_table_t;
static const usb_setup_dissector_table_t setup_request_dissectors[] = {
    {USB_SETUP_GET_STATUS,        dissect_usb_setup_get_status_request},
    {USB_SETUP_CLEAR_FEATURE,     dissect_usb_setup_clear_feature_request},
    {USB_SETUP_SET_FEATURE,       dissect_usb_setup_set_feature_request},
    {USB_SETUP_SET_ADDRESS,       dissect_usb_setup_set_address_request},
    {USB_SETUP_GET_DESCRIPTOR,    dissect_usb_setup_get_descriptor_request},
    {USB_SETUP_SET_CONFIGURATION, dissect_usb_setup_set_configuration_request},
    {USB_SETUP_GET_INTERFACE,     dissect_usb_setup_get_interface_request},
    {USB_SETUP_SET_INTERFACE,     dissect_usb_setup_set_interface_request},
    {USB_SETUP_SYNCH_FRAME,       dissect_usb_setup_synch_frame_request},
    {0, NULL}
};

static const usb_setup_dissector_table_t setup_response_dissectors[] = {
    {USB_SETUP_GET_STATUS,        dissect_usb_setup_get_status_response},
    {USB_SETUP_CLEAR_FEATURE,     dissect_usb_setup_clear_feature_response},
    {USB_SETUP_SET_FEATURE,       dissect_usb_setup_set_feature_response},
    {USB_SETUP_SET_ADDRESS,       dissect_usb_setup_set_address_response},
    {USB_SETUP_GET_DESCRIPTOR,    dissect_usb_setup_get_descriptor_response},
    {USB_SETUP_GET_CONFIGURATION, dissect_usb_setup_get_configuration_response},
    {USB_SETUP_SET_CONFIGURATION, dissect_usb_setup_set_configuration_response},
    {USB_SETUP_GET_INTERFACE,     dissect_usb_setup_get_interface_response},
    {USB_SETUP_SET_INTERFACE,     dissect_usb_setup_set_interface_response},
    {USB_SETUP_SYNCH_FRAME,       dissect_usb_setup_synch_frame_response},
    {0, NULL}
};

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
    {USB_SETUP_SET_SEL,                 "SET SEL"},
    {USB_SETUP_SET_ISOCH_DELAY,         "SET ISOCH DELAY"},
    {0, NULL}
};
static value_string_ext setup_request_names_vals_ext = VALUE_STRING_EXT_INIT(setup_request_names_vals);


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
    {RQT_SETUP_RECIPIENT_ENDPOINT,  "Endpoint" },
    {RQT_SETUP_RECIPIENT_OTHER,     "Other" },
    {0, NULL }
};

/* Dissector used for standard usb setup requests */
static int
dissect_usb_standard_setup_request(packet_info *pinfo, proto_tree *tree ,
                                   tvbuff_t *tvb, usb_conv_info_t  *usb_conv_info,
                                   usb_trans_info_t *usb_trans_info)
{
    gint offset = 0;
    const usb_setup_dissector_table_t *tmp;
    usb_setup_dissector dissector;

    proto_tree_add_item(tree, hf_usb_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s Request",
            val_to_str_ext(usb_trans_info->setup.request, &setup_request_names_vals_ext, "Unknown type %x"));

    dissector = NULL;
    for(tmp = setup_request_dissectors;tmp->dissector;tmp++) {
        if (tmp->request == usb_trans_info->setup.request) {
            dissector = tmp->dissector;
            break;
        }
    }

    if (!dissector) {
            dissector = &dissect_usb_setup_generic;
    }

    offset = dissector(pinfo, tree, tvb, offset, usb_conv_info);

    return offset;

}

/* Dissector used for standard usb setup responses */
static int
dissect_usb_standard_setup_response(packet_info *pinfo, proto_tree *tree,
                                    tvbuff_t *tvb, int offset,
                                    usb_conv_info_t  *usb_conv_info)
{
    const usb_setup_dissector_table_t *tmp;
    usb_setup_dissector dissector;
    gint length_remaining;


    col_add_fstr(pinfo->cinfo, COL_INFO, "%s Response",
        val_to_str_ext(usb_conv_info->usb_trans_info->setup.request,
            &setup_request_names_vals_ext, "Unknown type %x"));

    dissector = NULL;
    for(tmp = setup_response_dissectors;tmp->dissector;tmp++) {
        if (tmp->request == usb_conv_info->usb_trans_info->setup.request) {
            dissector = tmp->dissector;
            break;
        }
    }

    length_remaining = tvb_reported_length_remaining(tvb, offset);

    if (length_remaining <= 0)
        return offset;

    if (dissector) {
        offset = dissector(pinfo, tree, tvb, offset, usb_conv_info);
    } else {
        proto_tree_add_item(tree, hf_usb_control_response_generic,
                            tvb, offset, length_remaining, ENC_NA);
        offset += length_remaining;
    }

    return offset;
}


static void
usb_tap_queue_packet(packet_info *pinfo, guint8 urb_type,
                     usb_conv_info_t *usb_conv_info)
{
    usb_tap_data_t *tap_data;

    tap_data                = wmem_new(pinfo->pool, usb_tap_data_t);
    tap_data->urb_type      = urb_type;
    tap_data->transfer_type = (guint8)(usb_conv_info->transfer_type);
    tap_data->conv_info     = usb_conv_info;
    tap_data->trans_info    = usb_conv_info->usb_trans_info;

    tap_queue_packet(usb_tap, pinfo, tap_data);
}


static gboolean
is_usb_standard_setup_request(usb_trans_info_t *usb_trans_info)
{
    guint8 type, recip;

    type = USB_TYPE(usb_trans_info->setup.requesttype);
    recip = USB_RECIPIENT(usb_trans_info->setup.requesttype);

    if (type != RQT_SETUP_TYPE_STANDARD)
        return FALSE;

    /* the USB standards defines the GET_DESCRIPTOR request only as a
       request to a device
       if it's not aimed at a device, it's a non-standard request that
       should be handled by a class-specific dissector */
    if (usb_trans_info->setup.request == USB_SETUP_GET_DESCRIPTOR &&
            recip != RQT_SETUP_RECIPIENT_DEVICE) {
        return FALSE;
    }

    return TRUE;
}


static gint
try_dissect_next_protocol(proto_tree *tree, tvbuff_t *next_tvb, packet_info *pinfo,
        usb_conv_info_t *usb_conv_info, guint8 urb_type, proto_tree *urb_tree,
        proto_tree *setup_tree)
{
    int                      ret;
    wmem_tree_key_t          key[4];
    guint32                  k_frame_number;
    guint32                  k_device_address;
    guint32                  k_bus_id;
    usb_trans_info_t        *usb_trans_info;
    heur_dtbl_entry_t       *hdtbl_entry;
    heur_dissector_list_t    heur_subdissector_list = NULL;
    dissector_table_t        usb_dissector_table = NULL;
    proto_item              *sub_item;
    device_product_data_t   *device_product_data;
    device_protocol_data_t  *device_protocol_data;
    guint8                   ctrl_recip;
    /* if we select the next dissector based on a class,
       this is the (device or interface) class we're using */
    guint32                  usb_class;
    guint8                   transfer_type;
    gboolean                 use_setup_tree = FALSE;

    if (!usb_conv_info) {
        /*
         * Not enough information to choose the next protocol.
         * XXX - is there something we can still do here?
         */
        if (tvb_reported_length(next_tvb) > 0)
            call_data_dissector(next_tvb, pinfo, tree);

        return tvb_captured_length(next_tvb);
    }

    /* try dissect by "usb.device" */
    ret = dissector_try_uint_new(device_to_dissector,
            (guint32)(usb_conv_info->bus_id<<16 | usb_conv_info->device_address),
            next_tvb, pinfo, tree, TRUE, usb_conv_info);
    if (ret)
        return tvb_captured_length(next_tvb);

    k_frame_number = pinfo->num;
    k_device_address = usb_conv_info->device_address;
    k_bus_id = usb_conv_info->bus_id;

    key[0].length = 1;
    key[0].key    = &k_device_address;
    key[1].length = 1;
    key[1].key    = &k_bus_id;
    key[2].length = 1;
    key[2].key    = &k_frame_number;
    key[3].length = 0;
    key[3].key    = NULL;

    /* try dissect by "usb.protocol" */
    device_protocol_data = (device_protocol_data_t *)wmem_tree_lookup32_array_le(device_to_protocol_table, key);

    if (device_protocol_data &&
            device_protocol_data->bus_id == usb_conv_info->bus_id &&
            device_protocol_data->device_address == usb_conv_info->device_address) {
                ret = dissector_try_uint_new(protocol_to_dissector,
                        (guint32)device_protocol_data->protocol,
                        next_tvb, pinfo, tree, TRUE, usb_conv_info);
                if (ret)
                    return tvb_captured_length(next_tvb);
    }

    device_product_data = (device_product_data_t *)wmem_tree_lookup32_array_le(device_to_product_table, key);

    if (device_product_data && device_product_data->bus_id == usb_conv_info->bus_id &&
            device_product_data->device_address == usb_conv_info->device_address) {
                ret = dissector_try_uint_new(product_to_dissector,
                        (guint32)(device_product_data->vendor<<16 | device_product_data->product),
                        next_tvb, pinfo, tree, TRUE, usb_conv_info);
                if (ret)
                    return tvb_captured_length(next_tvb);
    }

    transfer_type = usb_conv_info->transfer_type;
    if (transfer_type == URB_UNKNOWN)
        transfer_type = usb_conv_info->descriptor_transfer_type;

    switch(transfer_type) {
        case URB_BULK:
            heur_subdissector_list = heur_bulk_subdissector_list;
            usb_dissector_table = usb_bulk_dissector_table;
            break;

        case URB_INTERRUPT:
            heur_subdissector_list = heur_interrupt_subdissector_list;
            usb_dissector_table = usb_interrupt_dissector_table;
            break;

        case URB_CONTROL:
            usb_trans_info = usb_conv_info->usb_trans_info;
            if (!usb_trans_info)
                break;

            /* for standard control requests and responses, there's no
               need to query dissector tables */
            if (is_usb_standard_setup_request(usb_trans_info))
                break;

            /* When dissecting requests, and Setup Data tree is created,
               pass it to next dissector instead of parent. */
            if (usb_conv_info->is_request && setup_tree)
                use_setup_tree = TRUE;

            ctrl_recip = USB_RECIPIENT(usb_trans_info->setup.requesttype);

            if (ctrl_recip == RQT_SETUP_RECIPIENT_INTERFACE) {
                guint8 interface_num = usb_trans_info->setup.wIndex & 0xff;

                heur_subdissector_list = heur_control_subdissector_list;
                usb_dissector_table = usb_control_dissector_table;

                usb_conv_info = get_usb_iface_conv_info(pinfo, interface_num);
                usb_conv_info->usb_trans_info = usb_trans_info;
            }
            else if (ctrl_recip == RQT_SETUP_RECIPIENT_ENDPOINT) {
                address               endpoint_addr;
                gint                  endpoint;
                guint32               src_endpoint, dst_endpoint;
                conversation_t       *conversation;

                heur_subdissector_list = heur_control_subdissector_list;
                usb_dissector_table = usb_control_dissector_table;

                endpoint = usb_trans_info->setup.wIndex & 0x0f;

                if (usb_conv_info->is_request) {
                    usb_address_t *dst_addr = wmem_new0(pinfo->pool, usb_address_t);
                    dst_addr->bus_id = usb_conv_info->bus_id;
                    dst_addr->device = usb_conv_info->device_address;
                    dst_addr->endpoint = dst_endpoint = GUINT32_TO_LE(endpoint);
                    set_address(&endpoint_addr, usb_address_type, USB_ADDR_LEN, (char *)dst_addr);

                    conversation = get_usb_conversation(pinfo, &pinfo->src, &endpoint_addr, pinfo->srcport, dst_endpoint);
                }
                else {
                    usb_address_t *src_addr = wmem_new0(pinfo->pool, usb_address_t);
                    src_addr->bus_id = usb_conv_info->bus_id;
                    src_addr->device = usb_conv_info->device_address;
                    src_addr->endpoint = src_endpoint = GUINT32_TO_LE(endpoint);
                    set_address(&endpoint_addr, usb_address_type, USB_ADDR_LEN, (char *)src_addr);

                    conversation  = get_usb_conversation(pinfo, &endpoint_addr, &pinfo->dst, src_endpoint, pinfo->destport);
                }

                usb_conv_info = get_usb_conv_info(conversation);
                usb_conv_info->usb_trans_info = usb_trans_info;
            }
            else {
                /* the recipient is "device" or "other" or "reserved"
                   there's no way for us to determine the interfaceClass
                   we set the usb_dissector_table anyhow as some
                   dissectors register for control messages to
                   IF_CLASS_UNKNOWN (this should be fixed) */
                heur_subdissector_list = heur_control_subdissector_list;
                usb_dissector_table = usb_control_dissector_table;
            }

            usb_tap_queue_packet(pinfo, urb_type, usb_conv_info);
            sub_item = proto_tree_add_uint(urb_tree, hf_usb_bInterfaceClass, next_tvb, 0, 0, usb_conv_info->interfaceClass);
            proto_item_set_generated(sub_item);
            break;

        default:
            break;
    }

    if (try_heuristics && heur_subdissector_list) {
        ret = dissector_try_heuristic(heur_subdissector_list,
                next_tvb, pinfo, use_setup_tree ? setup_tree : tree, &hdtbl_entry, usb_conv_info);
        if (ret)
            return tvb_captured_length(next_tvb);
    }

    if (usb_dissector_table) {
        /* we prefer the interface class unless it says we should refer
           to the device class
           XXX - use the device class if the interface class is unknown */
        if (usb_conv_info->interfaceClass == IF_CLASS_DEVICE) {
            usb_class = (usb_conv_info->device_protocol>>16) & 0xFF;
        }
        else {
            usb_class = usb_conv_info->interfaceClass;
        }

        ret = dissector_try_uint_new(usb_dissector_table, usb_class,
                next_tvb, pinfo, use_setup_tree ? setup_tree : tree, TRUE, usb_conv_info);
        if (ret)
            return tvb_captured_length(next_tvb);
    }

    return 0;
}


static int
dissect_usb_setup_response(packet_info *pinfo, proto_tree *tree,
                           tvbuff_t *tvb, int offset,
                           guint8 urb_type, usb_conv_info_t *usb_conv_info)
{
    proto_tree *parent;
    tvbuff_t   *next_tvb = NULL;
    gint        length_remaining;

    parent = proto_tree_get_parent_tree(tree);

    if (usb_conv_info) {
        if (usb_conv_info->usb_trans_info && is_usb_standard_setup_request(usb_conv_info->usb_trans_info)) {
            offset = dissect_usb_standard_setup_response(pinfo, parent, tvb, offset, usb_conv_info);
        }
        else {
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            offset += try_dissect_next_protocol(parent, next_tvb, pinfo, usb_conv_info, urb_type, tree, NULL);

            length_remaining = tvb_reported_length_remaining(tvb, offset);
            if (length_remaining > 0) {
                proto_tree_add_item(parent, hf_usb_control_response_generic,
                        tvb, offset, length_remaining, ENC_NA);
                offset += length_remaining;
            }
        }
    }
    else {
        /* no matching request available */
        length_remaining = tvb_reported_length_remaining(tvb, offset);
        if (length_remaining > 0) {
            proto_tree_add_item(parent, hf_usb_control_response_generic, tvb,
                    offset, length_remaining, ENC_NA);
            offset += length_remaining;
        }
    }

    return offset;
}


static int
dissect_usb_bmrequesttype(proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 *byte)
{
    guint64 val;

    static int * const bmRequestType_bits[] = {
        &hf_usb_bmRequestType_direction,
        &hf_usb_bmRequestType_type,
        &hf_usb_bmRequestType_recipient,
        NULL
    };

    proto_tree_add_bitmask_with_flags_ret_uint64(parent_tree, tvb, offset, hf_usb_bmRequestType, ett_usb_setup_bmrequesttype,
                                                 bmRequestType_bits, ENC_LITTLE_ENDIAN, BMT_NO_APPEND, &val);
    *byte = (guint8) val;

    return ++offset;
}

int
dissect_urb_transfer_flags(tvbuff_t *tvb, int offset, proto_tree* tree, int hf, int endian)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf, ett_transfer_flags, transfer_flags_fields, endian);
    return 4;
}

static int
dissect_linux_usb_pseudo_header_ext(tvbuff_t *tvb, int offset,
                                    packet_info *pinfo _U_,
                                    proto_tree *tree)
{
    proto_tree_add_item(tree, hf_usb_urb_interval, tvb, offset, 4, ENC_HOST_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_usb_urb_start_frame, tvb, offset, 4, ENC_HOST_ENDIAN);
    offset += 4;
    dissect_urb_transfer_flags(tvb, offset, tree, hf_usb_urb_copy_of_transfer_flags, ENC_HOST_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_usb_iso_numdesc, tvb, offset, 4, ENC_HOST_ENDIAN);
    offset += 4;

    return offset;
}


/* Dissector used for usb setup requests */
static int
dissect_usb_setup_request(packet_info *pinfo, proto_tree *tree,
                          tvbuff_t *tvb, int offset,
                          guint8 urb_type, usb_conv_info_t *usb_conv_info,
                          usb_header_t header_type, guint64 usb_id)
{
    gint              setup_offset;
    gint              req_type;
    gint              ret;
    proto_tree       *parent, *setup_tree;
    usb_trans_info_t *usb_trans_info, trans_info;
    tvbuff_t         *next_tvb, *data_tvb = NULL;
    guint8            bm_request_type;

    /* we should do the NULL check in all non-static functions */
    if (usb_conv_info)
        usb_trans_info = usb_conv_info->usb_trans_info;
    else
        usb_trans_info = &trans_info;

    parent = proto_tree_get_parent_tree(tree);

    setup_tree = proto_tree_add_subtree(parent, tvb, offset, 8, ett_usb_setup_hdr, NULL, "Setup Data");

    req_type = USB_TYPE(tvb_get_guint8(tvb, offset));
    usb_trans_info->setup.requesttype = tvb_get_guint8(tvb, offset);
    if (usb_conv_info) {
        usb_conv_info->setup_requesttype = tvb_get_guint8(tvb, offset);
        if (req_type != RQT_SETUP_TYPE_CLASS)
            usb_tap_queue_packet(pinfo, urb_type, usb_conv_info);
    }

    offset = dissect_usb_bmrequesttype(setup_tree, tvb, offset, &bm_request_type);

    /* as we're going through the data, we build a next_tvb that
       contains the the setup packet without the request type
       and request-specific data
       all subsequent dissection routines work on this tvb */

    setup_offset = offset;
    usb_trans_info->setup.request = tvb_get_guint8(tvb, offset);
    offset++;
    usb_trans_info->setup.wValue  = tvb_get_letohs(tvb, offset);
    offset += 2;
    usb_trans_info->setup.wIndex  = tvb_get_letohs(tvb, offset);
    offset += 2;
    usb_trans_info->setup.wLength = tvb_get_letohs(tvb, offset);
    offset += 2;

    if (header_type == USB_HEADER_LINUX_64_BYTES) {
        offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);
    } else if (header_type == USB_HEADER_USBPCAP) {
        if ((bm_request_type & 0x80) == 0 &&
            usb_trans_info->setup.wLength > 0 &&
            tvb_reported_length_remaining(tvb, offset) == 0) {
            /* UPBPcap older than 1.5.0.0 packet, save setup data
               and do not call subdissector */
            if (!PINFO_FD_VISITED(pinfo)) {
                wmem_tree_key_t key[3];
                usbpcap_setup_data_t *setup_data = wmem_new(wmem_file_scope(), usbpcap_setup_data_t);
                setup_data->usb_id = usb_id;
                tvb_memcpy(tvb, setup_data->setup_data, setup_offset-1, 8);
                key[0].length = 2;
                key[0].key = (guint32 *)&usb_id;
                key[1].length = 1;
                key[1].key = &pinfo->num;
                key[2].length = 0;
                key[2].key = NULL;
                wmem_tree_insert32_array(usbpcap_setup_data, key, setup_data);
            }
            proto_tree_add_item(setup_tree, hf_usb_request_unknown_class, tvb, setup_offset, 1, ENC_LITTLE_ENDIAN);
            dissect_usb_setup_generic(pinfo, setup_tree, tvb, setup_offset+1, usb_conv_info);
            return offset;
        }
    }


    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        next_tvb = tvb_new_composite();
        tvb_composite_append(next_tvb, tvb_new_subset_length_caplen(tvb, setup_offset, 7, 7));

        data_tvb = tvb_new_subset_remaining(tvb, offset);
        tvb_composite_append(next_tvb, data_tvb);
        offset += tvb_captured_length(data_tvb);
        tvb_composite_finalize(next_tvb);
        next_tvb = tvb_new_child_real_data(tvb,
                (const guint8 *) tvb_memdup(pinfo->pool, next_tvb, 0, tvb_captured_length(next_tvb)),
                tvb_captured_length(next_tvb),
                tvb_captured_length(next_tvb));
        add_new_data_source(pinfo, next_tvb, "USB Control");
    } else {
        next_tvb = tvb_new_subset_length_caplen(tvb, setup_offset, 7, 7);
    }

    /* at this point, offset contains the number of bytes that we
       dissected */

    if (is_usb_standard_setup_request(usb_trans_info)) {
        /* there's no point in checking the return value as there's no
           fallback for standard setup requests */
        dissect_usb_standard_setup_request(pinfo, setup_tree,
                next_tvb, usb_conv_info, usb_trans_info);
    }
    else {
        /* no standard request - pass it on to class-specific dissectors */
        ret = try_dissect_next_protocol(
                parent, next_tvb, pinfo, usb_conv_info, urb_type, tree, setup_tree);
        if (ret <= 0) {
            /* no class-specific dissector could handle it,
               dissect it as generic setup request */
            proto_tree_add_item(setup_tree, hf_usb_request_unknown_class,
                    next_tvb, 0, 1, ENC_LITTLE_ENDIAN);
            dissect_usb_setup_generic(pinfo, setup_tree,
                    next_tvb, 1, usb_conv_info);
        }
        /* at this point, non-standard request has been dissectored */
    }

    if (data_tvb)
        proto_tree_add_item(setup_tree, hf_usb_data_fragment, data_tvb, 0, -1, ENC_NA);

    return offset;
}


/* dissect the linux-specific USB pseudo header and fill the conversation struct
   return the number of dissected bytes */
static gint
dissect_linux_usb_pseudo_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        usb_conv_info_t *usb_conv_info, guint64 *urb_id)
{
    guint8  transfer_type;
    guint8  endpoint_byte;
    guint8  transfer_type_and_direction;
    guint8  urb_type;
    guint8  flag[2];
    guint32 bus_id;

    *urb_id = tvb_get_guint64(tvb, 0, ENC_HOST_ENDIAN);
    proto_tree_add_uint64(tree, hf_usb_urb_id, tvb, 0, 8, *urb_id);

    /* show the urb type of this URB as string and as a character */
    urb_type = tvb_get_guint8(tvb, 8);
    usb_conv_info->is_request = (urb_type==URB_SUBMIT);
    proto_tree_add_uint(tree, hf_usb_linux_urb_type, tvb, 8, 1, urb_type);
    proto_tree_add_item(tree, hf_usb_linux_transfer_type, tvb, 9, 1, ENC_LITTLE_ENDIAN);

    transfer_type = tvb_get_guint8(tvb, 9);
    usb_conv_info->transfer_type = transfer_type;

    endpoint_byte = tvb_get_guint8(tvb, 10);   /* direction bit | endpoint */
    usb_conv_info->endpoint = endpoint_byte & 0x7F;
    if (endpoint_byte & URB_TRANSFER_IN)
        usb_conv_info->direction = P2P_DIR_RECV;
    else
        usb_conv_info->direction = P2P_DIR_SENT;

    transfer_type_and_direction = (transfer_type & 0x7F) | (endpoint_byte & 0x80);
    col_append_str(pinfo->cinfo, COL_INFO,
                    val_to_str(transfer_type_and_direction, usb_transfer_type_and_direction_vals, "Unknown type %x"));

    proto_tree_add_bitmask(tree, tvb, 10, hf_usb_endpoint_address, ett_usb_endpoint, usb_endpoint_fields, ENC_NA);
    proto_tree_add_item(tree, hf_usb_device_address, tvb, 11, 1, ENC_LITTLE_ENDIAN);
    usb_conv_info->device_address = (guint16)tvb_get_guint8(tvb, 11);

    proto_tree_add_item_ret_uint(tree, hf_usb_bus_id, tvb, 12, 2, ENC_HOST_ENDIAN, &bus_id);
    usb_conv_info->bus_id = (guint16) bus_id;

    /* Right after the pseudo header we always have
     * sizeof(struct usb_device_setup_hdr) bytes. The content of these
     * bytes only have meaning in case setup_flag == 0.
     */
    flag[0] = tvb_get_guint8(tvb, 14);
    flag[1] = '\0';
    if (flag[0] == 0) {
        usb_conv_info->is_setup = TRUE;
        proto_tree_add_string(tree, hf_usb_setup_flag, tvb, 14, 1, "relevant (0)");
        if (usb_conv_info->transfer_type!=URB_CONTROL)
            proto_tree_add_expert(tree, pinfo, &ei_usb_invalid_setup, tvb, 14, 1);
    } else {
        usb_conv_info->is_setup = FALSE;
        proto_tree_add_string_format_value(tree, hf_usb_setup_flag, tvb,
            14, 1, flag, "not relevant ('%c')", g_ascii_isprint(flag[0]) ? flag[0]: '.');
    }

    flag[0] = tvb_get_guint8(tvb, 15);
    flag[1] = '\0';
    if (flag[0] == 0) {
        proto_tree_add_string(tree, hf_usb_data_flag, tvb, 15, 1, "present (0)");
    } else {
        proto_tree_add_string_format_value(tree, hf_usb_data_flag, tvb,
            15, 1, flag, "not present ('%c')", g_ascii_isprint(flag[0]) ? flag[0] : '.');
    }

    proto_tree_add_item(tree, hf_usb_urb_ts_sec, tvb, 16, 8, ENC_HOST_ENDIAN);
    proto_tree_add_item(tree, hf_usb_urb_ts_usec, tvb, 24, 4, ENC_HOST_ENDIAN);
    proto_tree_add_item(tree, hf_usb_urb_status, tvb, 28, 4, ENC_HOST_ENDIAN);
    proto_tree_add_item(tree, hf_usb_urb_len, tvb, 32, 4, ENC_HOST_ENDIAN);
    proto_tree_add_item(tree, hf_usb_urb_data_len, tvb, 36, 4, ENC_HOST_ENDIAN);

    return 40;
}

/* dissect the usbpcap_buffer_packet_header and fill the conversation struct
   this function does not handle the transfer-specific headers
   return the number of bytes processed */
static gint
dissect_usbpcap_buffer_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        usb_conv_info_t *usb_conv_info, guint32 *win32_data_len, guint64 *irp_id)
{
    proto_item *item;
    guint32  function_code;
    guint8   transfer_type;
    guint8   endpoint_byte;
    guint8   transfer_type_and_direction;
    guint8   tmp_val8;

    proto_tree_add_item(tree, hf_usb_win32_header_len, tvb, 0, 2, ENC_LITTLE_ENDIAN);
    *irp_id = tvb_get_guint64(tvb, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_uint64(tree, hf_usb_irp_id, tvb, 2, 8, *irp_id);
    proto_tree_add_item(tree, hf_usb_usbd_status, tvb, 10, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_usb_function, tvb, 14, 2, ENC_LITTLE_ENDIAN, &function_code);

    proto_tree_add_bitmask(tree, tvb, 16, hf_usb_info, ett_usb_usbpcap_info, usb_usbpcap_info_fields, ENC_LITTLE_ENDIAN);
    tmp_val8 = tvb_get_guint8(tvb, 16);
    /* TODO: Handle errors */
    if (tmp_val8 & 0x01) {
        usb_conv_info->is_request = FALSE;
    } else {
        usb_conv_info->is_request = TRUE;
    }

    proto_tree_add_item(tree, hf_usb_bus_id, tvb, 17, 2, ENC_LITTLE_ENDIAN);
    usb_conv_info->bus_id = tvb_get_letohs(tvb, 17);

    proto_tree_add_item(tree, hf_usb_win32_device_address, tvb, 19, 2, ENC_LITTLE_ENDIAN);
    usb_conv_info->device_address = tvb_get_letohs(tvb, 19);

    endpoint_byte = tvb_get_guint8(tvb, 21);
    usb_conv_info->direction = endpoint_byte&URB_TRANSFER_IN ?  P2P_DIR_RECV : P2P_DIR_SENT;
    usb_conv_info->endpoint = endpoint_byte&0x7F;
    proto_tree_add_bitmask(tree, tvb, 21, hf_usb_endpoint_address, ett_usb_endpoint, usb_endpoint_fields, ENC_LITTLE_ENDIAN);

    transfer_type = tvb_get_guint8(tvb, 22);
    usb_conv_info->transfer_type = transfer_type;
    item = proto_tree_add_item(tree, hf_usb_win32_transfer_type, tvb, 22, 1, ENC_LITTLE_ENDIAN);
    if (transfer_type == URB_UNKNOWN) {
        expert_add_info(pinfo, item, &ei_usb_usbpcap_unknown_urb);
    }

    /* Workaround bug in captures created with USBPcap earlier than 1.3.0.0 */
    if ((endpoint_byte == 0x00) && (transfer_type == URB_CONTROL) && (tvb_get_guint8(tvb, 27) == USB_CONTROL_STAGE_DATA)) {
        usb_conv_info->is_request = TRUE;
    }

    if (transfer_type != USBPCAP_URB_IRP_INFO) {
        transfer_type_and_direction = (transfer_type & 0x7F) | (endpoint_byte & 0x80);
        col_append_str(pinfo->cinfo, COL_INFO,
            val_to_str(transfer_type_and_direction, usb_transfer_type_and_direction_vals, "Unknown type %x"));
    } else {
        col_append_str(pinfo->cinfo, COL_INFO,
            val_to_str_ext(function_code, &win32_urb_function_vals_ext, "Unknown function %x"));
    }

    *win32_data_len = tvb_get_letohl(tvb, 23);
    proto_tree_add_item(tree, hf_usb_win32_data_len, tvb, 23, 4, ENC_LITTLE_ENDIAN);

    /* by default, we assume it's no setup packet
       the correct values will be set when we parse the control header */
    usb_conv_info->is_setup = FALSE;
    usb_conv_info->setup_requesttype = 0;

    /* we don't handle the transfer-specific headers here */
    return 27;
}


static gint
dissect_darwin_buffer_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        usb_conv_info_t *usb_conv_info, guint64 *id)
{
    guint8   transfer_type;
    guint8   request_type;
    guint8   endpoint_byte;
    guint8   transfer_type_and_direction;
    guint8   header_length;

    proto_tree_add_item(tree, hf_usb_darwin_bcd_version, tvb, 0, 2, ENC_LITTLE_ENDIAN);

    header_length = tvb_get_guint8(tvb, 2);
    proto_tree_add_item(tree, hf_usb_darwin_header_len, tvb, 2, 1, ENC_LITTLE_ENDIAN);

    request_type = tvb_get_guint8(tvb, 3);
    usb_conv_info->is_request = (request_type == DARWIN_IO_SUBMIT);
    proto_tree_add_uint(tree, hf_usb_darwin_request_type, tvb, 3, 1, request_type);

    proto_tree_add_item(tree, hf_usb_darwin_io_len, tvb, 4, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(tree, hf_usb_darwin_io_status, tvb, 8, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(tree, hf_usb_darwin_iso_num_packets, tvb, 12, 4, ENC_LITTLE_ENDIAN);

    *id = tvb_get_guint64(tvb, 16, ENC_LITTLE_ENDIAN);
    proto_tree_add_uint64(tree, hf_usb_darwin_io_id, tvb, 16, 8, *id);

    proto_tree_add_item(tree, hf_usb_darwin_device_location, tvb, 24, 4, ENC_LITTLE_ENDIAN);
    usb_conv_info->bus_id = tvb_get_letohl(tvb, 24) >> 24;

    proto_tree_add_item(tree, hf_usb_darwin_speed, tvb, 28, 1, ENC_LITTLE_ENDIAN);

    usb_conv_info->device_address = (guint16)tvb_get_guint8(tvb, 29);
    proto_tree_add_uint(tree, hf_usb_darwin_device_address, tvb, 29, 1, usb_conv_info->device_address);

    endpoint_byte = tvb_get_guint8(tvb, 30);   /* direction bit | endpoint */
    usb_conv_info->endpoint = endpoint_byte & 0x7F;
    if (endpoint_byte & URB_TRANSFER_IN) {
        usb_conv_info->direction = P2P_DIR_RECV;
    }
    else {
        usb_conv_info->direction = P2P_DIR_SENT;
    }
    proto_tree_add_uint(tree, hf_usb_darwin_endpoint_address, tvb, 30, 1, endpoint_byte);
    proto_tree_add_bitmask(tree, tvb, 30, hf_usb_endpoint_number, ett_usb_endpoint, usb_endpoint_fields, ENC_LITTLE_ENDIAN);

    transfer_type = MIN(tvb_get_guint8(tvb, 31), G_N_ELEMENTS(darwin_endpoint_to_linux) - 1);
    usb_conv_info->transfer_type = darwin_endpoint_to_linux[transfer_type];
    proto_tree_add_uint(tree, hf_usb_darwin_endpoint_type, tvb, 31, 1, transfer_type);

    transfer_type_and_direction = (darwin_endpoint_to_linux[transfer_type] & 0x7F) | (endpoint_byte & 0x80);
    col_append_str(pinfo->cinfo, COL_INFO,
                   val_to_str(transfer_type_and_direction, usb_transfer_type_and_direction_vals, "Unknown type %x"));
    col_append_str(pinfo->cinfo, COL_INFO, usb_conv_info->is_request == TRUE ? " (submitted)" : " (completed)");

    usb_conv_info->is_setup = FALSE;
    if ((usb_conv_info->is_request == TRUE) && (usb_conv_info->transfer_type == URB_CONTROL)) {
        usb_conv_info->is_setup = TRUE;
    }

    usb_conv_info->setup_requesttype = 0;

    /* we don't handle the transfer-specific headers here */
    return header_length;
}

/* Set the usb_address_t fields based on the direction of the urb */
static void
usb_set_addr(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint16 bus_id, guint16 device_address,
             int endpoint, gboolean req)
{
    proto_item     *sub_item;
    usb_address_t  *src_addr = wmem_new0(pinfo->pool, usb_address_t),
                   *dst_addr = wmem_new0(pinfo->pool, usb_address_t);
    guint8         *str_src_addr;
    guint8         *str_dst_addr;

    if (req) {
        /* request */
        src_addr->device   = 0xffffffff;
        src_addr->endpoint = NO_ENDPOINT;
        dst_addr->device   = GUINT16_TO_LE(device_address);
        dst_addr->endpoint = GUINT32_TO_LE(endpoint);
    } else {
        /* response */
        src_addr->device   = GUINT16_TO_LE(device_address);
        src_addr->endpoint = GUINT32_TO_LE(endpoint);
        dst_addr->device   = 0xffffffff;
        dst_addr->endpoint = NO_ENDPOINT;
    }
    src_addr->bus_id = GUINT16_TO_LE(bus_id);
    dst_addr->bus_id = GUINT16_TO_LE(bus_id);

    set_address(&pinfo->net_src, usb_address_type, USB_ADDR_LEN, (char *)src_addr);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);
    set_address(&pinfo->net_dst, usb_address_type, USB_ADDR_LEN, (char *)dst_addr);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

    pinfo->ptype = PT_USB;
    pinfo->srcport = src_addr->endpoint;
    pinfo->destport = dst_addr->endpoint;
    /* sent/received is from the perspective of the USB host */
    pinfo->p2p_dir = req ? P2P_DIR_SENT : P2P_DIR_RECV;

    str_src_addr = address_to_str(pinfo->pool, &pinfo->src);
    str_dst_addr = address_to_str(pinfo->pool, &pinfo->dst);

    sub_item = proto_tree_add_string(tree, hf_usb_src, tvb, 0, 0, str_src_addr);
    proto_item_set_generated(sub_item);

    sub_item = proto_tree_add_string(tree, hf_usb_addr, tvb, 0, 0, str_src_addr);
    proto_item_set_hidden(sub_item);

    sub_item = proto_tree_add_string(tree, hf_usb_dst, tvb, 0, 0, str_dst_addr);
    proto_item_set_generated(sub_item);

    sub_item = proto_tree_add_string(tree, hf_usb_addr, tvb, 0, 0, str_dst_addr);
    proto_item_set_hidden(sub_item);
}


/* Gets the transfer info for a given packet
 * Generates transfer info if none exists yet
 * Also adds request/response info to the tree for the given packet */
static usb_trans_info_t
*usb_get_trans_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    usb_header_t header_type, usb_conv_info_t *usb_conv_info, guint64 usb_id)
{
    usb_trans_info_t *usb_trans_info;
    proto_item       *ti;
    nstime_t          t, deltat;
    wmem_tree_key_t   key[3];

    /* request/response matching so we can keep track of transaction specific
     * data.
     */
    key[0].length = 2;
    key[0].key = (guint32 *)&usb_id;
    key[1].length = 1;
    key[1].key = &pinfo->num;
    key[2].length = 0;
    key[2].key = NULL;

    if (usb_conv_info->is_request) {
        /* this is a request */
        usb_trans_info = (usb_trans_info_t *)wmem_tree_lookup32_array(usb_conv_info->transactions, key);
        if (!usb_trans_info) {
            usb_trans_info              = wmem_new0(wmem_file_scope(), usb_trans_info_t);
            usb_trans_info->request_in  = pinfo->num;
            usb_trans_info->req_time    = pinfo->abs_ts;
            usb_trans_info->header_type = header_type;
            usb_trans_info->usb_id      = usb_id;

            wmem_tree_insert32_array(usb_conv_info->transactions, key, usb_trans_info);
        }

        if (usb_trans_info->response_in) {
            ti = proto_tree_add_uint(tree, hf_usb_response_in, tvb, 0, 0, usb_trans_info->response_in);
            proto_item_set_generated(ti);
        }

    } else {
        /* this is a response */
        if (pinfo->fd->visited) {
            usb_trans_info = (usb_trans_info_t *)wmem_tree_lookup32_array(usb_conv_info->transactions, key);

        } else {
            usb_trans_info = (usb_trans_info_t *)wmem_tree_lookup32_array_le(usb_conv_info->transactions, key);
            if (usb_trans_info) {
                if (usb_trans_info->usb_id == usb_id) {
                    if (usb_trans_info->response_in == 0) {
                        /* USBPcap generates 2 frames for response; store the first one */
                        usb_trans_info->response_in = pinfo->num;
                    }
                    wmem_tree_insert32_array(usb_conv_info->transactions, key, usb_trans_info);
                } else {
                    usb_trans_info = NULL;
                }
            }
        }

        if (usb_trans_info && usb_trans_info->request_in) {

            ti = proto_tree_add_uint(tree, hf_usb_request_in, tvb, 0, 0, usb_trans_info->request_in);
            proto_item_set_generated(ti);

            t = pinfo->abs_ts;
            nstime_delta(&deltat, &t, &usb_trans_info->req_time);
            ti = proto_tree_add_time(tree, hf_usb_time, tvb, 0, 0, &deltat);
            proto_item_set_generated(ti);
        }
    }

    return usb_trans_info;
}


/* dissect a group of isochronous packets inside an usb packet in
   usbpcap format */
#define MAX_ISO_PACKETS 100000 // Arbitrary
static gint
dissect_usbpcap_iso_packets(packet_info *pinfo _U_, proto_tree *urb_tree, guint8 urb_type,
        tvbuff_t *tvb, gint offset, guint32 win32_data_len, usb_conv_info_t *usb_conv_info)
{
    guint32     i;
    guint32     num_packets;
    int         data_start_offset;
    proto_item *num_packets_ti, *urb_tree_ti;

    proto_tree_add_item(urb_tree, hf_usb_win32_iso_start_frame, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    num_packets = tvb_get_letohl(tvb, offset);
    num_packets_ti = proto_tree_add_item(urb_tree, hf_usb_win32_iso_num_packets, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(urb_tree, hf_usb_win32_iso_error_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    if (num_packets > MAX_ISO_PACKETS) {
        expert_add_info_format(pinfo, num_packets_ti, &ei_usb_bad_length, "Too many isochronous transfer packets (%u)", num_packets);
        return tvb_captured_length(tvb);
    }

    data_start_offset = offset + 12 * num_packets;
    urb_tree_ti = proto_tree_get_parent(urb_tree);
    proto_item_set_len(urb_tree_ti, data_start_offset);

    for (i = 0; i < num_packets; i++) {
        guint32 this_offset;
        guint32 next_offset;
        guint32 iso_len;
        proto_item *iso_packet_ti, *ti;
        proto_tree *iso_packet_tree;

        iso_packet_ti = proto_tree_add_protocol_format(
                proto_tree_get_root(urb_tree), proto_usb,
                tvb, offset, 12, "USB isochronous packet");
        iso_packet_tree = proto_item_add_subtree(iso_packet_ti, ett_usb_win32_iso_packet);

        this_offset = tvb_get_letohl(tvb, offset);
        if (num_packets - i == 1) {
            /* this is the last packet */
            next_offset = win32_data_len;
        } else {
            /* there is next packet */
            next_offset = tvb_get_letohl(tvb, offset + 12);
        }

        if (next_offset > this_offset) {
            iso_len = next_offset - this_offset;
        } else {
            iso_len = 0;
        }

        /* If this packet does not contain isochrounous data, do not try to display it */
        if (!((usb_conv_info->is_request && usb_conv_info->direction==P2P_DIR_SENT) ||
                    (!usb_conv_info->is_request && usb_conv_info->direction==P2P_DIR_RECV))) {
            iso_len = 0;
        }

        proto_tree_add_item(iso_packet_tree, hf_usb_win32_iso_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        ti = proto_tree_add_item(iso_packet_tree, hf_usb_win32_iso_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        if (usb_conv_info->direction==P2P_DIR_SENT) {
            /* Isochronous OUT transfer */
            proto_item_append_text(ti, " (not used)");
        } else {
            /* Isochronous IN transfer.
             * Length field is being set by host controller.
             */
            if (usb_conv_info->is_request) {
                /* Length was not yet set */
                proto_item_append_text(ti, " (irrelevant)");
            } else {
                /* Length was set and (should be) valid */
                proto_item_append_text(ti, " (relevant)");
                iso_len = tvb_get_letohl(tvb, offset);
            }
        }
        offset += 4;

        ti = proto_tree_add_item(iso_packet_tree, hf_usb_win32_iso_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        if (urb_type == URB_SUBMIT) {
            proto_item_append_text(ti, " (irrelevant)");
        } else {
            proto_item_append_text(ti, " (relevant)");
        }
        offset += 4;

        if (iso_len && data_start_offset + this_offset + iso_len <= tvb_captured_length(tvb)) {
            proto_tree_add_item(iso_packet_tree, hf_usb_iso_data, tvb, (gint)(data_start_offset + this_offset), (gint)iso_len, ENC_NA);
            proto_tree_set_appendix(iso_packet_tree, tvb, (gint)(data_start_offset + this_offset), (gint)iso_len);
        }
    }

    if ((usb_conv_info->is_request && usb_conv_info->direction==P2P_DIR_SENT) ||
            (!usb_conv_info->is_request && usb_conv_info->direction==P2P_DIR_RECV)) {
        /* We have dissected all the isochronous data */
        offset += win32_data_len;
    }

    return offset;
}


static gint
dissect_linux_usb_iso_transfer(packet_info *pinfo _U_, proto_tree *urb_tree,
        usb_header_t header_type, tvbuff_t *tvb, gint offset,
        usb_conv_info_t *usb_conv_info)
{
    guint32     iso_numdesc = 0;
    proto_item *tii;
    guint32     i;
    guint       data_base;
    guint32     iso_status;
    guint32     iso_off = 0;
    guint32     iso_len = 0;

    tii = proto_tree_add_uint(urb_tree, hf_usb_bInterfaceClass, tvb, offset, 0, usb_conv_info->interfaceClass);
    proto_item_set_generated(tii);

    /* All fields which belong to Linux usbmon headers are in host-endian
     * byte order. The fields coming from the USB communication are in little
     * endian format (see usb_20.pdf, chapter 8.1 Byte/Bit ordering).
     *
     * When a capture file is transferred to a host with different endianness
     * than packet was captured then the necessary swapping happens in
     * wiretap/pcap-common.c, pcap_byteswap_linux_usb_pseudoheader().
     */

    /* iso urbs on linux can't possibly contain a setup packet
       see mon_bin_event() in the linux kernel */

    proto_tree_add_item(urb_tree, hf_usb_iso_error_count, tvb, offset, 4, ENC_HOST_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_uint(urb_tree, hf_usb_iso_numdesc, tvb, offset, 4, ENC_HOST_ENDIAN, &iso_numdesc);
    offset += 4;

    if (header_type == USB_HEADER_LINUX_64_BYTES) {
        offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, urb_tree);
    }

    data_base = offset + iso_numdesc*16;
    for (i = 0; i<iso_numdesc; i++) {
        proto_item   *iso_desc_ti;
        proto_tree   *iso_desc_tree;

        iso_desc_ti = proto_tree_add_protocol_format(urb_tree, proto_usb, tvb, offset,
                16, "USB isodesc %u", i);
        iso_desc_tree = proto_item_add_subtree(iso_desc_ti, ett_usb_isodesc);

        proto_tree_add_item_ret_int(iso_desc_tree, hf_usb_iso_status, tvb, offset, 4, ENC_HOST_ENDIAN, &iso_status);
        proto_item_append_text(iso_desc_ti, " [%s]", val_to_str_ext(iso_status, &linux_negative_errno_vals_ext, "Error %d"));
        offset += 4;

        proto_tree_add_item_ret_uint(iso_desc_tree, hf_usb_iso_off, tvb, offset, 4, ENC_HOST_ENDIAN, &iso_off);
        offset += 4;

        proto_tree_add_item_ret_uint(iso_desc_tree, hf_usb_iso_len, tvb, offset, 4, ENC_HOST_ENDIAN, &iso_len);
        if (iso_len != 0)
            proto_item_append_text(iso_desc_ti, " (%u bytes)", iso_len);
        offset += 4;

        /* Show the ISO data if we captured them and either the status
           is OK or the packet is sent from host to device.
           The Linux kernel sets the status field in outgoing isochronous
           URBs to -EXDEV and fills the data part with valid data.
         */
        if ((pinfo->p2p_dir==P2P_DIR_SENT || !iso_status) &&
                iso_len && data_base + iso_off + iso_len <= tvb_captured_length(tvb)) {
            proto_tree_add_item(iso_desc_tree, hf_usb_iso_data, tvb, data_base + iso_off, iso_len, ENC_NA);
            proto_tree_set_appendix(iso_desc_tree, tvb, (gint)(data_base+iso_off), (gint)iso_len);
        }

        proto_tree_add_item(iso_desc_tree, hf_usb_iso_pad, tvb, offset, 4, ENC_HOST_ENDIAN);
        offset += 4;
    }

    /* we jump to the end of the last iso data chunk
       this assumes that the iso data starts immediately after the
       iso descriptors
       we have to use the offsets from the last iso descriptor, we can't keep
       track of the offset ourselves as there may be gaps
       between data packets in the transfer buffer */
    return data_base+iso_off+iso_len;
}

static gint
dissect_usbip_iso_transfer(packet_info *pinfo _U_, proto_tree *urb_tree,
        tvbuff_t *tvb, gint offset, guint32 iso_numdesc, guint32 desc_offset,
        usb_conv_info_t *usb_conv_info)
{
    proto_item *tii;
    guint32     i;
    guint       data_base;
    guint32     iso_off = 0;
    guint32     iso_len = 0;

    tii = proto_tree_add_uint(urb_tree, hf_usb_bInterfaceClass, tvb, offset, 0, usb_conv_info->interfaceClass);
    proto_item_set_generated(tii);

    /* All fields which belong to usbip are in big-endian byte order.
     * unlike the linux kernel, the usb isoc descriptor is appended at
     * the end of the isoc data. We have to reassemble the pdus and jump
     * to the end (actual_length) and the remaining data is the isoc
     * descriptor.
     */

    data_base = offset;
    for (i = 0; i<iso_numdesc; i++) {
        proto_item   *iso_desc_ti;
        proto_tree   *iso_desc_tree;
        gint32        iso_status;

        iso_desc_ti = proto_tree_add_protocol_format(urb_tree, proto_usb, tvb, desc_offset,
                16, "USB isodesc %u", i);
        iso_desc_tree = proto_item_add_subtree(iso_desc_ti, ett_usb_isodesc);

        proto_tree_add_item_ret_uint(iso_desc_tree, hf_usb_iso_off, tvb, desc_offset, 4, ENC_BIG_ENDIAN, &iso_off);
        desc_offset += 4;

        proto_tree_add_item(iso_desc_tree, hf_usb_iso_len, tvb, desc_offset, 4, ENC_BIG_ENDIAN);
        desc_offset += 4;

        proto_tree_add_item_ret_uint(iso_desc_tree, hf_usb_iso_actual_len, tvb, desc_offset, 4, ENC_BIG_ENDIAN, &iso_len);
        desc_offset += 4;

        proto_tree_add_item_ret_int(iso_desc_tree, hf_usb_iso_status, tvb, desc_offset, 4, ENC_BIG_ENDIAN, &iso_status);
        proto_item_append_text(iso_desc_ti, " [%s]", val_to_str_ext(iso_status, &linux_negative_errno_vals_ext, "Error %d"));
        desc_offset += 4;

        if (iso_len > 0)
            proto_item_append_text(iso_desc_ti, " (%u bytes)", iso_len);

        /* Show the ISO data if we captured them and either the status
           is OK or the packet is sent from host to device.
           The Linux kernel sets the status field in outgoing isochronous
           URBs to -EXDEV and fills the data part with valid data.
         */
        if ((pinfo->p2p_dir==P2P_DIR_SENT || !iso_status) &&
                iso_len && data_base + iso_off + iso_len <= tvb_reported_length(tvb)) {
            proto_tree_add_item(iso_desc_tree, hf_usb_iso_data, tvb, (guint) data_base + iso_off, iso_len, ENC_NA);
            proto_tree_set_appendix(iso_desc_tree, tvb, (guint) data_base + iso_off, (gint)iso_len);
        }
    }
    return desc_offset;
}

static gint
dissect_darwin_usb_iso_transfer(packet_info *pinfo _U_, proto_tree *tree, usb_header_t header_type _U_,
                    guint8 urb_type _U_, tvbuff_t *tvb, gint32 offset, usb_conv_info_t *usb_conv_info)
{
    guint32     frame_length;
    guint32     frame_header_length;
    guint32     status;
    guint32     iso_tree_start;
    guint32     i;
    guint32     iso_numdesc;
    guint32     len;
    proto_item *tii;

    len  = (gint32)tvb_captured_length(tvb);
    len -= offset;

    tii = proto_tree_add_uint(tree, hf_usb_bInterfaceClass, tvb, offset, 0, usb_conv_info->interfaceClass);
    proto_item_set_generated(tii);

    status      = tvb_get_guint32(tvb, 8, ENC_LITTLE_ENDIAN);
    iso_numdesc = tvb_get_guint32(tvb, 12, ENC_LITTLE_ENDIAN);

    iso_tree_start = offset;
    for (i = 0; (i < iso_numdesc) && (len > 8 /* header len + frame len */); i++) {
        proto_item   *iso_desc_ti;
        proto_tree   *iso_desc_tree;

        /* Fetch ISO descriptor fields stored in little-endian byte order. */
        frame_header_length = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
        frame_length        = tvb_get_guint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);

        if ((len < frame_header_length) || (frame_header_length < 20)) {
            break;
        }

        iso_desc_ti = proto_tree_add_protocol_format(tree, proto_usb, tvb, offset,
                20, "Frame %u [%s]", i, val_to_str_ext(status, &usb_darwin_status_vals_ext, "Error %d"));

        iso_desc_tree = proto_item_add_subtree(iso_desc_ti, ett_usb_isodesc);

        proto_tree_add_item(iso_desc_tree, hf_usb_darwin_iso_frame_number, tvb, offset + 12, 8, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(iso_desc_tree, hf_usb_iso_len, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);

        if (usb_conv_info->is_request == FALSE) {
            proto_tree_add_item(iso_desc_tree, hf_usb_darwin_iso_timestamp, tvb, offset + 20, 8, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(iso_desc_tree, hf_usb_darwin_iso_status, tvb, offset + 8, 4, ENC_LITTLE_ENDIAN);

            /* Data */
            if (frame_length > len) {
                frame_length = len;
            }

            proto_tree_add_item(iso_desc_tree, hf_usb_iso_data, tvb, offset + frame_header_length, frame_length, ENC_NA);
            proto_tree_set_appendix(iso_desc_tree, tvb, (gint)iso_tree_start, (gint)(offset - iso_tree_start));

            len    -= frame_length;
            offset += frame_length;
        }

        /* Padding to align the next header */
        offset        += frame_header_length;
        offset         = WS_ROUNDUP_4(offset);
        iso_tree_start = offset;

        len -= frame_header_length;
    }

    return offset;
}

static gint
dissect_usb_payload(tvbuff_t *tvb, packet_info *pinfo,
                    proto_tree *parent, proto_tree *tree,
                    usb_conv_info_t *usb_conv_info, guint8 urb_type,
                    gint offset, guint16 device_address)
{
    wmem_tree_key_t          key[4];
    guint32                  k_frame_number;
    guint32                  k_device_address;
    guint32                  k_bus_id;
    device_product_data_t   *device_product_data = NULL;
    device_protocol_data_t  *device_protocol_data = NULL;
    tvbuff_t                *next_tvb = NULL;

    k_frame_number = pinfo->num;
    k_device_address = device_address;
    k_bus_id = usb_conv_info->bus_id;

    key[0].length = 1;
    key[0].key    = &k_device_address;
    key[1].length = 1;
    key[1].key    = &k_bus_id;
    key[2].length = 1;
    key[2].key    = &k_frame_number;
    key[3].length = 0;
    key[3].key    = NULL;

    device_product_data = (device_product_data_t *) wmem_tree_lookup32_array_le(device_to_product_table, key);
    if (device_product_data && device_product_data->bus_id == usb_conv_info->bus_id &&
            device_product_data->device_address == device_address) {
        p_add_proto_data(pinfo->pool, pinfo, proto_usb, USB_VENDOR_ID, GUINT_TO_POINTER((guint)device_product_data->vendor));
        p_add_proto_data(pinfo->pool, pinfo, proto_usb, USB_PRODUCT_ID, GUINT_TO_POINTER((guint)device_product_data->product));
        usb_conv_info->deviceVendor = device_product_data->vendor;
        usb_conv_info->deviceProduct = device_product_data->product;
        usb_conv_info->deviceVersion = device_product_data->device;
    }

    device_protocol_data = (device_protocol_data_t *) wmem_tree_lookup32_array_le(device_to_protocol_table, key);
    if (device_protocol_data && device_protocol_data->bus_id == usb_conv_info->bus_id &&
            device_protocol_data->device_address == device_address) {
        p_add_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_CLASS, GUINT_TO_POINTER(device_protocol_data->protocol >> 16));
        p_add_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_SUBCLASS, GUINT_TO_POINTER((device_protocol_data->protocol >> 8) & 0xFF));
        p_add_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_PROTOCOL, GUINT_TO_POINTER(device_protocol_data->protocol & 0xFF));
        usb_conv_info->device_protocol = device_protocol_data->protocol;
    }

    p_add_proto_data(pinfo->pool, pinfo, proto_usb, USB_BUS_ID, GUINT_TO_POINTER((guint)usb_conv_info->bus_id));
    p_add_proto_data(pinfo->pool, pinfo, proto_usb, USB_DEVICE_ADDRESS, GUINT_TO_POINTER((guint)device_address));

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        offset += try_dissect_next_protocol(parent, next_tvb, pinfo, usb_conv_info, urb_type, tree, NULL);
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        /* There is still leftover capture data to add (padding?) */
        proto_tree_add_item(parent, hf_usb_capdata, tvb, offset, -1, ENC_NA);
    }

    return offset;
}

static int
dissect_freebsd_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent, void *data _U_)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *tree = NULL, *frame_tree = NULL;
    guint32 nframes;
    guint32 i;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USB");

    /* add usb hdr*/
    if (parent) {
      ti = proto_tree_add_protocol_format(parent, proto_usb, tvb, 0, 128,
                                          "USB URB");
      tree = proto_item_add_subtree(ti, ett_usb_hdr);
    }

    proto_tree_add_item(tree, hf_usb_totlen, tvb, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_busunit, tvb, 4, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_address, tvb, 8, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_mode, tvb, 9, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_freebsd_urb_type, tvb, 10, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_freebsd_transfer_type, tvb, 11, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, 12, hf_usb_xferflags, ett_usb_xferflags,
                           usb_xferflags_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, 16, hf_usb_xferstatus, ett_usb_xferstatus,
                           usb_xferstatus_fields, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_error, tvb, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_interval, tvb, 24, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_usb_nframes, tvb, 28, 4, ENC_LITTLE_ENDIAN, &nframes);
    proto_tree_add_item(tree, hf_usb_packet_size, tvb, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_packet_count, tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(tree, tvb, 40, hf_usb_endpoint_address, ett_usb_endpoint, usb_endpoint_fields, ENC_NA);
    proto_tree_add_item(tree, hf_usb_speed, tvb, 44, 1, ENC_LITTLE_ENDIAN);

    offset += 128;
    for (i = 0; i < nframes; i++) {
        guint32 framelen;
        guint64 frameflags;

        frame_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
                                                   ett_usb_frame, &ti,
                                                   "Frame %u", i);
        proto_tree_add_item_ret_uint(frame_tree, hf_usb_frame_length,
                                     tvb, offset, 4, ENC_LITTLE_ENDIAN,
                                     &framelen);
        offset += 4;
        proto_tree_add_bitmask_ret_uint64(frame_tree, tvb, offset,
                                          hf_usb_frame_flags,
                                          ett_usb_frame_flags,
                                          usb_frame_flags_fields,
                                          ENC_LITTLE_ENDIAN, &frameflags);
        offset += 4;
        if (frameflags & FREEBSD_FRAMEFLAG_DATA_FOLLOWS) {
            /*
             * XXX - ultimately, we should dissect this data.
             */
            proto_tree_add_item(frame_tree, hf_usb_frame_data, tvb, offset,
                                framelen, ENC_NA);
            offset += WS_ROUNDUP_4(framelen);
        }
        proto_item_set_end(ti, tvb, offset);
    }

    return tvb_captured_length(tvb);
}

static int
netmon_HostController2(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 flags)
{
    proto_tree *host_tree;

    host_tree = proto_tree_add_subtree(tree, tvb, offset, (flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 20 : 16, ett_usbport_host_controller, NULL, "HostController");
    netmon_etl_field(host_tree, tvb, &offset, hf_usbport_device_object, flags);

    proto_tree_add_item(host_tree, hf_usbport_pci_bus, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(host_tree, hf_usbport_pci_device, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(host_tree, hf_usbport_pci_function, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(host_tree, hf_usbport_pci_vendor_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(host_tree, hf_usbport_pci_device_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
netmon_UsbPortPath(proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo)
{
    proto_item *path_item, *depth_item;
    proto_tree *path_tree;
    guint32 path_depth, path0, path1, path2, path3, path4, path5;

    path_tree = proto_tree_add_subtree(tree, tvb, offset, 28, ett_usbport_path, &path_item, "PortPath: ");
    depth_item = proto_tree_add_item_ret_uint(path_tree, hf_usbport_port_path_depth, tvb, offset, 4, ENC_LITTLE_ENDIAN, &path_depth);
    offset += 4;
    proto_tree_add_item_ret_uint(path_tree, hf_usbport_port_path0, tvb, offset, 4, ENC_LITTLE_ENDIAN, &path0);
    offset += 4;
    proto_tree_add_item_ret_uint(path_tree, hf_usbport_port_path1, tvb, offset, 4, ENC_LITTLE_ENDIAN, &path1);
    offset += 4;
    proto_tree_add_item_ret_uint(path_tree, hf_usbport_port_path2, tvb, offset, 4, ENC_LITTLE_ENDIAN, &path2);
    offset += 4;
    proto_tree_add_item_ret_uint(path_tree, hf_usbport_port_path3, tvb, offset, 4, ENC_LITTLE_ENDIAN, &path3);
    offset += 4;
    proto_tree_add_item_ret_uint(path_tree, hf_usbport_port_path4, tvb, offset, 4, ENC_LITTLE_ENDIAN, &path4);
    offset += 4;
    proto_tree_add_item_ret_uint(path_tree, hf_usbport_port_path5, tvb, offset, 4, ENC_LITTLE_ENDIAN, &path5);
    offset += 4;
    if (path_depth == 0) {
        proto_item_append_text(path_item, "-");
    }
    if (path_depth > 0) {
        proto_item_append_text(path_item, "%d", path0);
    }
    if (path_depth > 1) {
        proto_item_append_text(path_item, ",%d", path1);
    }
    if (path_depth > 2) {
        proto_item_append_text(path_item, ",%d", path2);
    }
    if (path_depth > 3) {
        proto_item_append_text(path_item, ",%d", path3);
    }
    if (path_depth > 4) {
        proto_item_append_text(path_item, ",%d", path4);
    }
    if (path_depth > 5) {
        proto_item_append_text(path_item, ",%d", path5);
    }
    if (path_depth > 6) {
        expert_add_info(pinfo, depth_item, &ei_usbport_invalid_path_depth);
    }

    return offset;
}

static int
netmon_fid_USBPORT_Device(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 flags, packet_info *pinfo)
{
    proto_item *device_item;
    proto_tree *device_tree;

    device_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_usbport_device, &device_item, "Device");
    netmon_etl_field(device_tree, tvb, &offset, hf_usbport_device_handle, flags);
    proto_tree_add_item(device_tree, hf_usb_idVendor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(device_tree, hf_usb_idProduct, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    offset = netmon_UsbPortPath(device_tree, tvb, offset, pinfo);
    proto_tree_add_item(device_tree, hf_usbport_device_speed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(device_tree, hf_usb_device_address, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
netmon_fid_USBPORT_Endpoint(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 flags)
{
    proto_tree *endpoint_tree;

    endpoint_tree = proto_tree_add_subtree(tree, tvb, offset, (flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 24 : 12, ett_usbport_endpoint, NULL, "Endpoint");
    netmon_etl_field(endpoint_tree, tvb, &offset, hf_usbport_endpoint, flags);
    netmon_etl_field(endpoint_tree, tvb, &offset, hf_usbport_pipehandle, flags);
    netmon_etl_field(endpoint_tree, tvb, &offset, hf_usbport_device_handle, flags);

    return offset;
}

static int
netmon_fid_USBPORT_Endpoint_Descriptor(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_tree *endpoint_desc_tree;

    endpoint_desc_tree = proto_tree_add_subtree(tree, tvb, offset, 7, ett_usbport_endpoint_desc, NULL, "Endpoint Descriptor");
    proto_tree_add_item(endpoint_desc_tree, hf_usbport_endpoint_desc_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(endpoint_desc_tree, hf_usbport_endpoint_desc_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(endpoint_desc_tree, hf_usbport_endpoint_address, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(endpoint_desc_tree, hf_usbport_bm_attributes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(endpoint_desc_tree, hf_usbport_max_packet_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(endpoint_desc_tree, hf_usbport_interval, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    return offset;
}

static int
netmon_URB(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 flags)
{
    proto_item *urb_item;
    proto_tree *urb_tree;
    guint32 func;
    int i, start_offset = offset;

    urb_tree = proto_tree_add_subtree(tree, tvb, offset, 8, ett_usbport_urb, &urb_item, "URB");
    proto_tree_add_item(urb_tree, hf_usbport_urb_header_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(urb_tree, hf_usbport_urb_header_function, tvb, offset, 2, ENC_LITTLE_ENDIAN, &func);
    proto_item_append_text(urb_item, ": %s", val_to_str_ext_const(func, &netmon_urb_function_vals_ext, "Unknown"));
    offset += 2;
    proto_tree_add_item(urb_tree, hf_usbport_urb_header_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_header_usbddevice_handle, flags);
    netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_header_usbdflags, flags);

    switch (func)
    {
    case 0x0000:
        netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_configuration_desc, flags);
        netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_configuration_handle, flags);
        break;
    case 0x0008: //URB_FUNCTION_CONTROL_TRANSFER
    case 0x0009: //URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER
    case 0x000A: //URB_FUNCTION_ISOCH_TRANSFER
    case 0x000B: //URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE
    case 0x000C: //URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE
    case 0x000D: //URB_FUNCTION_SET_FEATURE_TO_DEVICE
    case 0x000E: //URB_FUNCTION_SET_FEATURE_TO_INTERFACE
    case 0x000F: //URB_FUNCTION_SET_FEATURE_TO_ENDPOINT
    case 0x0010: //URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE
    case 0x0011: //URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE
    case 0x0012: //URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT
    case 0x0013: //URB_FUNCTION_GET_STATUS_FROM_DEVICE
    case 0x0014: //URB_FUNCTION_GET_STATUS_FROM_INTERFACE
    case 0x0015: //URB_FUNCTION_GET_STATUS_FROM_ENDPOINT
    case 0x0017: //URB_FUNCTION_VENDOR_DEVICE
    case 0x0018: //URB_FUNCTION_VENDOR_INTERFACE
    case 0x0019: //URB_FUNCTION_VENDOR_ENDPOINT
    case 0x001A: //URB_FUNCTION_CLASS_DEVICE
    case 0x001B: //URB_FUNCTION_CLASS_INTERFACE
    case 0x001C: //URB_FUNCTION_CLASS_ENDPOINT
    case 0x001F: //URB_FUNCTION_CLASS_OTHER
    case 0x0020: //URB_FUNCTION_VENDOR_OTHER
    case 0x0021: //URB_FUNCTION_GET_STATUS_FROM_OTHER
    case 0x0022: //URB_FUNCTION_CLEAR_FEATURE_TO_OTHER
    case 0x0023: //URB_FUNCTION_SET_FEATURE_TO_OTHER
    case 0x0024: //URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT
    case 0x0025: //URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT
    case 0x0026: //URB_FUNCTION_GET_CONFIGURATION
    case 0x0027: //URB_FUNCTION_GET_INTERFACE
    case 0x0028: //URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE
    case 0x0029: //URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE
    case 0x002A: //URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR
    case 0x0032: //URB_FUNCTION_CONTROL_TRANSFER_EX
    case 0x0037: //URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER_USING_CHAINED_MDL
    case 0x0038: //URB_FUNCTION_ISOCH_TRANSFER_USING_CHAINED_MDL
        netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_pipe_handle, flags);
        proto_tree_add_bitmask(urb_tree, tvb, offset, hf_usbport_urb_xferflags, ett_usb_xferflags,
                           usb_xferflags_fields, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(urb_tree, hf_usbport_urb_transfer_buffer_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_transfer_buffer, flags);
        netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_transfer_buffer_mdl, flags);
        netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_reserved_mbz, flags);
        for (i = 0; i < 8; i++)
        {
            netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_reserved_hcd, flags);
        }
        break;

    case 0x0002: //URB_FUNCTION_ABORT_PIPE
    case 0x001E: //URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL
    case 0x0030: //URB_FUNCTION_SYNC_RESET_PIPE
    case 0x0031: //URB_FUNCTION_SYNC_CLEAR_STALL
    case 0x0036: //URB_FUNCTION_CLOSE_STATIC_STREAMS
        netmon_etl_field(urb_tree, tvb, &offset, hf_usbport_urb_pipe_handle, flags);
        proto_tree_add_item(urb_tree, hf_usbport_urb_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        break;
    }

    proto_item_set_len(urb_item, offset-start_offset);
    return offset;
}

#define USBPORT_KEYWORD_DIAGNOSTIC         G_GUINT64_CONSTANT(0x0000000000000001)
#define USBPORT_KEYWORD_POWER_DIAGNOSTICS  G_GUINT64_CONSTANT(0x0000000000000002)
#define USBPORT_KEYWORD_PERF_DIAGNOSTICS   G_GUINT64_CONSTANT(0x0000000000000004)
#define USBPORT_KEYWORD_RESERVED1          G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFF8)

static int
dissect_netmon_usb_port(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent, void* data)
{
    proto_item *ti, *generated;
    proto_tree *usb_port_tree;
    int offset = 0;
    struct netmon_provider_id_data *provider_id_data = (struct netmon_provider_id_data*)data;
    static int * const keyword_fields[] = {
        &hf_usbport_keyword_diagnostic,
        &hf_usbport_keyword_power_diagnostics,
        &hf_usbport_keyword_perf_diagnostics,
        &hf_usbport_keyword_reserved1,
        NULL
    };

    DISSECTOR_ASSERT(provider_id_data != NULL);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBPort");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(parent, proto_usbport, tvb, 0, -1, ENC_NA);
    usb_port_tree = proto_item_add_subtree(ti, ett_usbport);

    generated = proto_tree_add_uint(usb_port_tree, hf_usbport_event_id, tvb, 0, 0, provider_id_data->event_id);
    proto_item_set_generated(generated);
    generated = proto_tree_add_bitmask_value(usb_port_tree, tvb, 0, hf_usbport_keyword, ett_usbport_keyword, keyword_fields, provider_id_data->keyword);
    proto_item_set_generated(generated);

    switch (provider_id_data->event_id)
    {
    case 71:
        offset = netmon_HostController2(usb_port_tree, tvb, offset, provider_id_data->event_flags);
        offset = netmon_fid_USBPORT_Device(usb_port_tree, tvb, offset, provider_id_data->event_flags, pinfo);
        offset = netmon_fid_USBPORT_Endpoint(usb_port_tree, tvb, offset, provider_id_data->event_flags);
        offset = netmon_fid_USBPORT_Endpoint_Descriptor(usb_port_tree, tvb, offset);
        netmon_etl_field(usb_port_tree, tvb, &offset, hf_usbport_irp, provider_id_data->event_flags);
        netmon_etl_field(usb_port_tree, tvb, &offset, hf_usbport_urb, provider_id_data->event_flags);
        offset = netmon_URB(usb_port_tree, tvb, offset, provider_id_data->event_flags);
        proto_tree_add_item(usb_port_tree, hf_usbport_urb_transfer_data, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        break;
    }

    return tvb_captured_length(tvb);
}

void
dissect_usb_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent,
                   usb_header_t header_type, void *extra_data)
{
    gint                  offset = 0;
    int                   endpoint;
    guint8                urb_type;
    guint32               win32_data_len = 0;
    guint32               iso_numdesc = 0;
    guint32               desc_offset = 0;
    guint32               location = 0;
    proto_item           *urb_tree_ti;
    proto_tree           *tree;
    proto_item           *item;
    usb_conv_info_t      *usb_conv_info;
    conversation_t       *conversation;
    guint16              device_address;
    guint16              bus_id;
    guint8                   usbpcap_control_stage = 0;
    guint64                  usb_id;
    struct mausb_header  *ma_header = NULL;
    struct usbip_header  *ip_header = NULL;
    usb_pseudo_urb_t     *pseudo_urb = NULL;

    /* the goal is to get the conversation struct as early as possible
       and store all status values in this struct
       at first, we read the fields required to create/identify
       the right conversation struct */
    switch (header_type) {

    case USB_HEADER_LINUX_48_BYTES:
    case USB_HEADER_LINUX_64_BYTES:
        urb_type = tvb_get_guint8(tvb, 8);
        endpoint = tvb_get_guint8(tvb, 10) & 0x7F;
        device_address = (guint16)tvb_get_guint8(tvb, 11);
        bus_id = tvb_get_letohs(tvb, 12);
        break;

    case USB_HEADER_USBPCAP:
        urb_type = tvb_get_guint8(tvb, 16) & 0x01 ? URB_COMPLETE : URB_SUBMIT;
        device_address = tvb_get_letohs(tvb, 19);
        endpoint = tvb_get_guint8(tvb, 21);
        if ((endpoint == 0x00) && (tvb_get_guint8(tvb, 22) == URB_CONTROL) &&
            (tvb_get_guint8(tvb, 27) == USB_CONTROL_STAGE_DATA)) {
            /* USBPcap before 1.3.0.0 DATA OUT packet (the info at offset 16 is wrong) */
            urb_type = URB_SUBMIT;
        }
        endpoint &= 0x7F; /* Clear the direction flag */
        bus_id = tvb_get_letohs(tvb, 17);
        break;

    case USB_HEADER_MAUSB:
        ma_header = (struct mausb_header *) extra_data;
        urb_type = mausb_is_from_host(ma_header) ? URB_SUBMIT : URB_COMPLETE;
        device_address = mausb_ep_handle_dev_addr(ma_header->handle);
        endpoint = mausb_ep_handle_ep_num(ma_header->handle);
        bus_id = mausb_ep_handle_bus_num(ma_header->handle);
        break;

    case USB_HEADER_USBIP:
        ip_header = (struct usbip_header *) extra_data;
        urb_type = tvb_get_ntohl(tvb, 0) == 1 ? URB_SUBMIT : URB_COMPLETE;
        device_address = ip_header->devid;
        bus_id = ip_header->busid;
        endpoint = ip_header->ep;
        break;

    case USB_HEADER_DARWIN:
        urb_type = tvb_get_guint8(tvb, 1);
        endpoint = tvb_get_guint8(tvb, 30) & 0x7F;
        device_address = (guint16)tvb_get_guint8(tvb, 29);
        location = tvb_get_letohl(tvb, 23);
        bus_id = location >> 24;
        break;

    case USB_HEADER_PSEUDO_URB:
        pseudo_urb = (usb_pseudo_urb_t *) extra_data;
        urb_type = pseudo_urb->from_host ? URB_SUBMIT : URB_COMPLETE;
        device_address = pseudo_urb->device_address;
        endpoint = pseudo_urb->endpoint;
        bus_id = pseudo_urb->bus_id;
        break;

    default:
        return; /* invalid USB pseudo header */
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USB");
    urb_tree_ti = proto_tree_add_protocol_format(parent, proto_usb, tvb, 0, -1, "USB URB");
    tree = proto_item_add_subtree(urb_tree_ti, ett_usb_hdr);

    usb_set_addr(tree, tvb, pinfo, bus_id, device_address, endpoint,
                 (urb_type == URB_SUBMIT));

    conversation = get_usb_conversation(pinfo, &pinfo->src, &pinfo->dst, pinfo->srcport, pinfo->destport);
    usb_conv_info = get_usb_conv_info(conversation);
    clear_usb_conv_tmp_data(usb_conv_info);


    switch (header_type) {

    case USB_HEADER_LINUX_48_BYTES:
    case USB_HEADER_LINUX_64_BYTES:
        proto_item_set_len(urb_tree_ti, (header_type == USB_HEADER_LINUX_64_BYTES) ? 64 : 48);
        offset = dissect_linux_usb_pseudo_header(tvb, pinfo, tree, usb_conv_info, &usb_id);
        break;

    case USB_HEADER_USBPCAP:
        offset = dissect_usbpcap_buffer_packet_header(tvb, pinfo, tree, usb_conv_info, &win32_data_len, &usb_id);
        /* the length that we're setting here might have to be corrected
           if there's a transfer-specific pseudo-header following */
        proto_item_set_len(urb_tree_ti, offset);
        break;

    case USB_HEADER_MAUSB:
        /* MA USB header gets dissected earlier, just set conversation variables */
        offset = MAUSB_DPH_LENGTH;
        mausb_set_usb_conv_info(usb_conv_info, ma_header);
        usb_id = 0;
        break;

    case USB_HEADER_USBIP:
        iso_numdesc = tvb_get_ntohl(tvb, 0x20);
        usb_conv_info->transfer_type = endpoint == 0 ? URB_CONTROL : (iso_numdesc > 0 ? URB_ISOCHRONOUS : URB_UNKNOWN);
        usb_conv_info->direction = ip_header->dir == USBIP_DIR_OUT ? P2P_DIR_SENT : P2P_DIR_RECV;
        usb_conv_info->is_setup = endpoint == 0 ? (tvb_get_ntoh64(tvb, 0x28) != G_GUINT64_CONSTANT(0)) : FALSE;
        usb_conv_info->is_request = (urb_type==URB_SUBMIT);
        offset = usb_conv_info->is_setup ? USBIP_HEADER_WITH_SETUP_LEN : USBIP_HEADER_LEN;

        /* The ISOC descriptor is located at the end of the isoc frame behind the isoc data. */
        if ((usb_conv_info->is_request && usb_conv_info->direction == USBIP_DIR_OUT) ||
            (!usb_conv_info->is_request && usb_conv_info->direction == USBIP_DIR_IN)) {
            desc_offset += tvb_get_ntohl(tvb, 0x18);
        }

        desc_offset += offset;
        usb_id = 0;
        break;

    case USB_HEADER_DARWIN:
        offset = dissect_darwin_buffer_packet_header(tvb, pinfo, tree, usb_conv_info, &usb_id);
        proto_item_set_len(urb_tree_ti, offset);
        break;

    case USB_HEADER_PSEUDO_URB:
        usb_conv_info->transfer_type = pseudo_urb->transfer_type;
        usb_conv_info->direction = pseudo_urb->from_host ? P2P_DIR_SENT : P2P_DIR_RECV;
        usb_conv_info->is_setup = pseudo_urb->from_host && (pseudo_urb->transfer_type == URB_CONTROL);
        usb_conv_info->is_request = pseudo_urb->from_host;
        usb_conv_info->speed = pseudo_urb->speed;
        usb_id = 0;
        break;

    default:
        usb_id = 0;
        break;
    }

    usb_conv_info->usb_trans_info = usb_get_trans_info(tvb, pinfo, tree, header_type, usb_conv_info, usb_id);

    if (usb_conv_info->transfer_type != URB_CONTROL) {
        usb_tap_queue_packet(pinfo, urb_type, usb_conv_info);
    }

    switch(usb_conv_info->transfer_type) {
    case URB_BULK:
    case URB_INTERRUPT:
        item = proto_tree_add_uint(tree, hf_usb_bInterfaceClass, tvb, 0, 0, usb_conv_info->interfaceClass);
        proto_item_set_generated(item);

        switch (header_type) {

        case USB_HEADER_LINUX_48_BYTES:
        case USB_HEADER_LINUX_64_BYTES:
            /* bulk and interrupt transfers never contain a setup packet */
            proto_tree_add_item(tree, hf_usb_urb_unused_setup_header, tvb, offset, 8, ENC_NA);
            offset += 8;
            if (header_type == USB_HEADER_LINUX_64_BYTES) {
                offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);
            }
            break;

        case USB_HEADER_USBPCAP:
            break;

        case USB_HEADER_MAUSB:
            break;

        case USB_HEADER_USBIP:
            break;

        case USB_HEADER_DARWIN:
            break;

        case USB_HEADER_PSEUDO_URB:
            break;
        }
        break;

    case URB_CONTROL:
        if (header_type == USB_HEADER_USBPCAP) {
            proto_tree_add_item(tree, hf_usb_win32_control_stage, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            usbpcap_control_stage = tvb_get_guint8(tvb, offset);
            offset++;
            proto_item_set_len(urb_tree_ti, offset);
            if (usbpcap_control_stage == USB_CONTROL_STAGE_SETUP) {
                usb_conv_info->is_setup = TRUE;
            } else if (usbpcap_control_stage == USB_CONTROL_STAGE_DATA && urb_type == URB_SUBMIT) {
                /* USBPcap before 1.5.0.0 */
                wmem_tree_key_t key[3];
                key[0].length = 2;
                key[0].key = (guint32 *)&usb_id;
                key[1].length = 1;
                key[1].key = &pinfo->num;
                key[2].length = 0;
                key[2].key = NULL;
                usbpcap_setup_data_t *setup_data = (usbpcap_setup_data_t *)wmem_tree_lookup32_array_le(usbpcap_setup_data, key);
                if (setup_data && setup_data->usb_id == usb_id) {
                    tvbuff_t *reassembled_tvb = tvb_new_composite();
                    tvb_composite_append(reassembled_tvb, tvb_new_child_real_data(tvb, setup_data->setup_data, 8, 8));
                    tvb_composite_append(reassembled_tvb, tvb_new_subset_remaining(tvb, offset));
                    tvb_composite_finalize(reassembled_tvb);
                    add_new_data_source(pinfo, reassembled_tvb, "USBPcap reassembled setup");
                    usb_conv_info->is_setup = TRUE;
                    tvb = reassembled_tvb;
                    offset = 0;
                }
            }
        }

        if (usb_conv_info->is_request) {
            if (usb_conv_info->is_setup) {
                offset = dissect_usb_setup_request(pinfo, tree, tvb, offset, urb_type,
                                                   usb_conv_info, header_type, usb_id);

            } else {
                switch (header_type) {

                case USB_HEADER_LINUX_48_BYTES:
                case USB_HEADER_LINUX_64_BYTES:
                    proto_tree_add_item(tree, hf_usb_urb_unused_setup_header, tvb, offset, 8, ENC_NA);
                    offset += 8;
                    if (header_type == USB_HEADER_LINUX_64_BYTES) {
                        offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);
                    }
                    break;

                case USB_HEADER_USBPCAP:
                    break;

                case USB_HEADER_MAUSB:
                    break;

                case USB_HEADER_USBIP:
                    break;

                case USB_HEADER_DARWIN:
                    break;

                case USB_HEADER_PSEUDO_URB:
                    break;
                }
            }
        } else {
            /* this is a response */

            switch (header_type) {

            case USB_HEADER_LINUX_48_BYTES:
            case USB_HEADER_LINUX_64_BYTES:
                /* Skip setup header - it's never applicable for responses */
                proto_tree_add_item(tree, hf_usb_urb_unused_setup_header, tvb, offset, 8, ENC_NA);
                offset += 8;
                if (header_type == USB_HEADER_LINUX_64_BYTES) {
                    offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);
                }
                break;

            case USB_HEADER_USBPCAP:
                /* Check if this is status stage */
                if ((usb_conv_info->usb_trans_info) &&
                    (usbpcap_control_stage == USB_CONTROL_STAGE_STATUS)) {
                    const gchar *description;
                    if (USB_TYPE(usb_conv_info->usb_trans_info->setup.requesttype) == RQT_SETUP_TYPE_STANDARD) {
                        description = val_to_str_ext(usb_conv_info->usb_trans_info->setup.request,
                            &setup_request_names_vals_ext, "Unknown type %x") ;
                    } else {
                        description = "URB_CONTROL";
                    }
                    col_add_fstr(pinfo->cinfo, COL_INFO, "%s status", description);
                    /* There is no data to dissect */
                    return;
                }
                break;

            case USB_HEADER_MAUSB:
                break;

            case USB_HEADER_USBIP:
                break;

            case USB_HEADER_DARWIN:
                break;

            case USB_HEADER_PSEUDO_URB:
                break;
            }

            offset = dissect_usb_setup_response(pinfo, tree, tvb, offset,
                                                urb_type, usb_conv_info);
        }
        break;
    case URB_ISOCHRONOUS:
        switch (header_type) {

        case USB_HEADER_LINUX_48_BYTES:
        case USB_HEADER_LINUX_64_BYTES:
            offset = dissect_linux_usb_iso_transfer(pinfo, tree, header_type,
                    tvb, offset, usb_conv_info);
            break;

        case USB_HEADER_USBPCAP:
            offset = dissect_usbpcap_iso_packets(pinfo, tree,
                    urb_type, tvb, offset, win32_data_len, usb_conv_info);
            break;

        case USB_HEADER_MAUSB:
            break;

        case USB_HEADER_USBIP:
            offset = dissect_usbip_iso_transfer(pinfo, tree,
                    tvb, offset, iso_numdesc, desc_offset, usb_conv_info);
            break;

        case USB_HEADER_DARWIN:
            offset = dissect_darwin_usb_iso_transfer(pinfo, tree, header_type,
                    urb_type, tvb, offset, usb_conv_info);
            break;

        case USB_HEADER_PSEUDO_URB:
            break;
        }
        break;

    default:
        /* unknown transfer type */
        switch (header_type) {
        case USB_HEADER_LINUX_48_BYTES:
        case USB_HEADER_LINUX_64_BYTES:
            proto_tree_add_item(tree, hf_usb_urb_unused_setup_header, tvb, offset, 8, ENC_NA);
            offset += 8;
            if (header_type == USB_HEADER_LINUX_64_BYTES) {
                offset = dissect_linux_usb_pseudo_header_ext(tvb, offset, pinfo, tree);
            }
            break;

        case USB_HEADER_USBPCAP:
            break;

        case USB_HEADER_MAUSB:
            break;

        case USB_HEADER_USBIP:
            break;

        case USB_HEADER_DARWIN:
            break;

        case USB_HEADER_PSEUDO_URB:
            break;
        }
        break;
    }

    dissect_usb_payload(tvb, pinfo, parent, tree, usb_conv_info, urb_type,
                        offset, device_address);
}

static int
dissect_linux_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent, void* data _U_)
{
    dissect_usb_common(tvb, pinfo, parent, USB_HEADER_LINUX_48_BYTES, NULL);
    return tvb_captured_length(tvb);
}

static int
dissect_linux_usb_mmapped(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent, void* data _U_)
{
    dissect_usb_common(tvb, pinfo, parent, USB_HEADER_LINUX_64_BYTES, NULL);
    return tvb_captured_length(tvb);
}


static int
dissect_win32_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent, void* data _U_)
{
    dissect_usb_common(tvb, pinfo, parent, USB_HEADER_USBPCAP, NULL);
    return tvb_captured_length(tvb);
}

static int
dissect_darwin_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent, void* data _U_)
{
    dissect_usb_common(tvb, pinfo, parent, USB_HEADER_DARWIN, NULL);
    return tvb_captured_length(tvb);
}

void
proto_register_usb(void)
{
    module_t *usb_module;
    static hf_register_info hf[] = {

    /* USB packet pseudoheader members */

        { &hf_usb_totlen,
          { "Total length", "usb.totlen",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_busunit,
          { "Host controller unit number", "usb.busunit",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_address,
          { "USB device index", "usb.address",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_mode,
          { "Mode of transfer", "usb.transfer_mode",
            FT_UINT8, BASE_DEC, VALS(usb_freebsd_transfer_mode_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_freebsd_urb_type,
          { "URB type", "usb.freebsd_type",
            FT_UINT8, BASE_DEC, VALS(usb_freebsd_urb_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_freebsd_transfer_type,
          { "URB transfer type", "usb.freebsd_transfer_type",
            FT_UINT8, BASE_HEX, VALS(usb_freebsd_transfer_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_xferflags,
          { "Transfer flags", "usb.xferflags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_xferflags_force_short_xfer,
          { "Force short transfer", "usb.xferflags.force_short_xfer",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_FORCE_SHORT_XFER,
            NULL, HFILL }},

        { &hf_usb_xferflags_short_xfer_ok,
          { "Short transfer OK", "usb.xferflags.short_xfer_ok",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_SHORT_XFER_OK,
            NULL, HFILL }},

        { &hf_usb_xferflags_short_frames_ok,
          { "Short frames OK", "usb.xferflags.short_frames_ok",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_SHORT_FRAMES_OK,
            NULL, HFILL }},

        { &hf_usb_xferflags_pipe_bof,
          { "Pipe BOF", "usb.xferflags.pipe_bof",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_PIPE_BOF,
            NULL, HFILL }},

        { &hf_usb_xferflags_proxy_buffer,
          { "Proxy buffer", "usb.xferflags.proxy_buffer",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_PROXY_BUFFER,
            NULL, HFILL }},

        { &hf_usb_xferflags_ext_buffer,
          { "External buffer", "usb.xferflags.ext_buffer",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_EXT_BUFFER,
            NULL, HFILL }},

        { &hf_usb_xferflags_manual_status,
          { "Manual status", "usb.xferflags.manual_status",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_MANUAL_STATUS,
            NULL, HFILL }},

        { &hf_usb_xferflags_no_pipe_ok,
          { "No pipe OK", "usb.xferflags.no_pipe_ok",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_NO_PIPE_OK,
            NULL, HFILL }},

        { &hf_usb_xferflags_stall_pipe,
          { "Stall pipe", "usb.xferflags.stall_pipe",
            FT_BOOLEAN, 32, NULL, FREEBSD_FLAG_STALL_PIPE,
            NULL, HFILL }},

        { &hf_usb_xferstatus,
          { "Transfer status", "usb.xferstatus",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_xferstatus_open,
          { "Pipe has been opened", "usb.xferstatus.open",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_OPEN,
            NULL, HFILL }},

        { &hf_usb_xferstatus_transferring,
          { "Transfer in progress", "usb.xferstatus.transferring",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_TRANSFERRING,
            NULL, HFILL }},

        { &hf_usb_xferstatus_did_dma_delay,
          { "Waited for hardware DMA", "usb.xferstatus.did_dma_delay",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_DID_DMA_DELAY,
            NULL, HFILL }},

        { &hf_usb_xferstatus_did_close,
          { "Transfer closed", "usb.xferstatus.did_close",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_DID_CLOSE,
            NULL, HFILL }},

        { &hf_usb_xferstatus_draining,
          { "Draining transfer", "usb.xferstatus.draining",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_DRAINING,
            NULL, HFILL }},

        { &hf_usb_xferstatus_started,
          { "Transfer started", "usb.xferstatus.started",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_STARTED,
            "Whether the transfer is started or stopped", HFILL }},

        { &hf_usb_xferstatus_bw_reclaimed,
          { "Bandwidth reclaimed", "usb.xferstatus.bw_reclaimed",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_BW_RECLAIMED,
            NULL, HFILL }},

        { &hf_usb_xferstatus_control_xfr,
          { "Control transfer", "usb.xferstatus.control_xfr",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_CONTROL_XFR,
            NULL, HFILL }},

        { &hf_usb_xferstatus_control_hdr,
          { "Control header being sent", "usb.xferstatus.control_hdr",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_CONTROL_HDR,
            NULL, HFILL }},

        { &hf_usb_xferstatus_control_act,
          { "Control transfer active", "usb.xferstatus.control_act",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_CONTROL_ACT,
            NULL, HFILL }},

        { &hf_usb_xferstatus_control_stall,
          { "Control transfer should be stalled", "usb.xferstatus.control_stall",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_CONTROL_STALL,
            NULL, HFILL }},

        { &hf_usb_xferstatus_short_frames_ok,
          { "Short frames OK", "usb.xferstatus.short_frames_ok",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_SHORT_FRAMES_OK,
            NULL, HFILL }},

        { &hf_usb_xferstatus_short_xfer_ok,
          { "Short transfer OK", "usb.xferstatus.short_xfer_ok",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_SHORT_XFER_OK,
            NULL, HFILL }},

        { &hf_usb_xferstatus_bdma_enable,
          { "BUS-DMA enabled", "usb.xferstatus.bdma_enable",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_BDMA_ENABLE,
            NULL, HFILL }},

        { &hf_usb_xferstatus_bdma_no_post_sync,
          { "BUS-DMA post sync op not done", "usb.xferstatus.bdma_no_post_sync",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_BDMA_NO_POST_SYNC,
            NULL, HFILL }},

        { &hf_usb_xferstatus_bdma_setup,
          { "BUS-DMA set up", "usb.xferstatus.bdma_setup",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_BDMA_SETUP,
            NULL, HFILL }},

        { &hf_usb_xferstatus_isochronous_xfr,
          { "Isochronous transfer", "usb.xferstatus.isochronous_xfr",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_ISOCHRONOUS_XFR,
            NULL, HFILL }},

        { &hf_usb_xferstatus_curr_dma_set,
          { "Current DMA set", "usb.xferstatus.curr_dma_set",
            FT_UINT32, BASE_DEC, NULL, FREEBSD_STATUS_CURR_DMA_SET,
            NULL, HFILL }},

        { &hf_usb_xferstatus_can_cancel_immed,
          { "Transfer can be cancelled immediately", "usb.xferstatus.can_cancel_immed",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_CAN_CANCEL_IMMED,
            NULL, HFILL }},

        { &hf_usb_xferstatus_doing_callback,
          { "Executing the callback", "usb.xferstatus.doing_callback",
            FT_BOOLEAN, 32, NULL, FREEBSD_STATUS_DOING_CALLBACK,
            NULL, HFILL }},

        { &hf_usb_error,
          { "Error", "usb.error",
            FT_UINT32, BASE_DEC, VALS(usb_freebsd_err_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_interval,
          { "Interval", "usb.interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Interval (ms)", HFILL }},

        { &hf_usb_nframes,
          { "Number of following frames", "usb.nframes",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_packet_size,
          { "Packet size used", "usb.packet_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_packet_count,
          { "Packet count used", "usb.packet_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_speed,
          { "Speed", "usb.speed",
            FT_UINT8, BASE_DEC, VALS(usb_freebsd_speed_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_frame_length,
          { "Frame length", "usb.frame.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_frame_flags,
          { "Frame flags", "usb.frame.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_frame_flags_read,
          { "Data direction is read", "usb.frame.read",
            FT_BOOLEAN, 32, NULL, FREEBSD_FRAMEFLAG_READ,
            NULL, HFILL }},

        { &hf_usb_frame_flags_data_follows,
          { "Frame contains data", "usb.frame.data_follows",
            FT_BOOLEAN, 32, NULL, FREEBSD_FRAMEFLAG_DATA_FOLLOWS,
            NULL, HFILL }},

        { &hf_usb_frame_data,
          { "Frame data", "usb.frame.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_urb_id,
          { "URB id", "usb.urb_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_linux_urb_type,
          { "URB type", "usb.urb_type",
            FT_CHAR, BASE_HEX, VALS(usb_linux_urb_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_linux_transfer_type,
          { "URB transfer type", "usb.transfer_type",
            FT_UINT8, BASE_HEX, VALS(usb_linux_transfer_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_endpoint_address,
          { "Endpoint", "usb.endpoint_address",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "USB endpoint address", HFILL }},

        { &hf_usb_endpoint_direction,
          { "Direction", "usb.endpoint_address.direction",
            FT_UINT8, BASE_DEC, VALS(usb_endpoint_direction_vals), 0x80,
            "USB endpoint direction", HFILL }},

        { &hf_usb_endpoint_number,
          { "Endpoint number", "usb.endpoint_address.number",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            "USB endpoint number", HFILL }},

        { &hf_usb_device_address,
          { "Device", "usb.device_address",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "USB device address", HFILL }},

        { &hf_usb_bus_id,
          { "URB bus id", "usb.bus_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_setup_flag,
          { "Device setup request", "usb.setup_flag",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "USB device setup request is relevant (0) or not", HFILL }},

        { &hf_usb_data_flag,
          { "Data", "usb.data_flag",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "USB data is present (0) or not", HFILL }},

        { &hf_usb_urb_ts_sec,
          { "URB sec", "usb.urb_ts_sec",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_urb_ts_usec,
          { "URB usec", "usb.urb_ts_usec",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_urb_status,
          { "URB status", "usb.urb_status",
            FT_INT32, BASE_DEC|BASE_EXT_STRING, &linux_negative_errno_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_urb_len,
          { "URB length [bytes]", "usb.urb_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "URB length in bytes", HFILL }},

        { &hf_usb_urb_data_len,
          { "Data length [bytes]", "usb.data_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "URB data length in bytes", HFILL }},

        { &hf_usb_urb_unused_setup_header,
          { "Unused Setup Header",
            "usb.unused_setup_header", FT_NONE, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_usb_urb_interval,
          { "Interval",
            "usb.interval", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_usb_urb_start_frame,
          { "Start frame",
            "usb.start_frame", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_usb_urb_copy_of_transfer_flags,
          { "Copy of Transfer Flags",
            "usb.copy_of_transfer_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_short_not_ok,
          { "Short not OK",
            "usb.transfer_flags.short_not_ok", FT_BOOLEAN, 32,
            NULL, URB_SHORT_NOT_OK, NULL, HFILL }},

        { &hf_iso_asap,
          { "ISO ASAP",
            "usb.transfer_flags.iso_asap", FT_BOOLEAN, 32,
            NULL, URB_ISO_ASAP, NULL, HFILL }},

        { &hf_no_transfer_dma_map,
          { "No transfer DMA map",
            "usb.transfer_flags.no_transfer_dma_map", FT_BOOLEAN, 32,
            NULL, URB_NO_TRANSFER_DMA_MAP, NULL, HFILL }},

        { &hf_no_fsbr,
          { "No FSBR",
            "usb.transfer_flags.no_fsbr", FT_BOOLEAN, 32,
            NULL, URB_NO_FSBR, NULL, HFILL }},

        { &hf_zero_packet,
          { "Zero Packet", "usb.transfer_flags.zero_packet", FT_BOOLEAN, 32,
            NULL, URB_ZERO_PACKET, NULL, HFILL }},

        { &hf_no_interrupt,
          { "No Interrupt", "usb.transfer_flags.no_interrupt", FT_BOOLEAN, 32,
            NULL, URB_NO_INTERRUPT, NULL, HFILL }},

        { &hf_free_buffer,
          { "Free Buffer", "usb.transfer_flags.free_buffer", FT_BOOLEAN, 32,
            NULL, URB_FREE_BUFFER, NULL, HFILL }},

        { &hf_dir_in,
          { "Dir IN", "usb.transfer_flags.dir_in", FT_BOOLEAN, 32,
            NULL, URB_DIR_IN, NULL, HFILL }},

        { &hf_dma_map_single,
          { "DMA Map Single", "usb.transfer_flags.dma_map_single", FT_BOOLEAN, 32,
            NULL, URB_DMA_MAP_SINGLE, NULL, HFILL }},

        { &hf_dma_map_page,
          { "DMA Map Page", "usb.transfer_flags.dma_map_page", FT_BOOLEAN, 32,
            NULL, URB_DMA_MAP_PAGE, NULL, HFILL }},

        { &hf_dma_map_sg,
          { "DMA Map SG", "usb.transfer_flags.dma_map_sg", FT_BOOLEAN, 32,
            NULL, URB_DMA_MAP_SG, NULL, HFILL }},

        { &hf_map_local,
          { "Map Local", "usb.transfer_flags.map_local", FT_BOOLEAN, 32,
            NULL, URB_MAP_LOCAL, NULL, HFILL }},

        { &hf_setup_map_single,
          { "Setup Map Single", "usb.transfer_flags.setup_map_single", FT_BOOLEAN, 32,
            NULL, URB_SETUP_MAP_SINGLE, NULL, HFILL }},

        { &hf_setup_map_local,
          { "Setup Map Local", "usb.transfer_flags.setup_map_local", FT_BOOLEAN, 32,
            NULL, URB_SETUP_MAP_LOCAL, NULL, HFILL }},

        { &hf_dma_sg_combined,
          { "DMA S-G Combined", "usb.transfer_flags.dma_sg_combined", FT_BOOLEAN, 32,
            NULL, URB_DMA_SG_COMBINED, NULL, HFILL }},

        { &hf_aligned_temp_buffer,
          { "Aligned Temp Buffer", "usb.transfer_flags.aligned_temp_buffer", FT_BOOLEAN, 32,
            NULL, URB_ALIGNED_TEMP_BUFFER, NULL, HFILL }},

        /* Win32 USBPcap pseudoheader */
        { &hf_usb_win32_header_len,
          { "USBPcap pseudoheader length", "usb.usbpcap_header_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_irp_id,
          { "IRP ID", "usb.irp_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_usbd_status,
          { "IRP USBD_STATUS", "usb.usbd_status",
            FT_UINT32, BASE_HEX | BASE_EXT_STRING, &win32_usbd_status_vals_ext, 0x0,
            "USB request status value", HFILL }},

        { &hf_usb_function,
          { "URB Function", "usb.function",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &win32_urb_function_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_info,
          { "IRP information", "usb.irp_info",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_usbpcap_info_reserved,
          { "Reserved", "usb.irp_info.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            NULL, HFILL }},

        { &hf_usb_usbpcap_info_direction,
          { "Direction", "usb.irp_info.direction",
            FT_UINT8, BASE_HEX, VALS(win32_usb_info_direction_vals), 0x01,
            NULL, HFILL }},

        { &hf_usb_win32_device_address,
          { "Device address", "usb.device_address",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Windows USB device address", HFILL }},

        { &hf_usb_win32_transfer_type,
          { "URB transfer type", "usb.transfer_type",
            FT_UINT8, BASE_HEX, VALS(win32_usb_transfer_type_vals), 0x0,
            NULL, HFILL } },

        { &hf_usb_win32_data_len,
          { "Packet Data Length", "usb.data_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_win32_control_stage,
          { "Control transfer stage", "usb.control_stage",
            FT_UINT8, BASE_DEC, VALS(usb_control_stage_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_win32_iso_start_frame,
          { "Isochronous transfer start frame", "usb.win32.iso_frame",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_win32_iso_num_packets,
          { "Isochronous transfer number of packets", "usb.win32.iso_num_packets",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_win32_iso_error_count,
          { "Isochronous transfer error count", "usb.win32.iso_error_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_win32_iso_offset,
          { "ISO Data offset", "usb.win32.iso_offset",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_win32_iso_length,
          { "ISO Data length", "usb.win32.iso_data_len",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_win32_iso_status,
          { "ISO USBD status", "usb.win32.iso_status",
            FT_UINT32, BASE_HEX | BASE_EXT_STRING, &win32_usbd_status_vals_ext, 0x0,
            NULL, HFILL }},

        /* macOS usbdump pseudoheader */
        { &hf_usb_darwin_bcd_version,
          { "Darwin header bcdVersion", "usb.darwin.bcdVersion",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_header_len,
          { "Darwin header length", "usb.darwin.header_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_request_type,
          { "Request type", "usb.darwin.request_type",
            FT_UINT8, BASE_DEC, VALS(usb_darwin_request_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_io_len,
          { "I/O length [bytes]", "usb.darwin.io_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Request length in bytes", HFILL }},

        { &hf_usb_darwin_io_status,
          { "Request status", "usb.darwin.io_status",
            FT_UINT32, BASE_HEX | BASE_EXT_STRING, &usb_darwin_status_vals_ext, 0x0,
            "USB request status", HFILL }},

        { &hf_usb_darwin_iso_num_packets,
          { "Isochronous transfer number of frames", "usb.darwin.io_frame_count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_io_id,
          { "I/O ID", "usb.darwin.io_id",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_device_location,
          { "Device location ID", "usb.darwin.location_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_speed,
          { "Device speed", "usb.darwin_device_speed",
            FT_UINT8, BASE_DEC, VALS(usb_darwin_speed_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_device_address,
          { "USB device index", "usb.darwin.device_address",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_endpoint_address,
          { "Endpoint address", "usb.darwin.endpoint_address",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Endpoint address and direction", HFILL }},

        { &hf_usb_darwin_endpoint_type,
          { "Endpoint transfer type", "usb.darwin.endpoint_type",
            FT_UINT8, BASE_DEC, VALS(usb_darwin_endpoint_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_iso_status,
          { "Frame status", "usb.darwin.iso.status",
            FT_UINT32, BASE_HEX | BASE_EXT_STRING, &usb_darwin_status_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_iso_timestamp,
          { "Frame timestamp", "usb.darwin.iso.timestamp",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_darwin_iso_frame_number,
          { "Frame number", "usb.darwin.iso.frame_number",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bmRequestType,
          { "bmRequestType", "usb.bmRequestType",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* Only used when response type cannot be determined */
        { &hf_usb_control_response_generic,
          { "CONTROL response data", "usb.control.Response",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_request,
          { "bRequest", "usb.setup.bRequest",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &setup_request_names_vals_ext, 0x0,
            NULL, HFILL }},

        /* Same as hf_usb_request but no descriptive text */
        { &hf_usb_request_unknown_class,
          { "bRequest", "usb.setup.bRequest",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_value,
          { "wValue", "usb.setup.wValue",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_index,
          { "wIndex", "usb.setup.wIndex",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_length,
          { "wLength", "usb.setup.wLength",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_device_wFeatureSelector,
          { "wFeatureSelector", "usb.setup.wFeatureSelector",
            FT_UINT16, BASE_DEC, VALS(usb_device_feature_selector_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_interface_wFeatureSelector,
          { "wFeatureSelector", "usb.setup.wFeatureSelector",
            FT_UINT16, BASE_DEC, VALS(usb_interface_feature_selector_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_endpoint_wFeatureSelector,
          { "wFeatureSelector", "usb.setup.wFeatureSelector",
            FT_UINT16, BASE_DEC, VALS(usb_endpoint_feature_selector_vals), 0x0,
            NULL, HFILL }},

        { &hf_usb_wInterface,
          { "wInterface", "usb.setup.wInterface",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_wEndpoint,
          { "wEndpoint", "usb.setup.wEndpoint",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_wStatus,
          { "wStatus", "usb.setup.wStatus",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_wFrameNumber,
          { "wFrameNumber", "usb.setup.wFrameNumber",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

    /* --------------------------------- */
        { &hf_usb_iso_error_count,                /* host endian byte order */
          { "ISO error count", "usb.iso.error_count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_iso_numdesc,
          { "Number of ISO descriptors", "usb.iso.numdesc",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        /* fields of struct mon_bin_isodesc from linux/drivers/usb/mon/mon_bin.c */
        { &hf_usb_iso_status,
          { "Status", "usb.iso.iso_status",
            FT_INT32, BASE_DEC|BASE_EXT_STRING, &linux_negative_errno_vals_ext, 0x0,
            "ISO descriptor status", HFILL }},

        { &hf_usb_iso_off,
          { "Offset [bytes]", "usb.iso.iso_off",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "ISO data offset in bytes starting from the end of the last ISO descriptor", HFILL }},

        { &hf_usb_iso_len,
          { "Length [bytes]", "usb.iso.iso_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "ISO data length in bytes", HFILL }},

        { &hf_usb_iso_actual_len,
          { "Actual Length [bytes]", "usb.iso.iso_actual_len",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "ISO data actual length in bytes", HFILL }},

        { &hf_usb_iso_pad,                        /* host endian byte order */
          { "Padding", "usb.iso.pad",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Padding field of ISO descriptor structure", HFILL }},

        { &hf_usb_iso_data,
          {"ISO Data", "usb.iso.data",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},
    /* --------------------------------- */
#if 0
        { &hf_usb_data_len,
          {"Application Data Length", "usb.data.length",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }},
#endif

        { &hf_usb_capdata,
          {"Leftover Capture Data", "usb.capdata",
           FT_BYTES, BASE_NONE, NULL, 0x0,
           "Padding added by the USB capture system", HFILL }},

        { &hf_usb_bmRequestType_direction,
          { "Direction", "usb.bmRequestType.direction",
            FT_BOOLEAN, 8, TFS(&tfs_bmrequesttype_direction), USB_DIR_IN,
            NULL, HFILL }},

        { &hf_usb_bmRequestType_type,
          { "Type", "usb.bmRequestType.type",
            FT_UINT8, BASE_HEX, VALS(bmrequesttype_type_vals), USB_TYPE_MASK,
            NULL, HFILL }},

        { &hf_usb_bmRequestType_recipient,
          { "Recipient", "usb.bmRequestType.recipient",
            FT_UINT8, BASE_HEX, VALS(bmrequesttype_recipient_vals), 0x1f,
            NULL, HFILL }},

        { &hf_usb_bDescriptorType,
          { "bDescriptorType", "usb.bDescriptorType",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &std_descriptor_type_vals_ext, 0x0,
            NULL, HFILL }},

        /* Only used when descriptor type cannot be determined */
        { &hf_usb_get_descriptor_resp_generic,
          { "GET DESCRIPTOR Response data", "usb.getDescriptor.Response",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_descriptor_index,
          { "Descriptor Index", "usb.DescriptorIndex",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_language_id,
          { "Language Id", "usb.LanguageId",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING,&usb_langid_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bLength,
          { "bLength", "usb.bLength",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bcdUSB,
          { "bcdUSB", "usb.bcdUSB",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bDeviceClass,
          { "bDeviceClass", "usb.bDeviceClass",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &usb_class_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bDeviceSubClass,
          { "bDeviceSubClass", "usb.bDeviceSubClass",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bDeviceProtocol,
          { "bDeviceProtocol", "usb.bDeviceProtocol",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bMaxPacketSize0,
          { "bMaxPacketSize0", "usb.bMaxPacketSize0",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_idVendor,
          { "idVendor", "usb.idVendor",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ext_usb_vendors_vals, 0x0,
            NULL, HFILL }},

        { &hf_usb_idProduct,
          { "idProduct", "usb.idProduct",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bcdDevice,
          { "bcdDevice", "usb.bcdDevice",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_iManufacturer,
          { "iManufacturer", "usb.iManufacturer",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_iProduct,
          { "iProduct", "usb.iProduct",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_iSerialNumber,
          { "iSerialNumber", "usb.iSerialNumber",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bNumConfigurations,
          { "bNumConfigurations", "usb.bNumConfigurations",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_wLANGID,
          { "wLANGID", "usb.wLANGID",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING,&usb_langid_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bString,
          { "bString", "usb.bString",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceNumber,
          { "bInterfaceNumber", "usb.bInterfaceNumber",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bAlternateSetting,
          { "bAlternateSetting", "usb.bAlternateSetting",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bNumEndpoints,
          { "bNumEndpoints", "usb.bNumEndpoints",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceClass,
          { "bInterfaceClass", "usb.bInterfaceClass",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &usb_class_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceSubClass,
          { "bInterfaceSubClass", "usb.bInterfaceSubClass",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceSubClass_audio,
          { "bInterfaceSubClass", "usb.bInterfaceSubClass",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ext_usb_audio_subclass_vals, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceSubClass_cdc,
          { "bInterfaceSubClass", "usb.bInterfaceSubClass",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ext_usb_com_subclass_vals, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceSubClass_massstorage ,
          { "bInterfaceSubClass", "usb.bInterfaceSubClass",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ext_usb_massstorage_subclass_vals, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceSubClass_hid,
          { "bInterfaceSubClass", "usb.bInterfaceSubClass",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_hid_subclass_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceSubClass_misc,
          { "bInterfaceSubClass", "usb.bInterfaceSubClass",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_misc_subclass_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceSubClass_app,
          { "bInterfaceSubClass", "usb.bInterfaceSubClass",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_app_subclass_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol,
          { "bInterfaceProtocol", "usb.bInterfaceProtocol",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol_cdc,
          { "bInterfaceProtocol", "usb.bInterfaceProtocol",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_cdc_protocol_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol_massstorage,
          { "bInterfaceProtocol", "usb.bInterfaceProtocol",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_massstorage_protocol_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol_cdc_data,
          { "bInterfaceProtocol", "usb.bInterfaceProtocol",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_cdc_data_protocol_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol_hid_boot,
          { "bInterfaceProtocol", "usb.bInterfaceProtocol",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_hid_boot_protocol_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol_app_dfu,
          { "bInterfaceProtocol", "usb.bInterfaceProtocol",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_app_dfu_protocol_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol_app_irda,
          { "bInterfaceProtocol", "usb.bInterfaceProtocol",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_app_irda_protocol_vals_ext, 0x0,
            NULL, HFILL }},

        { &hf_usb_bInterfaceProtocol_app_usb_test_and_measurement,
          { "bInterfaceProtocol", "usb.bInterfaceProtocol",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &usb_app_usb_test_and_measurement_protocol_vals_ext, 0x0,
            NULL, HFILL }},


        { &hf_usb_iInterface,
          { "iInterface", "usb.iInterface",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bEndpointAddress,
          { "bEndpointAddress", "usb.bEndpointAddress",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_configuration_bmAttributes,
          { "Configuration bmAttributes", "usb.configuration.bmAttributes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bmAttributes,
          { "bmAttributes", "usb.bmAttributes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bEndpointAttributeTransfer,
          { "Transfertype", "usb.bmAttributes.transfer",
            FT_UINT8, BASE_HEX, VALS(usb_bmAttributes_transfer_vals), 0x03,
            NULL, HFILL }},

        { &hf_usb_bEndpointAttributeSynchonisation,
          { "Synchronisationtype", "usb.bmAttributes.sync",
            FT_UINT8, BASE_HEX, VALS(usb_bmAttributes_sync_vals), 0x0c,
            NULL, HFILL }},

        { &hf_usb_bEndpointAttributeBehaviour,
          { "Behaviourtype", "usb.bmAttributes.behaviour",
            FT_UINT8, BASE_HEX, VALS(usb_bmAttributes_behaviour_vals), 0x30,
            NULL, HFILL }},

        { &hf_usb_wMaxPacketSize,
          { "wMaxPacketSize", "usb.wMaxPacketSize",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_wMaxPacketSize_size,
          { "Maximum Packet Size", "usb.wMaxPacketSize.size",
            FT_UINT16, BASE_DEC, NULL, 0x3FF,
            NULL, HFILL }},

        { &hf_usb_wMaxPacketSize_slots,
          { "Transactions per microframe", "usb.wMaxPacketSize.slots",
            FT_UINT16, BASE_DEC, VALS(usb_wMaxPacketSize_slots_vals), (3<<11),
            NULL, HFILL }},

        { &hf_usb_bInterval,
          { "bInterval", "usb.bInterval",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bMaxBurst,
          { "bMaxBurst", "usb.bMaxBurst",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Valid values are from 0 to 15. For control endpoints this value shall be 0.", HFILL }},

        { &hf_usb_audio_bRefresh,
          { "bRefresh", "usb.audio.bRefresh",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        { &hf_usb_audio_bSynchAddress,
          { "bSynchAddress", "usb.audio.bSynchAddress",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        { &hf_usb_bSSEndpointAttributeBulkMaxStreams,
          { "MaxStreams", "usb.bmAttributes.MaxStreams",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            "Number of streams = 2 to the power MaxStreams", HFILL }},

        { &hf_usb_bSSEndpointAttributeIsoMult,
          { "Mult", "usb.bmAttributes.Mult",
            FT_UINT8, BASE_DEC, NULL, 0x03,
            "Maximum number of packets = bMaxBurst * (Mult + 1)", HFILL } },

        { &hf_usb_wBytesPerInterval,
          { "wBytesPerInterval", "usb.wBytesPerInterval",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },

        { &hf_usb_wTotalLength,
          { "wTotalLength", "usb.wTotalLength",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bNumInterfaces,
          { "bNumInterfaces", "usb.bNumInterfaces",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bConfigurationValue,
          { "bConfigurationValue", "usb.bConfigurationValue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_iConfiguration,
          { "iConfiguration", "usb.iConfiguration",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_bMaxPower,
          { "bMaxPower", "usb.bMaxPower",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_usb_configuration_legacy10buspowered,
          { "Must be 1", "usb.configuration.legacy10buspowered",
            FT_BOOLEAN, 8, TFS(&tfs_mustbeone), 0x80,
            "Legacy USB 1.0 bus powered", HFILL }},

        { &hf_usb_configuration_selfpowered,
          { "Self-Powered", "usb.configuration.selfpowered",
            FT_BOOLEAN, 8, TFS(&tfs_selfpowered), 0x40,
            NULL, HFILL }},

        { &hf_usb_configuration_remotewakeup,
          { "Remote Wakeup", "usb.configuration.remotewakeup",
            FT_BOOLEAN, 8, TFS(&tfs_remotewakeup), 0x20,
            NULL, HFILL }},

        { &hf_usb_bEndpointAddress_number,
          { "Endpoint Number", "usb.bEndpointAddress.number",
            FT_UINT8, BASE_HEX, NULL, 0x0f,
            NULL, HFILL }},

        { &hf_usb_bEndpointAddress_direction,
          { "Direction", "usb.bEndpointAddress.direction",
            FT_BOOLEAN, 8, TFS(&tfs_endpoint_direction), 0x80,
            NULL, HFILL }},

        { &hf_usb_request_in,
          { "Request in", "usb.request_in",
            FT_FRAMENUM, BASE_NONE,  NULL, 0,
            "The request to this packet is in this packet", HFILL }},

        { &hf_usb_time,
          { "Time from request", "usb.time",
            FT_RELATIVE_TIME, BASE_NONE,  NULL, 0,
            "Time between Request and Response for USB cmds", HFILL }},

        { &hf_usb_response_in,
          { "Response in", "usb.response_in",
            FT_FRAMENUM, BASE_NONE,  NULL, 0,
            "The response to this packet is in this packet", HFILL }},

        { &hf_usb_bFirstInterface,
          { "bFirstInterface", "usb.bFirstInterface",
            FT_UINT8, BASE_DEC,  NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bInterfaceCount,
          { "bInterfaceCount",
            "usb.bInterfaceCount", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bFunctionClass,
          { "bFunctionClass", "usb.bFunctionClass",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING,  &usb_class_vals_ext, 0x0, NULL, HFILL }},

        { &hf_usb_bFunctionSubClass,
          { "bFunctionSubClass",
            "usb.bFunctionSubClass", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_usb_bFunctionProtocol,
          { "bFunctionProtocol", "usb.bFunctionProtocol",
            FT_UINT8, BASE_HEX,  NULL, 0x0, NULL, HFILL }},

        { &hf_usb_iFunction,
          { "iFunction",
            "usb.iFunction", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_usb_data_fragment,
          { "Data Fragment",
            "usb.data_fragment", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_usb_src,
            { "Source",                              "usb.src",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usb_dst,
            { "Destination",                         "usb.dst",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usb_addr,
            { "Source or Destination",               "usb.addr",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static hf_register_info hf_usbport[] = {
        { &hf_usbport_event_id,
            { "Event ID",               "usbport.event_id",
            FT_UINT32, BASE_DEC_HEX|BASE_EXT_STRING, &netmon_event_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_device_object,
            { "Device Object",          "usbport.device_object",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_pci_bus,
            { "PCI Bus",          "usbport.pci_bus",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_pci_device,
            { "PCI Bus",          "usbport.pci_device",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_pci_function,
            { "PCI Function",          "usbport.pci_function",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_pci_vendor_id,
            { "PCI Vendor ID",          "usbport.pci_vendor_id",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_pci_device_id,
            { "PCI Device ID",          "usbport.pci_device_id",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_port_path_depth,
            { "Path Depth",          "usbport.port_path_depth",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_port_path0,
            { "Path0",          "usbport.port_path0",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_port_path1,
            { "Path1",          "usbport.port_path1",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_port_path2,
            { "Path2",          "usbport.port_path2",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_port_path3,
            { "Path3",          "usbport.port_path3",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_port_path4,
            { "Path4",          "usbport.port_path4",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_port_path5,
            { "Path5",          "usbport.port_path5",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_device_handle,
            { "Device Handle",          "usbport.device_handle",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_device_speed,
            { "Device Speed",          "usbport.device_speed",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_endpoint,
            { "Endpoint",          "usbport.endpoint",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_pipehandle,
            { "Pipe Handle",          "usbport.pipehandle",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_endpoint_desc_length,
            { "Length",          "usbport.endpoint_desc_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_endpoint_desc_type,
            { "Description Type",          "usbport.endpoint_desc_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_endpoint_address,
            { "Endpoint Address",          "usbport.endpoint_address",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_bm_attributes,
            { "bmAttributes",          "usbport.bm_attributes",
            FT_UINT8, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_max_packet_size,
            { "Max Packet Size",          "usbport.max_packet_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_interval,
            { "Interval",          "usbport.interval",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_irp,
            { "IRP",          "usbport.irp",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb,
            { "URB",          "usbport.urb",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_transfer_data,
            { "URB Transfer data",          "usbport.urb_transfer_data",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_header_length,
            { "URB Header Length",          "usbport.urb_header_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_header_function,
            { "URB Header Function",          "usbport.urb_header_function",
            FT_UINT16, BASE_DEC|BASE_EXT_STRING, &netmon_urb_function_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_header_status,
            { "URB Header Status",          "usbport.urb_header_status",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_header_usbddevice_handle,
            { "URB Header Device Handle",          "usbport.urb_header_usbddevice_handle",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_header_usbdflags,
            { "URB Header Flags",          "usbport.urb_header_usbdflags",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_configuration_desc,
            { "URB Configuration Description",          "usbport.urb_configuration_desc",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_configuration_handle,
            { "URB Configuration Handle",          "usbport.urb_configuration_handle",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_pipe_handle,
            { "URB Pipe Handle",          "usbport.urb_pipe_handle",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_xferflags,
            { "URB Transfer Flags",          "usbport.urb_xferflags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_transfer_buffer_length,
            { "URB Transfer Buffer Length",          "usbport.urb_transfer_buffer_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_transfer_buffer,
            { "URB Transfer Buffer",          "usbport.urb_transfer_buffer",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_transfer_buffer_mdl,
            { "URB Transfer Buffer MDL",          "usbport.urb_transfer_buffer_mdl",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_reserved_mbz,
            { "URB Reserved MBZ",          "usbport.urb_reserved_mbz",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_reserved_hcd,
            { "URB Reserved HCD",          "usbport.urb_reserved_hcd",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_urb_reserved,
            { "URB Reserved",          "usbport.urb_reserved",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_keyword,
            { "Keyword",          "usbport.keyword",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_usbport_keyword_diagnostic,
            { "USBPORT_ETW_KEYWORD_DIAGNOSTIC",          "usbport.keyword.diagnostic",
            FT_BOOLEAN, 64, NULL, USBPORT_KEYWORD_DIAGNOSTIC,
            NULL, HFILL }
        },
        { &hf_usbport_keyword_power_diagnostics,
            { "USBPORT_ETW_KEYWORD_POWER_DIAGNOSTICS",          "usbport.keyword.power_diagnostics",
            FT_BOOLEAN, 64, NULL, USBPORT_KEYWORD_POWER_DIAGNOSTICS,
            NULL, HFILL }
        },
        { &hf_usbport_keyword_perf_diagnostics,
            { "USBPORT_ETW_KEYWORD_PERF_DIAGNOSTICS",          "usbport.keyword.perf_diagnostics",
            FT_BOOLEAN, 64, NULL, USBPORT_KEYWORD_PERF_DIAGNOSTICS,
            NULL, HFILL }
        },
        { &hf_usbport_keyword_reserved1,
            { "Reserved1",          "usbport.keyword.reserved1",
            FT_UINT64, BASE_HEX, NULL, USBPORT_KEYWORD_RESERVED1,
            NULL, HFILL }
        },
    };

    static gint *usb_subtrees[] = {
        &ett_usb_hdr,
        &ett_usb_setup_hdr,
        &ett_usb_isodesc,
        &ett_usb_win32_iso_packet,
        &ett_usb_endpoint,
        &ett_usb_xferflags,
        &ett_usb_xferstatus,
        &ett_usb_frame,
        &ett_usb_frame_flags,
        &ett_usb_setup_bmrequesttype,
        &ett_usb_usbpcap_info,
        &ett_descriptor_device,
        &ett_configuration_bmAttributes,
        &ett_configuration_bEndpointAddress,
        &ett_endpoint_bmAttributes,
        &ett_endpoint_wMaxPacketSize,
        &ett_transfer_flags,
    };

    static gint *usbport_subtrees[] = {
        &ett_usbport,
        &ett_usbport_host_controller,
        &ett_usbport_path,
        &ett_usbport_device,
        &ett_usbport_endpoint,
        &ett_usbport_endpoint_desc,
        &ett_usbport_urb,
        &ett_usbport_keyword,
    };

    static ei_register_info ei[] = {
        { &ei_usb_undecoded, { "usb.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
        { &ei_usb_bLength_even, { "usb.bLength.even", PI_PROTOCOL, PI_WARN, "Invalid STRING DESCRIPTOR Length (must be even)", EXPFILL }},
        { &ei_usb_bLength_too_short, { "usb.bLength.too_short", PI_MALFORMED, PI_ERROR, "Invalid STRING DESCRIPTOR Length (must be 2 or larger)", EXPFILL }},
        { &ei_usb_desc_length_invalid, { "usb.desc_length.invalid", PI_MALFORMED, PI_ERROR, "Invalid descriptor length", EXPFILL }},
        { &ei_usb_invalid_setup, { "usb.setup.invalid", PI_MALFORMED, PI_ERROR, "Only control URBs may contain a setup packet", EXPFILL }},
        { &ei_usb_ss_ep_companion_before_ep, { "usb.bmAttributes.invalid_order", PI_MALFORMED, PI_ERROR, "SuperSpeed Endpoint Companion must come after Endpoint Descriptor", EXPFILL }},
        { &ei_usb_usbpcap_unknown_urb, { "usb.usbpcap.unknown_urb", PI_MALFORMED, PI_ERROR, "USBPcap did not recognize URB Function code (report to desowin.org/USBPcap)", EXPFILL }},
        { &ei_usb_bad_length, { "usb.bad_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
        { &ei_usb_invalid_max_packet_size, { "usb.wMaxPacketSize.invalid", PI_PROTOCOL, PI_WARN, "Invalid Max Packet Size", EXPFILL }},
        { &ei_usb_invalid_max_packet_size0, { "usb.bMaxPacketSize0.invalid", PI_PROTOCOL, PI_WARN, "Invalid Max Packet Size", EXPFILL }},
        { &ei_usb_invalid_endpoint_type, { "usb.bmAttributes.transfer.invalid", PI_PROTOCOL, PI_WARN, "Transfer type not allowed at Low-Speed", EXPFILL }},
    };
    static ei_register_info ei_usbport[] = {
        { &ei_usbport_invalid_path_depth, { "usbport.path_depth.invalid", PI_PROTOCOL, PI_WARN, "Invalid path depth", EXPFILL }},
    };

    expert_module_t *expert_usb, *expert_usbport;

    proto_usb = proto_register_protocol("USB", "USB", "usb");
    proto_usbport = proto_register_protocol("USBPort", "USBPort", "usbport");

    proto_register_field_array(proto_usb, hf, array_length(hf));
    proto_register_field_array(proto_usbport, hf_usbport, array_length(hf_usbport));
    proto_register_subtree_array(usb_subtrees, array_length(usb_subtrees));
    proto_register_subtree_array(usbport_subtrees, array_length(usbport_subtrees));

    expert_usb = expert_register_protocol(proto_usb);
    expert_register_field_array(expert_usb, ei, array_length(ei));
    expert_usbport = expert_register_protocol(proto_usbport);
    expert_register_field_array(expert_usbport, ei_usbport, array_length(ei_usbport));

    device_to_product_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    device_to_protocol_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    usbpcap_setup_data = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    device_to_dissector = register_dissector_table("usb.device",     "USB device",   proto_usb, FT_UINT32, BASE_HEX);
    protocol_to_dissector = register_dissector_table("usb.protocol", "USB protocol", proto_usb, FT_UINT32, BASE_HEX);
    product_to_dissector = register_dissector_table("usb.product",   "USB product",  proto_usb, FT_UINT32, BASE_HEX);

    usb_bulk_dissector_table = register_dissector_table("usb.bulk",
        "USB bulk endpoint", proto_usb, FT_UINT8, BASE_DEC);
    heur_bulk_subdissector_list = register_heur_dissector_list("usb.bulk", proto_usb);
    usb_control_dissector_table = register_dissector_table("usb.control",
        "USB control endpoint", proto_usb, FT_UINT8, BASE_DEC);
    heur_control_subdissector_list = register_heur_dissector_list("usb.control", proto_usb);
    usb_interrupt_dissector_table = register_dissector_table("usb.interrupt",
        "USB interrupt endpoint", proto_usb, FT_UINT8, BASE_DEC);
    heur_interrupt_subdissector_list = register_heur_dissector_list("usb.interrupt", proto_usb);
    usb_descriptor_dissector_table = register_dissector_table("usb.descriptor",
        "USB descriptor", proto_usb, FT_UINT8, BASE_DEC);

    usb_module = prefs_register_protocol(proto_usb, NULL);
    prefs_register_bool_preference(usb_module, "try_heuristics",
        "Try heuristic sub-dissectors",
        "Try to decode a packet using a heuristic sub-dissector before "
         "attempting to dissect the packet using the \"usb.bulk\", \"usb.interrupt\" or "
         "\"usb.control\" dissector tables.", &try_heuristics);

    usb_tap = register_tap("usb");

    register_decode_as(&usb_protocol_da);
    register_decode_as(&usb_product_da);
    register_decode_as(&usb_device_da);

    usb_address_type = address_type_dissector_register("AT_USB", "USB Address", usb_addr_to_str, usb_addr_str_len, NULL, usb_col_filter_str, NULL, NULL, NULL);

    register_conversation_table(proto_usb, TRUE, usb_conversation_packet, usb_endpoint_packet);
}

void
proto_reg_handoff_usb(void)
{
    dissector_handle_t  linux_usb_handle;
    dissector_handle_t  linux_usb_mmapped_handle;
    dissector_handle_t  win32_usb_handle;
    dissector_handle_t  freebsd_usb_handle;
    dissector_handle_t  darwin_usb_handle;
    dissector_handle_t  netmon_usb_port_handle;
    static guid_key usb_port_key = {{ 0xc88a4ef5, 0xd048, 0x4013, { 0x94, 0x08, 0xe0, 0x4b, 0x7d, 0xb2, 0x81, 0x4a }}, 0 };

    linux_usb_handle = create_dissector_handle(dissect_linux_usb, proto_usb);
    linux_usb_mmapped_handle = create_dissector_handle(dissect_linux_usb_mmapped,
                                                       proto_usb);
    win32_usb_handle = create_dissector_handle(dissect_win32_usb, proto_usb);
    freebsd_usb_handle = create_dissector_handle(dissect_freebsd_usb, proto_usb);
    darwin_usb_handle = create_dissector_handle(dissect_darwin_usb, proto_usb);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_LINUX, linux_usb_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_LINUX_MMAPPED, linux_usb_mmapped_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USBPCAP, win32_usb_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_FREEBSD, freebsd_usb_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USB_DARWIN, darwin_usb_handle);

    netmon_usb_port_handle = create_dissector_handle( dissect_netmon_usb_port, proto_usbport);
    dissector_add_guid( "netmon.provider_id", &usb_port_key, netmon_usb_port_handle);

}

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
