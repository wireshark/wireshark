/* packet-usb-video.c
 *
 * Forked from packet-usb-masstorage.c 35224 2010-12-20 05:35:29Z guy
 * which was authored by Ronnie Sahlberg (2006)
 *
 * usb video dissector
 * Steven J. Magnani 2013
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>
#include "packet-usb.h"

void proto_register_usb_vid(void);
void proto_reg_handoff_usb_vid(void);

/* References are to sections in USB Video Class specifications -
 * specifically V1.5, but versions have tended to keep
 * the same numbering (as of this writing).
 *
 * http://www.usb.org/developers/devclass_docs/USB_Video_Class_1_5.zip
 */

/* Table 2-1. Interrupt originators */
#define INT_VIDEOCONTROL               1
#define INT_VIDEOSTREAMING             2

#define INT_ORIGINATOR_MASK            0xF

/* Table 2-2. Video Control Status Packet bAttribute */
#define CONTROL_CHANGE_VALUE           0x00
#define CONTROL_CHANGE_INFO            0x01
#define CONTROL_CHANGE_FAILURE         0x02
#define CONTROL_CHANGE_MIN             0x03   /* UVC 1.5+ */
#define CONTROL_CHANGE_MAX             0x04   /* UVC 1.5+ */


/* A.2 Video Interface Subclass Codes */
#define SC_UNDEFINED                   0
#define SC_VIDEOCONTROL                1
#define SC_VIDEOSTREAMING              2
#define SC_VIDEO_INTERFACE_COLLECTION  3

/* A.4. Video Class-Specific Descriptor Types */
#define CS_INTERFACE       0x24
#define CS_ENDPOINT        0x25

/* A.5 Video Class-Specific VC Interface Descriptor Subtypes */
#define VC_HEADER           1
#define VC_INPUT_TERMINAL   2
#define VC_OUTPUT_TERMINAL  3
#define VC_SELECTOR_UNIT    4
#define VC_PROCESSING_UNIT  5
#define VC_EXTENSION_UNIT   6
#define VC_ENCODING_UNIT    7

/* A.6 Video Class-Specific VS Interface Descriptor Subtypes */
#define VS_UNDEFINED             0x00
#define VS_INPUT_HEADER          0x01
#define VS_OUTPUT_HEADER         0x02
#define VS_STILL_IMAGE_FRAME     0x03
#define VS_FORMAT_UNCOMPRESSED   0x04
#define VS_FRAME_UNCOMPRESSED    0x05
#define VS_FORMAT_MJPEG          0x06
#define VS_FRAME_MJPEG           0x07
#define VS_FORMAT_MPEG1          0x08     /* Pre-UVC 1.1 */
#define VS_FORMAT_MPEG2PS        0x09     /* Pre-UVC 1.1 */
#define VS_FORMAT_MPEG2TS        0x0A
#define VS_FORMAT_MPEG4SL        0x0B     /* Pre-UVC 1.1 */
#define VS_FORMAT_DV             0x0C
#define VS_COLORFORMAT           0x0D
#define VS_FORMAT_VENDOR         0x0E     /* Pre-UVC 1.1 */
#define VS_FRAME_VENDOR          0x0F     /* Pre-UVC 1.1 */
#define VS_FORMAT_FRAME_BASED    0x10
#define VS_FRAME_FRAME_BASED     0x11
#define VS_FORMAT_STREAM_BASED   0x12
#define VS_FORMAT_H264           0x13       /* UVC 1.5 */
#define VS_FRAME_H264            0x14       /* UVC 1.5 */
#define VS_FORMAT_H264_SIMULCAST 0x15       /* UVC 1.5 */
#define VS_FORMAT_VP8            0x16       /* UVC 1.5 */
#define VS_FRAME_VP8             0x17       /* UVC 1.5 */
#define VS_FORMAT_VP8_SIMULCAST  0x18       /* UVC 1.5 */

/* A.7 Video Class-Specific Endpoint Descriptor Subtypes */
#define EP_INTERRUPT           0x03

/* A.9.1 Video Control Interface Control Selectors */
#define VC_CONTROL_UNDEFINED                      0x00
#define VC_VIDEO_POWER_MODE_CONTROL               0x01
#define VC_REQUEST_ERROR_CODE_CONTROL             0x02
#define VC_REQUEST_INDICATE_HOST_CLOCK_CONTROL    0x03  /* Pre-UVC 1.1 */

/* A.9.3 Selector Unit Control Selectors */
#define SU_CONTROL_UNDEFINED                      0x00
#define SU_INPUT_SELECT_CONTROL                   0x01

/* A.9.4 Camera Terminal Control Selectors */
#define CT_CONTROL_UNDEFINED                      0x00
#define CT_SCANNING_MODE_CONTROL                  0x01
#define CT_AE_MODE_CONTROL                        0x02
#define CT_AE_PRIORITY_CONTROL                    0x03
#define CT_EXPOSURE_TIME_ABSOLUTE_CONTROL         0x04
#define CT_EXPOSURE_TIME_RELATIVE_CONTROL         0x05
#define CT_FOCUS_ABSOLUTE_CONTROL                 0x06
#define CT_FOCUS_RELATIVE_CONTROL                 0x07
#define CT_FOCUS_AUTO_CONTROL                     0x08
#define CT_IRIS_ABSOLUTE_CONTROL                  0x09
#define CT_IRIS_RELATIVE_CONTROL                  0x0A
#define CT_ZOOM_ABSOLUTE_CONTROL                  0x0B
#define CT_ZOOM_RELATIVE_CONTROL                  0x0C
#define CT_PANTILT_ABSOLUTE_CONTROL               0x0D
#define CT_PANTILT_RELATIVE_CONTROL               0x0E
#define CT_ROLL_ABSOLUTE_CONTROL                  0x0F
#define CT_ROLL_RELATIVE_CONTROL                  0x10
#define CT_PRIVACY_CONTROL                        0x11
#define CT_FOCUS_SIMPLE_CONTROL                   0x12  /* UVC 1.5 */
#define CT_WINDOW_CONTROL                         0x13  /* UVC 1.5 */
#define CT_REGION_OF_INTEREST_CONTROL             0x14  /* UVC 1.5 */

/* A.9.5 Processing Unit Control Selectors */
#define PU_CONTROL_UNDEFINED                      0x00
#define PU_BACKLIGHT_COMPENSATION_CONTROL         0x01
#define PU_BRIGHTNESS_CONTROL                     0x02
#define PU_CONTRAST_CONTROL                       0x03
#define PU_GAIN_CONTROL                           0x04
#define PU_POWER_LINE_FREQUENCY_CONTROL           0x05
#define PU_HUE_CONTROL                            0x06
#define PU_SATURATION_CONTROL                     0x07
#define PU_SHARPNESS_CONTROL                      0x08
#define PU_GAMMA_CONTROL                          0x09
#define PU_WHITE_BALANCE_TEMPERATURE_CONTROL      0x0A
#define PU_WHITE_BALANCE_TEMPERATURE_AUTO_CONTROL 0x0B
#define PU_WHITE_BALANCE_COMPONENT_CONTROL        0x0C
#define PU_WHITE_BALANCE_COMPONENT_AUTO_CONTROL   0x0D
#define PU_DIGITAL_MULTIPLIER_CONTROL             0x0E
#define PU_DIGITAL_MULTIPLIER_LIMIT_CONTROL       0x0F
#define PU_HUE_AUTO_CONTROL                       0x10
#define PU_ANALOG_VIDEO_STANDARD_CONTROL          0x11
#define PU_ANALOG_LOCK_STATUS_CONTROL             0x12
#define PU_CONTRAST_AUTO_CONTROL                  0x13

/* A.9.7 VideoStreaming Interface Control Selectors */
#define VS_CONTROL_UNDEFINED                      0x00
#define VS_PROBE_CONTROL                          0x01
#define VS_COMMIT_CONTROL                         0x02
#define VS_STILL_PROBE_CONTROL                    0x03
#define VS_STILL_COMMIT_CONTROL                   0x04
#define VS_STILL_IMAGE_TRIGGER_CONTROL            0x05
#define VS_STREAM_ERROR_CODE_CONTROL              0x06
#define VS_GENERATE_KEY_FRAME_CONTROL             0x07
#define VS_UPDATE_FRAME_SEGMENT_CONTROL           0x08
#define VS_SYNCH_DELAY_CONTROL                    0x09

/* Appendix B Terminal Types */
#define TT_VENDOR_SPECIFIC          0x100
#define TT_STREAMING                0x101
#define ITT_VENDOR_SPECIFIC         0x200
#define ITT_CAMERA                  0x201
#define ITT_MEDIA_TRANSPORT_INPUT   0x202
#define OTT_VENDOR_SPECIFIC         0x300
#define OTT_DISPLAY                 0x301
#define OTT_MEDIA_TRANSPORT_OUTPUT  0x302
#define EXTERNAL_VENDOR_SPECIFIC    0x400
#define COMPOSITE_CONNECTOR         0x401
#define SVIDEO_CONNECTOR            0x402
#define COMPONENT_CONNECTOR         0x403

/* Table 2-2 Status Packet Format (VideoControl Interface as the Originator) */
#define CONTROL_INTERRUPT_EVENT_CONTROL_CHANGE  0

/* Table 4-7 Request Error Code Control bRequestErrorCode */
#define UVC_ERROR_NONE              0
#define UVC_ERROR_NOT_READY         1
#define UVC_ERROR_WRONG_STATE       2
#define UVC_ERROR_POWER             3
#define UVC_ERROR_OUT_OF_RANGE      4
#define UVC_ERROR_INVALID_UNIT      5
#define UVC_ERROR_INVALID_CONTROL   6
#define UVC_ERROR_INVALID_REQUEST   7
#define UVC_ERROR_INVALID_VALUE     8
#define UVC_ERROR_UNKNOWN           255

/* A.8 Video Class-Specific Request Codes */
#define USB_SETUP_SET_CUR           0x01
#define USB_SETUP_SET_CUR_ALL       0x11    /* UVC 1.5 */
#define USB_SETUP_GET_CUR           0x81
#define USB_SETUP_GET_MIN           0x82
#define USB_SETUP_GET_MAX           0x83
#define USB_SETUP_GET_RES           0x84
#define USB_SETUP_GET_LEN           0x85
#define USB_SETUP_GET_INFO          0x86
#define USB_SETUP_GET_DEF           0x87
#define USB_SETUP_GET_CUR_ALL       0x91    /* UVC 1.5 */
#define USB_SETUP_GET_MIN_ALL       0x92    /* UVC 1.5 */
#define USB_SETUP_GET_MAX_ALL       0x93    /* UVC 1.5 */
#define USB_SETUP_GET_RES_ALL       0x94    /* UVC 1.5 */
#define USB_SETUP_GET_DEF_ALL       0x97    /* UVC 1.5 */

/* protocols and header fields */
static int proto_usb_vid = -1;

static int hf_usb_vid_control_entity    = -1;
static int hf_usb_vid_control_interface = -1;
static int hf_usb_vid_control_selector  = -1;
static int hf_usb_vid_epdesc_subtype = -1;
static int hf_usb_vid_epdesc_max_transfer_sz = -1;
static int hf_usb_vid_control_ifdesc_subtype = -1;
static int hf_usb_vid_control_ifdesc_terminal_id = -1;
static int hf_usb_vid_control_ifdesc_terminal_type = -1;
static int hf_usb_vid_control_ifdesc_assoc_terminal = -1;
static int hf_usb_vid_streaming_ifdesc_subtype = -1;
static int hf_usb_vid_streaming_ifdesc_bNumFormats = -1;
static int hf_usb_vid_control_ifdesc_unit_id = -1;
static int hf_usb_vid_request = -1;
static int hf_usb_vid_length = -1;
static int hf_usb_vid_interrupt_bStatusType = -1;
static int hf_usb_vid_interrupt_bOriginator = -1;
static int hf_usb_vid_interrupt_bAttribute = -1;
static int hf_usb_vid_control_interrupt_bEvent = -1;
static int hf_usb_vid_control_ifdesc_bcdUVC = -1;
static int hf_usb_vid_ifdesc_wTotalLength = -1;
static int hf_usb_vid_control_ifdesc_dwClockFrequency = -1;
static int hf_usb_vid_control_ifdesc_bInCollection = -1;
static int hf_usb_vid_control_ifdesc_baInterfaceNr = -1;
static int hf_usb_vid_control_ifdesc_iTerminal = -1;
static int hf_usb_vid_control_ifdesc_src_id = -1;
static int hf_usb_vid_cam_objective_focal_len_min = -1;
static int hf_usb_vid_cam_objective_focal_len_max = -1;
static int hf_usb_vid_cam_ocular_focal_len = -1;
static int hf_usb_vid_bControlSize = -1;
static int hf_usb_vid_bmControl = -1;
static int hf_usb_vid_control_default = -1;
static int hf_usb_vid_control_min = -1;
static int hf_usb_vid_control_max = -1;
static int hf_usb_vid_control_res = -1;
static int hf_usb_vid_control_cur = -1;
static int hf_usb_vid_control_info = -1;
static int hf_usb_vid_control_info_D[7]   = { -1, -1, -1, -1, -1, -1, -1 };
static int hf_usb_vid_control_length = -1;
static int hf_usb_vid_cam_control_D[22]   = { -1, -1, -1, -1, -1, -1, -1, -1,
                                              -1, -1, -1, -1, -1, -1, -1, -1,
                                              -1, -1, -1, -1, -1, -1 };
static int hf_usb_vid_proc_control_D[19]  = { -1, -1, -1, -1, -1, -1, -1, -1,
                                              -1, -1, -1, -1, -1, -1, -1, -1,
                                              -1, -1, -1 };
static int hf_usb_vid_proc_standards_D[6] = { -1, -1, -1, -1, -1, -1 };
static int hf_usb_vid_exten_guid = -1;
static int hf_usb_vid_exten_num_controls = -1;
static int hf_usb_vid_num_inputs = -1;
static int hf_usb_vid_sources = -1;
static int hf_usb_vid_streaming_bmInfo = -1;
static int hf_usb_vid_streaming_info_D[1] = { -1 };
static int hf_usb_vid_streaming_terminal_link = -1;
static int hf_usb_vid_streaming_still_capture_method = -1;
static int hf_usb_vid_streaming_trigger_support = -1;
static int hf_usb_vid_streaming_trigger_usage = -1;
static int hf_usb_vid_streaming_control_D[6] = { -1, -1, -1, -1, -1, -1 };
static int hf_usb_vid_format_index = -1;
static int hf_usb_vid_format_num_frame_descriptors = -1;
static int hf_usb_vid_format_guid = -1;
static int hf_usb_vid_format_bits_per_pixel = -1;
static int hf_usb_vid_default_frame_index = -1;
static int hf_usb_vid_aspect_ratio_x = -1;
static int hf_usb_vid_aspect_ratio_y = -1;
static int hf_usb_vid_is_interlaced = -1;
static int hf_usb_vid_interlaced_fields = -1;
static int hf_usb_vid_field_1_first = -1;
static int hf_usb_vid_field_pattern = -1;
static int hf_usb_vid_copy_protect = -1;
static int hf_usb_vid_variable_size = -1;
static int hf_usb_vid_frame_index = -1;
static int hf_usb_vid_frame_capabilities = -1;
static int hf_usb_vid_frame_stills_supported = -1;
static int hf_usb_vid_frame_fixed_frame_rate = -1;
static int hf_usb_vid_frame_width = -1;
static int hf_usb_vid_frame_height = -1;
static int hf_usb_vid_frame_min_bit_rate = -1;
static int hf_usb_vid_frame_max_bit_rate = -1;
static int hf_usb_vid_frame_max_frame_sz = -1;
static int hf_usb_vid_frame_default_interval = -1;
static int hf_usb_vid_frame_bytes_per_line = -1;
static int hf_usb_vid_mjpeg_flags = -1;
static int hf_usb_vid_mjpeg_fixed_samples = -1;
static int hf_usb_vid_probe_hint = -1;
static int hf_usb_vid_probe_hint_D[5] = { -1, -1, -1, -1, -1 };
static int hf_usb_vid_frame_interval = -1;
static int hf_usb_vid_probe_key_frame_rate = -1;
static int hf_usb_vid_probe_p_frame_rate = -1;
static int hf_usb_vid_probe_comp_quality = -1;
static int hf_usb_vid_probe_comp_window = -1;
static int hf_usb_vid_probe_delay = -1;
static int hf_usb_vid_probe_max_frame_sz = -1;
static int hf_usb_vid_probe_max_payload_sz = -1;
static int hf_usb_vid_probe_clock_freq = -1;
static int hf_usb_vid_probe_framing = -1;
static int hf_usb_vid_probe_framing_D[2] = { -1, -1 };
static int hf_usb_vid_probe_preferred_ver = -1;
static int hf_usb_vid_probe_min_ver = -1;
static int hf_usb_vid_probe_max_ver = -1;
static int hf_usb_vid_frame_interval_type = -1;
static int hf_usb_vid_frame_min_interval = -1;
static int hf_usb_vid_frame_max_interval = -1;
static int hf_usb_vid_frame_step_interval = -1;
static int hf_usb_vid_color_primaries = -1;
static int hf_usb_vid_transfer_characteristics = -1;
static int hf_usb_vid_matrix_coefficients = -1;
static int hf_usb_vid_max_multiplier = -1;
static int hf_usb_vid_iProcessing = -1;
static int hf_usb_vid_iExtension = -1;
static int hf_usb_vid_iSelector = -1;
static int hf_usb_vid_proc_standards = -1;
static int hf_usb_vid_request_error = -1;

/* Subtrees */
static gint ett_usb_vid = -1;
static gint ett_descriptor_video_endpoint = -1;
static gint ett_descriptor_video_control = -1;
static gint ett_descriptor_video_streaming = -1;
static gint ett_camera_controls = -1;
static gint ett_processing_controls = -1;
static gint ett_streaming_controls = -1;
static gint ett_streaming_info = -1;
static gint ett_interlace_flags = -1;
static gint ett_frame_capability_flags = -1;
static gint ett_mjpeg_flags = -1;
static gint ett_video_probe = -1;
static gint ett_probe_hint = -1;
static gint ett_probe_framing = -1;
static gint ett_video_standards = -1;
static gint ett_control_capabilities = -1;

static expert_field ei_usb_vid_subtype_unknown = EI_INIT;
static expert_field ei_usb_vid_bitmask_len = EI_INIT;

/* Lookup tables */
static const value_string vc_ep_descriptor_subtypes[] = {
    { EP_INTERRUPT, "Interrupt" },
    { 0, NULL }
};

static const value_string vid_descriptor_type_vals[] = {
    {CS_INTERFACE, "video class interface"},
    {CS_ENDPOINT, "video class endpoint"},
    {0,NULL}
};
static value_string_ext vid_descriptor_type_vals_ext =
    VALUE_STRING_EXT_INIT(vid_descriptor_type_vals);

static const value_string vc_if_descriptor_subtypes[] = {
    { VC_HEADER,              "Header" },
    { VC_INPUT_TERMINAL,      "Input Terminal" },
    { VC_OUTPUT_TERMINAL,     "Output Terminal" },
    { VC_SELECTOR_UNIT,       "Selector Unit" },
    { VC_PROCESSING_UNIT,     "Processing Unit" },
    { VC_EXTENSION_UNIT,      "Extension Unit" },
    { VC_ENCODING_UNIT,       "Encoding Unit" },
    { 0, NULL }
};
static value_string_ext vc_if_descriptor_subtypes_ext =
    VALUE_STRING_EXT_INIT(vc_if_descriptor_subtypes);

static const value_string cs_control_interface[] = {
    { VC_CONTROL_UNDEFINED,          "Undefined" },
    { VC_VIDEO_POWER_MODE_CONTROL,   "Video Power Mode" },
    { VC_REQUEST_ERROR_CODE_CONTROL, "Request Error Code" },
    { VC_REQUEST_INDICATE_HOST_CLOCK_CONTROL, "Request Indicate Host Clock" },
    { 0, NULL }
};
static value_string_ext cs_control_interface_ext =
    VALUE_STRING_EXT_INIT(cs_control_interface);

static const value_string cs_streaming_interface[] = {
    { VS_CONTROL_UNDEFINED,            "Undefined" },
    { VS_PROBE_CONTROL,                "Probe" },
    { VS_COMMIT_CONTROL,               "Commit" },
    { VS_STILL_PROBE_CONTROL,          "Still Probe" },
    { VS_STILL_COMMIT_CONTROL,         "Still Commit" },
    { VS_STILL_IMAGE_TRIGGER_CONTROL,  "Still Image Trigger" },
    { VS_STREAM_ERROR_CODE_CONTROL,    "Stream Error Code" },
    { VS_GENERATE_KEY_FRAME_CONTROL,   "Generate Key Frame" },
    { VS_UPDATE_FRAME_SEGMENT_CONTROL, "Update Frame Segment" },
    { VS_SYNCH_DELAY_CONTROL,          "Synch Delay" },
    { 0, NULL }
};
static value_string_ext cs_streaming_interface_ext =
    VALUE_STRING_EXT_INIT(cs_streaming_interface);

static const value_string cs_selector_unit[] = {
    { SU_CONTROL_UNDEFINED,              "Undefined" },
    { SU_INPUT_SELECT_CONTROL,           "Input Select" },
    { 0, NULL }
};
static value_string_ext cs_selector_unit_ext =
    VALUE_STRING_EXT_INIT(cs_selector_unit);

static const value_string cs_camera_terminal[] = {
    { CT_CONTROL_UNDEFINED,              "Undefined" },
    { CT_SCANNING_MODE_CONTROL,          "Scanning Mode" },
    { CT_AE_MODE_CONTROL,                "Auto-Exposure Mode" },
    { CT_AE_PRIORITY_CONTROL,            "Auto-Exposure Priority" },
    { CT_EXPOSURE_TIME_ABSOLUTE_CONTROL, "Exposure Time (Absolute)" },
    { CT_EXPOSURE_TIME_RELATIVE_CONTROL, "Exposure Time (Relative)" },
    { CT_FOCUS_ABSOLUTE_CONTROL,         "Focus (Absolute)" },
    { CT_FOCUS_RELATIVE_CONTROL,         "Focus (Relative)" },
    { CT_FOCUS_AUTO_CONTROL,             "Focus, Auto" },
    { CT_IRIS_ABSOLUTE_CONTROL,          "Iris (Absolute)" },
    { CT_IRIS_RELATIVE_CONTROL,          "Iris (Relative)" },
    { CT_ZOOM_ABSOLUTE_CONTROL,          "Zoom (Absolute)" },
    { CT_ZOOM_RELATIVE_CONTROL,          "Zoom (Relative)" },
    { CT_PANTILT_ABSOLUTE_CONTROL,       "PanTilt (Absolute)" },
    { CT_PANTILT_RELATIVE_CONTROL,       "PanTilt (Relative)" },
    { CT_ROLL_ABSOLUTE_CONTROL,          "Roll (Absolute)" },
    { CT_ROLL_RELATIVE_CONTROL,          "Roll (Relative)" },
    { CT_PRIVACY_CONTROL,                "Privacy" },
    { CT_FOCUS_SIMPLE_CONTROL,           "Focus (Simple)" },
    { CT_WINDOW_CONTROL,                 "Window" },
    { CT_REGION_OF_INTEREST_CONTROL,     "Region of Interest" },
    { 0, NULL }
};
static value_string_ext cs_camera_terminal_ext =
    VALUE_STRING_EXT_INIT(cs_camera_terminal);

static const value_string cs_processing_unit[] = {
    { PU_CONTROL_UNDEFINED,                     "Undefined" },
    { PU_BACKLIGHT_COMPENSATION_CONTROL,        "Backlight Compensation" },
    { PU_BRIGHTNESS_CONTROL,                    "Brightness" },
    { PU_CONTRAST_CONTROL,                      "Contrast" },
    { PU_GAIN_CONTROL,                          "Gain" },
    { PU_POWER_LINE_FREQUENCY_CONTROL,          "Power Line Frequency" },
    { PU_HUE_CONTROL,                           "Hue" },
    { PU_SATURATION_CONTROL,                    "Saturation" },
    { PU_SHARPNESS_CONTROL,                     "Sharpness" },
    { PU_GAMMA_CONTROL,                         "Gamma" },
    { PU_WHITE_BALANCE_TEMPERATURE_CONTROL,     "White Balance Temperature" },
    { PU_WHITE_BALANCE_TEMPERATURE_AUTO_CONTROL,"White Balance Temperature Auto" },
    { PU_WHITE_BALANCE_COMPONENT_CONTROL,       "White Balance Component" },
    { PU_WHITE_BALANCE_COMPONENT_AUTO_CONTROL,  "White Balance Component Auto" },
    { PU_DIGITAL_MULTIPLIER_CONTROL,            "Digital Multiplier" },
    { PU_DIGITAL_MULTIPLIER_LIMIT_CONTROL,      "Digital Multiplier Limit" },
    { PU_HUE_AUTO_CONTROL,                      "Hue Auto" },
    { PU_ANALOG_VIDEO_STANDARD_CONTROL,         "Video Standard" },
    { PU_ANALOG_LOCK_STATUS_CONTROL,            "Analog Lock Status" },
    { PU_CONTRAST_AUTO_CONTROL,                 "Contrast Auto" },
    { 0, NULL }
};
static value_string_ext cs_processing_unit_ext =
    VALUE_STRING_EXT_INIT(cs_processing_unit);

static const value_string vc_terminal_types[] = {
    { TT_VENDOR_SPECIFIC,         "Vendor Specific", },
    { TT_STREAMING,               "Streaming" },
    { ITT_VENDOR_SPECIFIC,        "Vendor Specific Input" },
    { ITT_CAMERA,                 "Camera Input" },
    { ITT_MEDIA_TRANSPORT_INPUT,  "Media Transport Input" },
    { OTT_VENDOR_SPECIFIC,        "Vendor Specific Output" },
    { OTT_DISPLAY,                "Display Output" },
    { OTT_MEDIA_TRANSPORT_OUTPUT, "Media Transport Output" },
    { EXTERNAL_VENDOR_SPECIFIC,   "Vendor Specific External" },
    { COMPOSITE_CONNECTOR,        "Composite Connector" },
    { SVIDEO_CONNECTOR,           "SVideo Connector" },
    { COMPONENT_CONNECTOR,        "Component Connector" },
    { 0, NULL }
};
static value_string_ext vc_terminal_types_ext =
    VALUE_STRING_EXT_INIT(vc_terminal_types);

static const value_string vs_if_descriptor_subtypes[] = {
    { VS_UNDEFINED,             "Undefined" },
    { VS_INPUT_HEADER,          "Input Header" },
    { VS_OUTPUT_HEADER,         "Output Header" },
    { VS_STILL_IMAGE_FRAME,     "Still Image Frame" },
    { VS_FORMAT_UNCOMPRESSED,   "Format Uncompressed" },
    { VS_FRAME_UNCOMPRESSED,    "Frame Uncompressed" },
    { VS_FORMAT_MJPEG,          "Format MJPEG" },
    { VS_FRAME_MJPEG,           "Frame MJPEG" },
    { VS_FORMAT_MPEG1,          "Format MPEG1" },
    { VS_FORMAT_MPEG2PS,        "Format MPEG2-PS" },
    { VS_FORMAT_MPEG2TS,        "Format MPEG2-TS" },
    { VS_FORMAT_MPEG4SL,        "Format MPEG4-SL" },
    { VS_FORMAT_DV,             "Format DV" },
    { VS_COLORFORMAT,           "Colorformat" },
    { VS_FORMAT_VENDOR,         "Format Vendor" },
    { VS_FRAME_VENDOR,          "Frame Vendor" },
    { VS_FORMAT_FRAME_BASED,    "Format Frame-Based" },
    { VS_FRAME_FRAME_BASED,     "Frame Frame-Based" },
    { VS_FORMAT_STREAM_BASED,   "Format Stream Based" },
    { VS_FORMAT_H264,           "Format H.264" },
    { VS_FRAME_H264,            "Frame H.264" },
    { VS_FORMAT_H264_SIMULCAST, "Format H.264 Simulcast" },
    { VS_FORMAT_VP8,            "Format VP8" },
    { VS_FRAME_VP8,             "Frame VP8" },
    { VS_FORMAT_VP8_SIMULCAST,  "Format VP8 Simulcast" },
    { 0, NULL }
};
static value_string_ext vs_if_descriptor_subtypes_ext =
    VALUE_STRING_EXT_INIT(vs_if_descriptor_subtypes);

static const value_string interrupt_status_types[] = {
    { INT_VIDEOCONTROL,       "VideoControl Interface"   },
    { INT_VIDEOSTREAMING,     "VideoStreaming Interface" },
    { 0, NULL }
};

static const value_string control_change_types[] = {
    { CONTROL_CHANGE_VALUE,   "Value" },
    { CONTROL_CHANGE_INFO,    "Info" },
    { CONTROL_CHANGE_FAILURE, "Failure" },
    { CONTROL_CHANGE_MIN,     "Min" },
    { CONTROL_CHANGE_MAX,     "Max" },
    { 0, NULL }
};
static value_string_ext control_change_types_ext =
    VALUE_STRING_EXT_INIT(control_change_types);

static const value_string control_interrupt_events[] = {
    { CONTROL_INTERRUPT_EVENT_CONTROL_CHANGE,  "Control Change" },
    { 0, NULL }
};

/* Table 3-13 VS Interface Input Header Descriptor - bStillCaptureMethod field */
static const value_string vs_still_capture_methods[] = {
    { 0,  "None" },
    { 1,  "Uninterrupted streaming" },
    { 2,  "Suspended streaming" },
    { 3,  "Dedicated pipe" },
    { 0, NULL }
};
static value_string_ext vs_still_capture_methods_ext =
    VALUE_STRING_EXT_INIT(vs_still_capture_methods);

/* Table 3-13 VS Interface Input Header Descriptor - bTriggerUsage field */
static const value_string vs_trigger_usage[] = {
    { 0,  "Initiate still image capture" },
    { 1,  "General purpose button event" },
    { 0, NULL }
};

/* bmInterlaceFlags for format descriptors */
static const true_false_string is_interlaced_meaning = {
    "Interlaced",
    "Non-interlaced"
};

/* bmInterlaceFlags for format descriptors */
static const true_false_string interlaced_fields_meaning = {
    "1 field",
    "2 fields"
};

/* bmInterlaceFlags for format descriptors */
static const value_string field_pattern_meaning[] = {
    { 0,  "Field 1 only" },
    { 1,  "Field 2 only" },
    { 2,  "Regular pattern of fields 1 and 2" },
    { 3,  "Random pattern of fields 1 and 2" },
    {0, NULL},
};
static value_string_ext field_pattern_meaning_ext =
    VALUE_STRING_EXT_INIT(field_pattern_meaning);

/* bCopyProtect for format descriptors */
static const value_string copy_protect_meaning[] = {
    { 0,  "No restrictions" },
    { 1,  "Restrict duplication" },
    {0, NULL},
};

/* Table 4-46 Video Probe and Commit Controls - bmHint field */
static const true_false_string probe_hint_meaning = {
    "Constant",
    "Variable"
};

/* Table 3-19 Color Matching Descriptor - bColorPrimaries field */
static const value_string color_primaries_meaning[] = {
    { 0,  "Unspecified" },
    { 1,  "BT.709, sRGB" },
    { 2,  "BT.470-2 (M)" },
    { 3,  "BT.470-2 (B,G)" },
    { 4,  "SMPTE 170M" },
    { 5,  "SMPTE 240M" },
    {0, NULL},
};
static value_string_ext color_primaries_meaning_ext =
    VALUE_STRING_EXT_INIT(color_primaries_meaning);

/* Table 3-19 Color Matching Descriptor - bTransferCharacteristics field */
static const value_string color_transfer_characteristics[] = {
    { 0,  "Unspecified" },
    { 1,  "BT.709" },
    { 2,  "BT.470-2 (M)" },
    { 3,  "BT.470-2 (B,G)" },
    { 4,  "SMPTE 170M" },
    { 5,  "SMPTE 240M" },
    { 6,  "Linear (V=Lc)" },
    { 7,  "sRGB" },
    {0, NULL},
};
static value_string_ext color_transfer_characteristics_ext =
    VALUE_STRING_EXT_INIT(color_transfer_characteristics);

/* Table 3-19 Color Matching Descriptor - bMatrixCoefficients field */
static const value_string matrix_coefficients_meaning[] = {
    { 0,  "Unspecified" },
    { 1,  "BT.709" },
    { 2,  "FCC" },
    { 3,  "BT.470-2 (B,G)" },
    { 4,  "SMPTE 170M (BT.601)" },
    { 5,  "SMPTE 240M" },
    {0, NULL},
};
static value_string_ext matrix_coefficients_meaning_ext =
    VALUE_STRING_EXT_INIT(matrix_coefficients_meaning);

static const value_string request_error_codes[] = {
    { UVC_ERROR_NONE,             "No error" },
    { UVC_ERROR_NOT_READY,        "Not ready" },
    { UVC_ERROR_WRONG_STATE,      "Wrong state" },
    { UVC_ERROR_POWER,            "Insufficient power" } ,
    { UVC_ERROR_OUT_OF_RANGE,     "Out of range" },
    { UVC_ERROR_INVALID_UNIT,     "Invalid unit" },
    { UVC_ERROR_INVALID_CONTROL,  "Invalid control" },
    { UVC_ERROR_INVALID_REQUEST,  "Invalid request" },
    { UVC_ERROR_INVALID_VALUE,    "Invalid value within range" },
    { UVC_ERROR_UNKNOWN,          "Unknown" },
    {0, NULL},
};
static value_string_ext request_error_codes_ext =
    VALUE_STRING_EXT_INIT(request_error_codes);

/* There is one such structure per terminal or unit per interface */
typedef struct
{
    guint8  entityID;
    guint8  subtype;
    guint16 terminalType;
} video_entity_t;

/* video_entity_t's (units/terminals) associated with each video interface */
/* There is one such structure for each video conversation (interface) */
typedef struct _video_conv_info_t {
    wmem_tree_t* entities;      /* indexed by entity ID */
} video_conv_info_t;

/*****************************************************************************/
/*                            UTILITY FUNCTIONS                              */
/*****************************************************************************/

/**
 * Dissector for variable-length bmControl bitmask / bControlSize pair.
 *
 * Creates an item for bControlSize, and a subtree for the bmControl bitmask.
 *
 * @param tree            protocol tree to be the parent of the bitmask subtree
 * @param tvb             the tv_buff with the (remaining) packet data
 * @param offset          where in tvb to find bControlSize field
 * @param ett_subtree     index of the subtree to use for this bitmask
 * @param bm_items        NULL-terminated array of pointers that lists all the fields
 *                        of the bitmask
 *
 * @return   offset within tvb at which dissection should continue
 */
static int
dissect_bmControl(proto_tree *tree, tvbuff_t *tvb, int offset,
                  gint ett_subtree, const int** bm_items)
{
    guint8 bm_size = 0;

    bm_size = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_vid_bControlSize, tvb, offset, 1, ENC_NA);
    ++offset;

    if (bm_size > 0)
    {
        proto_tree_add_bitmask_len(tree, tvb, offset, bm_size, hf_usb_vid_bmControl,
                                   ett_subtree, bm_items, &ei_usb_vid_bitmask_len, ENC_LITTLE_ENDIAN);
        offset += bm_size;
    }

    return offset;
}

/*****************************************************************************/
/*                          VIDEO CONTROL DESCRIPTORS                        */
/*****************************************************************************/

/* Dissect a Camera Terminal descriptor */
static int
dissect_usb_video_camera_terminal(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    static const int *control_bits[] = {
        &hf_usb_vid_cam_control_D[0],
        &hf_usb_vid_cam_control_D[1],
        &hf_usb_vid_cam_control_D[2],
        &hf_usb_vid_cam_control_D[3],
        &hf_usb_vid_cam_control_D[4],
        &hf_usb_vid_cam_control_D[5],
        &hf_usb_vid_cam_control_D[6],
        &hf_usb_vid_cam_control_D[7],
        &hf_usb_vid_cam_control_D[8],
        &hf_usb_vid_cam_control_D[9],
        &hf_usb_vid_cam_control_D[10],
        &hf_usb_vid_cam_control_D[11],
        &hf_usb_vid_cam_control_D[12],
        &hf_usb_vid_cam_control_D[13],
        &hf_usb_vid_cam_control_D[14],
        &hf_usb_vid_cam_control_D[15],
        &hf_usb_vid_cam_control_D[16],
        &hf_usb_vid_cam_control_D[17],
        &hf_usb_vid_cam_control_D[18],
        &hf_usb_vid_cam_control_D[19],
        &hf_usb_vid_cam_control_D[20],
        &hf_usb_vid_cam_control_D[21],
        NULL
    };

    DISSECTOR_ASSERT(array_length(control_bits) == (1+array_length(hf_usb_vid_cam_control_D)));

    proto_tree_add_item(tree, hf_usb_vid_cam_objective_focal_len_min,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_vid_cam_objective_focal_len_max,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_usb_vid_cam_ocular_focal_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    offset = dissect_bmControl(tree, tvb, offset, ett_camera_controls, control_bits);

    return offset;
}

/* Dissect a Processing Unit descriptor */
static int
dissect_usb_video_processing_unit(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    static const int *control_bits[] = {
        &hf_usb_vid_proc_control_D[0],
        &hf_usb_vid_proc_control_D[1],
        &hf_usb_vid_proc_control_D[2],
        &hf_usb_vid_proc_control_D[3],
        &hf_usb_vid_proc_control_D[4],
        &hf_usb_vid_proc_control_D[5],
        &hf_usb_vid_proc_control_D[6],
        &hf_usb_vid_proc_control_D[7],
        &hf_usb_vid_proc_control_D[8],
        &hf_usb_vid_proc_control_D[9],
        &hf_usb_vid_proc_control_D[10],
        &hf_usb_vid_proc_control_D[11],
        &hf_usb_vid_proc_control_D[12],
        &hf_usb_vid_proc_control_D[13],
        &hf_usb_vid_proc_control_D[14],
        &hf_usb_vid_proc_control_D[15],
        &hf_usb_vid_proc_control_D[16],
        &hf_usb_vid_proc_control_D[17],
        &hf_usb_vid_proc_control_D[18],
        NULL
    };

    DISSECTOR_ASSERT(array_length(control_bits) == (1+array_length(hf_usb_vid_proc_control_D)));

    proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_src_id, tvb, offset,   1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_max_multiplier,        tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
    offset += 3;

    offset = dissect_bmControl(tree, tvb, offset, ett_processing_controls, control_bits);

    proto_tree_add_item(tree, hf_usb_vid_iProcessing, tvb, offset, 1, ENC_NA);
    ++offset;

    /* UVC 1.1 added bmVideoStandards */
    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        static const int *standard_bits[] = {
            &hf_usb_vid_proc_standards_D[0],
            &hf_usb_vid_proc_standards_D[1],
            &hf_usb_vid_proc_standards_D[2],
            &hf_usb_vid_proc_standards_D[3],
            &hf_usb_vid_proc_standards_D[4],
            &hf_usb_vid_proc_standards_D[5],
            NULL
        };

        DISSECTOR_ASSERT(array_length(standard_bits) == (1+array_length(hf_usb_vid_proc_standards_D)));

        proto_tree_add_bitmask(tree, tvb, offset, hf_usb_vid_proc_standards,
                               ett_video_standards, standard_bits, ENC_NA);
        ++offset;
    }

    return offset;
}

/* Dissect a Selector Unit descriptor */
static int
dissect_usb_video_selector_unit(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint8 num_inputs;

    num_inputs = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_vid_num_inputs, tvb, offset, 1, ENC_NA);
    ++offset;

    if (num_inputs > 0)
    {
        proto_tree_add_item(tree, hf_usb_vid_sources, tvb, offset, num_inputs, ENC_NA);
        offset += num_inputs;
    }

    proto_tree_add_item(tree, hf_usb_vid_iSelector, tvb, offset, 1, ENC_NA);
    ++offset;

    return offset;
}

/* Dissect an Extension Unit descriptor */
static int
dissect_usb_video_extension_unit(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint8 num_inputs;
    guint8 control_size;

    proto_tree_add_item(tree, hf_usb_vid_exten_guid,         tvb, offset,    16, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_exten_num_controls, tvb, offset+16,  1, ENC_NA);
    offset += 17;

    num_inputs = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_vid_num_inputs,   tvb, offset,  1, ENC_NA);
    ++offset;

    if (num_inputs > 0)
    {
        proto_tree_add_item(tree, hf_usb_vid_sources, tvb, offset, num_inputs, ENC_NA);
        offset += num_inputs;
    }

    control_size = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_vid_bControlSize, tvb, offset, 1, ENC_NA);
    ++offset;

    if (control_size > 0)
    {
        if (control_size <= proto_registrar_get_length(hf_usb_vid_bmControl))
        {
            proto_tree_add_item(tree, hf_usb_vid_bmControl, tvb, offset, control_size,
                                ENC_LITTLE_ENDIAN);
        }
        else
        {
            /* Too big to display as integer */
            /* @todo Display as FT_BYTES with a big-endian disclaimer?
             * See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7933
             */
            proto_tree_add_text(tree, tvb, offset, control_size, "bmControl");
        }
        offset += control_size;
    }

    proto_tree_add_item(tree, hf_usb_vid_iExtension, tvb, offset, 1, ENC_NA);
    ++offset;

    return offset;
}

/**
 * Dissector for video class control interface descriptors
 *
 * @param parent_tree     the protocol tree to be the parent of the descriptor subtree
 * @param tvb             the tv_buff with the (remaining) packet data
 *                        On entry the gaze is set to the descriptor length field.
 * @param descriptor_len  Length of the descriptor to dissect
 * @param pinfo           Information associated with the packet being dissected
 *
 * @return   offset within tvb at which dissection should continue
 */
static int
dissect_usb_video_control_interface_descriptor(proto_tree *parent_tree, tvbuff_t *tvb,
                                               guint8 descriptor_len, packet_info *pinfo, usb_conv_info_t *usb_conv_info)
{
    video_conv_info_t *video_conv_info = NULL;
    video_entity_t    *entity          = NULL;
    proto_item *item          = NULL;
    proto_item *subtype_item  = NULL;
    proto_tree *tree          = NULL;
    guint8      entity_id     = 0;
    guint16     terminal_type = 0;
    int         offset        = 0;
    guint8      subtype;

    subtype = tvb_get_guint8(tvb, offset+2);

    if (parent_tree)
    {
        const gchar *subtype_str;

        subtype_str = val_to_str_ext(subtype, &vc_if_descriptor_subtypes_ext, "Unknown (0x%x)");

        item = proto_tree_add_text(parent_tree, tvb, offset, descriptor_len,
                                   "VIDEO CONTROL INTERFACE DESCRIPTOR [%s]",
                                   subtype_str);
        tree = proto_item_add_subtree(item, ett_descriptor_video_control);
    }

    /* Common fields */
    dissect_usb_descriptor_header(tree, tvb, offset, &vid_descriptor_type_vals_ext);
    subtype_item = proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_subtype, tvb, offset+2, 1, ENC_NA);
    offset += 3;

    if (subtype == VC_HEADER)
    {
        guint8 num_vs_interfaces;

        proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_bcdUVC,            tvb, offset,   2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_vid_ifdesc_wTotalLength,              tvb, offset+2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_dwClockFrequency,  tvb, offset+4, 4, ENC_LITTLE_ENDIAN);

        num_vs_interfaces = tvb_get_guint8(tvb, offset+8);
        proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_bInCollection,     tvb, offset+8, 1, ENC_LITTLE_ENDIAN);

        if (num_vs_interfaces > 0)
        {
            proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_baInterfaceNr, tvb, offset+9, num_vs_interfaces, ENC_NA);
        }

        offset += 9 + num_vs_interfaces;
    }
    else if ((subtype == VC_INPUT_TERMINAL) || (subtype == VC_OUTPUT_TERMINAL))
    {
        /* Fields common to input and output terminals */
        entity_id     = tvb_get_guint8(tvb, offset);
        terminal_type = tvb_get_letohs(tvb, offset+1);

        proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_terminal_id,    tvb, offset,   1, ENC_NA);
        proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_terminal_type,  tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_assoc_terminal, tvb, offset+3, 1, ENC_NA);
        offset += 4;

        if (subtype == VC_OUTPUT_TERMINAL)
        {
            proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_src_id, tvb, offset, 1, ENC_NA);
            ++offset;
        }

        proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_iTerminal, tvb, offset, 1, ENC_NA);
        ++offset;

        if (subtype == VC_INPUT_TERMINAL)
        {
            if (terminal_type == ITT_CAMERA)
            {
                offset = dissect_usb_video_camera_terminal(tree, tvb, offset);
            }
            else if (terminal_type == ITT_MEDIA_TRANSPORT_INPUT)
            {
                /* @todo */
            }
        }

        if (subtype == VC_OUTPUT_TERMINAL)
        {
            if (terminal_type == OTT_MEDIA_TRANSPORT_OUTPUT)
            {
                /* @todo */
            }
        }
    }
    else
    {
        /* Field common to extension / processing / selector / encoding units */
        entity_id = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_usb_vid_control_ifdesc_unit_id, tvb, offset, 1, ENC_NA);
        ++offset;

        if (subtype == VC_PROCESSING_UNIT)
        {
            offset = dissect_usb_video_processing_unit(tree, tvb, offset);
        }
        else if (subtype == VC_SELECTOR_UNIT)
        {
            offset = dissect_usb_video_selector_unit(tree, tvb, offset);
        }
        else if (subtype == VC_EXTENSION_UNIT)
        {
            offset = dissect_usb_video_extension_unit(tree, tvb, offset);
        }
        else if (subtype == VC_ENCODING_UNIT)
        {
            /* @todo UVC 1.5 */
        }
        else
        {
            expert_add_info_format(pinfo, subtype_item, &ei_usb_vid_subtype_unknown,
                                   "Unknown VC subtype %u", subtype);
        }
    }

    /* Soak up descriptor bytes beyond those we know how to dissect */
    if (offset < descriptor_len)
    {
        proto_tree_add_text(tree, tvb, offset, descriptor_len-offset, "Descriptor data");
        /* offset = descriptor_len; */
    }

    if (entity_id != 0)
        proto_item_append_text(item, " (Entity %d)", entity_id);

    if (subtype != VC_HEADER && usb_conv_info)
    {
        /* Switch to the usb_conv_info of the Video Control interface */
        usb_conv_info = get_usb_iface_conv_info(pinfo, usb_conv_info->interfaceNum);
        video_conv_info = (video_conv_info_t *)usb_conv_info->class_data;

        if (!video_conv_info)
        {
            video_conv_info = wmem_new(wmem_file_scope(), video_conv_info_t);
            video_conv_info->entities = wmem_tree_new(wmem_file_scope());
            usb_conv_info->class_data = video_conv_info;
        }

        entity = (video_entity_t*) wmem_tree_lookup32(video_conv_info->entities, entity_id);
        if (!entity)
        {
            entity = wmem_new(wmem_file_scope(), video_entity_t);
            entity->entityID     = entity_id;
            entity->subtype      = subtype;
            entity->terminalType = terminal_type;

            wmem_tree_insert32(video_conv_info->entities, entity_id, entity);
        }
    }

    return descriptor_len;
}

/*****************************************************************************/
/*                        VIDEO STREAMING DESCRIPTORS                        */
/*****************************************************************************/

/* Dissect a Video Streaming Input Header descriptor */
static int
dissect_usb_video_streaming_input_header(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint8 num_formats;
    guint8 bm_size;

    static const int *info_bits[] = {
        &hf_usb_vid_streaming_info_D[0],
        NULL
    };
    static const int *control_bits[] = {
        &hf_usb_vid_streaming_control_D[0],
        &hf_usb_vid_streaming_control_D[1],
        &hf_usb_vid_streaming_control_D[2],
        &hf_usb_vid_streaming_control_D[3],
        &hf_usb_vid_streaming_control_D[4],
        &hf_usb_vid_streaming_control_D[5],
        NULL
    };

    DISSECTOR_ASSERT(array_length(control_bits) == (1+array_length(hf_usb_vid_streaming_control_D)));

    num_formats = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_vid_streaming_ifdesc_bNumFormats, tvb, offset,   1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_ifdesc_wTotalLength,          tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
    offset += 3;

    dissect_usb_endpoint_address(tree, tvb, offset);
    offset++;

    proto_tree_add_bitmask(tree, tvb, offset, hf_usb_vid_streaming_bmInfo,
                           ett_streaming_info, info_bits, ENC_NA);

    proto_tree_add_item(tree, hf_usb_vid_streaming_terminal_link,        tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_streaming_still_capture_method, tvb, offset+2, 1, ENC_NA);
    offset += 3;

    proto_tree_add_item(tree, hf_usb_vid_streaming_trigger_support,      tvb, offset,   1, ENC_NA);
    if (tvb_get_guint8(tvb, offset) > 0)
    {
        proto_tree_add_item(tree, hf_usb_vid_streaming_trigger_usage,    tvb, offset+1, 1, ENC_NA);
    }
    else
    {
        proto_tree_add_text(tree, tvb, offset+1, 1, "bTriggerUsage: Not applicable");
    }

    offset += 2;

    /* NOTE: Can't use dissect_bmControl here because there's only one size
     *       field for (potentially) multiple bmControl fields
     */
    bm_size = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_vid_bControlSize, tvb, offset, 1, ENC_NA);
    ++offset;

    if (bm_size > 0)
    {
        guint8 i;
        for (i=0; i<num_formats; ++i)
        {
            proto_tree_add_bitmask_len(tree, tvb, offset, bm_size, hf_usb_vid_bmControl,
                                       ett_streaming_controls, control_bits, &ei_usb_vid_bitmask_len,
                                       ENC_LITTLE_ENDIAN);
            offset += bm_size;
        }
    }

    return offset;
}

/**
 * Dissect a known Video Payload Format descriptor.
 *
 * @param tree     protocol tree to which fields should be added
 * @param tvb      the tv_buff with the (remaining) packet data
 * @param offset   where in tvb to begin dissection.
 *                 On entry this refers to the bFormatIndex field.
 * @param subtype  Type of format descriptor, from the
 *                 bDescriptorSubtype field
 *
 * @return   offset within tvb at which dissection should continue
 */
static int
dissect_usb_video_format(proto_tree *tree, tvbuff_t *tvb, int offset,
                         guint8 subtype)
{
    static const int *interlace_bits[] = {
        &hf_usb_vid_is_interlaced,
        &hf_usb_vid_interlaced_fields,
        &hf_usb_vid_field_1_first,
        &hf_usb_vid_field_pattern,
        NULL
    };

    proto_item *desc_item;
    guint8 format_index;

    /* Augment the descriptor root item with the index of this descriptor */
    format_index = tvb_get_guint8(tvb, offset);
    desc_item = proto_tree_get_parent(tree);
    proto_item_append_text(desc_item, "  (Format %u)", format_index);

    proto_tree_add_item(tree, hf_usb_vid_format_index,                  tvb, offset,    1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_format_num_frame_descriptors,  tvb, offset+1,  1, ENC_NA);
    offset += 2;

    if ((subtype == VS_FORMAT_UNCOMPRESSED) || (subtype == VS_FORMAT_FRAME_BASED))
    {
        /* Augment the descriptor root item with the format's four-character-code */
        char fourcc[5];
        tvb_memcpy(tvb, (guint8 *)fourcc, offset, 4);
        fourcc[4] = '\0';
        proto_item_append_text(desc_item, ": %s", fourcc);

        proto_tree_add_item(tree, hf_usb_vid_format_guid, tvb, offset,   16, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_vid_format_bits_per_pixel,        tvb, offset+16, 1, ENC_NA);
        offset += 17;
    }
    else if (subtype == VS_FORMAT_MJPEG)
    {
        proto_item *flags_item = NULL;
        proto_tree *flags_tree = NULL;
        guint8 bmFlags;

        flags_item = proto_tree_add_item(tree, hf_usb_vid_mjpeg_flags, tvb, offset, 1, ENC_NA);
        flags_tree = proto_item_add_subtree(flags_item, ett_mjpeg_flags);

        bmFlags = tvb_get_guint8(tvb, offset);

        proto_tree_add_boolean(flags_tree, hf_usb_vid_mjpeg_fixed_samples, tvb, offset, 1, bmFlags);
        offset++;
    }
    else
    {
        /* We should only be called for known format descriptor subtypes */
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    proto_tree_add_item(tree, hf_usb_vid_default_frame_index, tvb, offset,   1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_aspect_ratio_x,      tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_aspect_ratio_y,      tvb, offset+2, 1, ENC_NA);
    offset += 3;

#if 0
    /* @todo Display "N/A" if Camera Terminal does not support scanning mode control */
    if (something)
        proto_tree_add_text(tree, tvb, offset, 1, "bmInterlaceFlags: Not applicable");
#endif

    proto_tree_add_bitmask_text(tree, tvb, offset, 1, "bmInterlaceFlags", NULL,
                                ett_interlace_flags, interlace_bits, ENC_NA,
                                BMT_NO_APPEND);
    offset++;

    proto_tree_add_item(tree, hf_usb_vid_copy_protect, tvb, offset, 1, ENC_NA);
    offset++;

    if (subtype == VS_FORMAT_FRAME_BASED)
    {
        proto_tree_add_item(tree, hf_usb_vid_variable_size, tvb, offset, 1, ENC_NA);
        offset++;
    }

    return offset;
}

/**
 * Dissect a known Video Frame descriptor.
 *
 * @param tree     protocol tree to which fields should be added
 * @param tvb      the tv_buff with the (remaining) packet data
 * @param offset   where in tvb to begin dissection.
 *                 On entry this refers to the bFrameIndex field.
 * @param subtype  Type of frame descriptor, from the
 *                 bDescriptorSubtype field
 *
 * @return   offset within tvb at which dissection should continue
 */
static int
dissect_usb_video_frame(proto_tree *tree, tvbuff_t *tvb, int offset,
                        guint8 subtype)
{
    static const int *capability_bits[] = {
        &hf_usb_vid_frame_stills_supported,
        &hf_usb_vid_frame_fixed_frame_rate,
        NULL
    };
    proto_item *desc_item;
    guint8      bFrameIntervalType;
    guint8      frame_index;
    guint16     frame_width;
    guint16     frame_height;

    frame_index = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_usb_vid_frame_index, tvb, offset, 1, ENC_NA);
    offset++;

    proto_tree_add_bitmask(tree, tvb, offset, hf_usb_vid_frame_capabilities,
                           ett_frame_capability_flags, capability_bits, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_usb_vid_frame_width,        tvb, offset,    2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_frame_height,       tvb, offset+2,  2, ENC_LITTLE_ENDIAN);

    /* Augment the descriptor root item with useful information */
    frame_width = tvb_get_letohs(tvb, offset);
    frame_height = tvb_get_letohs(tvb, offset+2);
    desc_item = proto_tree_get_parent(tree);
    proto_item_append_text(desc_item, "   (Index %2u): %4u x %4u", frame_index, frame_width, frame_height);

    proto_tree_add_item(tree, hf_usb_vid_frame_min_bit_rate, tvb, offset+4,  4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_frame_max_bit_rate, tvb, offset+8,  4, ENC_LITTLE_ENDIAN);
    offset += 12;

    if (subtype != VS_FRAME_FRAME_BASED)
    {
        proto_tree_add_item(tree, hf_usb_vid_frame_max_frame_sz, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    proto_tree_add_item(tree, hf_usb_vid_frame_default_interval, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    bFrameIntervalType = tvb_get_guint8(tvb, offset);
    if (bFrameIntervalType == 0)
    {
        proto_tree_add_uint_format_value(tree, hf_usb_vid_frame_interval_type, tvb, offset, 1,
                                         bFrameIntervalType, "Continuous (0)");
        offset++;

        if (subtype == VS_FRAME_FRAME_BASED)
        {
            proto_tree_add_item(tree, hf_usb_vid_frame_bytes_per_line, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        proto_tree_add_item(tree, hf_usb_vid_frame_min_interval,  tvb, offset,   4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_vid_frame_max_interval,  tvb, offset+4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_vid_frame_step_interval, tvb, offset+8, 4, ENC_LITTLE_ENDIAN);
        offset += 12;
    }
    else
    {
        guint8 i;
        proto_tree_add_uint_format_value(tree, hf_usb_vid_frame_interval_type, tvb, offset, 1,
                                         bFrameIntervalType, "Discrete (%u choice%s)",
                                         bFrameIntervalType, (bFrameIntervalType > 1) ? "s" : "");
        offset++;

        if (subtype == VS_FRAME_FRAME_BASED)
        {
            proto_tree_add_item(tree, hf_usb_vid_frame_bytes_per_line, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }

        for (i=0; i<bFrameIntervalType; ++i)
        {
            proto_tree_add_item(tree, hf_usb_vid_frame_interval,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
    }

    return offset;
}

/* Dissect a Color Matching descriptor */
static int
dissect_usb_video_colorformat(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(tree, hf_usb_vid_color_primaries,          tvb, offset,   1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_transfer_characteristics, tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_matrix_coefficients,      tvb, offset+2, 1, ENC_NA);
    offset +=3;

    return offset;
}

/**
 * Dissector for video class streaming interface descriptors.
 *
 * @param parent_tree     the protocol tree to be the parent of the descriptor subtree
 * @param tvb             the tv_buff with the (remaining) packet data
 *                        On entry the gaze is set to the descriptor length field.
 * @param descriptor_len  Length of the descriptor to dissect
 *
 * @return   offset within tvb at which dissection should continue
 */
static int
dissect_usb_video_streaming_interface_descriptor(proto_tree *parent_tree, tvbuff_t *tvb,
                                                 guint8 descriptor_len)
{
    proto_item  *item;
    proto_tree  *tree;
    int          offset = 0;
    const gchar *subtype_str;
    guint8       subtype;

    subtype = tvb_get_guint8(tvb, offset+2);

    subtype_str = val_to_str_ext(subtype, &vs_if_descriptor_subtypes_ext, "Unknown (0x%x)");
    item = proto_tree_add_text(parent_tree, tvb, offset, descriptor_len,
            "VIDEO STREAMING INTERFACE DESCRIPTOR [%s]",
            subtype_str);
    tree = proto_item_add_subtree(item, ett_descriptor_video_streaming);

    dissect_usb_descriptor_header(tree, tvb, offset, &vid_descriptor_type_vals_ext);
    proto_tree_add_item(tree, hf_usb_vid_streaming_ifdesc_subtype, tvb, offset+2, 1, ENC_NA);
    offset += 3;

    switch (subtype)
    {
        case VS_INPUT_HEADER:
            offset = dissect_usb_video_streaming_input_header(tree, tvb, offset);
            break;

        case VS_FORMAT_UNCOMPRESSED:
        case VS_FORMAT_MJPEG:
        case VS_FORMAT_FRAME_BASED:
            offset = dissect_usb_video_format(tree, tvb, offset, subtype);
            break;

        /* @todo MPEG2, H.264, VP8, Still Image Frame */
        /* @todo Obsolete UVC-1.0 descriptors? */

        case VS_FRAME_UNCOMPRESSED:
        case VS_FRAME_MJPEG:
        case VS_FRAME_FRAME_BASED:
            offset = dissect_usb_video_frame(tree, tvb, offset, subtype);
            break;

        case VS_COLORFORMAT:
            offset = dissect_usb_video_colorformat(tree, tvb, offset);
            break;

        default:
            break;
    }

    /* Soak up descriptor bytes beyond those we know how to dissect */
    if (offset < descriptor_len)
        proto_tree_add_text(tree, tvb, offset, descriptor_len-offset, "Descriptor data");

    return descriptor_len;
}

/*****************************************************************************/

/**
 * Dissector for video class-specific endpoint descriptor.
 *
 * @param parent_tree     the protocol tree to be the parent of the descriptor subtree
 * @param tvb             the tv_buff with the (remaining) packet data
 *                        On entry the gaze is set to the descriptor length field.
 * @param descriptor_len  Length of the descriptor to dissect
 *
 * @return   offset within tvb at which dissection should continue
 */
static int
dissect_usb_video_endpoint_descriptor(proto_tree *parent_tree, tvbuff_t *tvb,
                                      guint8 descriptor_len)
{
    proto_item *item   = NULL;
    proto_tree *tree   = NULL;
    int         offset = 0;
    guint8      subtype;

    subtype = tvb_get_guint8(tvb, offset+2);

    if (parent_tree)
    {
        const gchar* subtype_str;

        subtype_str = val_to_str(subtype, vc_ep_descriptor_subtypes, "Unknown (0x%x)");
        item = proto_tree_add_text(parent_tree, tvb, offset, descriptor_len,
                "VIDEO CONTROL ENDPOINT DESCRIPTOR [%s]",
                subtype_str);
        tree = proto_item_add_subtree(item, ett_descriptor_video_endpoint);
    }

    dissect_usb_descriptor_header(tree, tvb, offset, &vid_descriptor_type_vals_ext);
    proto_tree_add_item(tree, hf_usb_vid_epdesc_subtype, tvb, offset+2, 1, ENC_NA);
    offset += 3;

    if (subtype == EP_INTERRUPT)
    {
        proto_tree_add_item(tree, hf_usb_vid_epdesc_max_transfer_sz, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    /* Soak up descriptor bytes beyond those we know how to dissect */
    if (offset < descriptor_len)
        proto_tree_add_text(tree, tvb, offset, descriptor_len-offset, "Descriptor data");

    return descriptor_len;
}

/**
 * Registered dissector for video class-specific descriptors
 *
 * @param tvb    the tv_buff with the (remaining) packet data
 *               On entry the gaze is set to the descriptor length field.
 * @param pinfo  the packet info of this packet (additional info)
 * @param tree   the protocol tree to be built or NULL
 * @param data   Not used
 *
 * @return   0   no class specific dissector was found
 * @return  <0   not enough data
 * @return  >0   amount of data in the descriptor
 */
static int
dissect_usb_vid_descriptor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int    offset = 0;
    guint8 descriptor_len;
    guint8 descriptor_type;
    gint   bytes_available;
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *)data;

    tvbuff_t         *desc_tvb;

    descriptor_len  = tvb_get_guint8(tvb, offset);
    descriptor_type = tvb_get_guint8(tvb, offset+1);

    bytes_available = tvb_length_remaining(tvb, offset);
    desc_tvb = tvb_new_subset(tvb, 0, bytes_available, descriptor_len);

    if (descriptor_type == CS_ENDPOINT)
    {
        offset = dissect_usb_video_endpoint_descriptor(tree, desc_tvb,
                                                       descriptor_len);
    }
    else if (descriptor_type == CS_INTERFACE)
    {
        if (usb_conv_info && usb_conv_info->interfaceSubclass == SC_VIDEOCONTROL)
        {
            offset = dissect_usb_video_control_interface_descriptor(tree, desc_tvb,
                                                                    descriptor_len,
                                                                    pinfo, usb_conv_info);
        }
        else if (usb_conv_info && usb_conv_info->interfaceSubclass == SC_VIDEOSTREAMING)
        {
            offset = dissect_usb_video_streaming_interface_descriptor(tree, desc_tvb,
                                                                      descriptor_len);
        }
    }
    /* else not something we recognize, just return offset = 0 */

    return offset;
}

/*****************************************************************************/
/*                            CONTROL TRANSFERS                              */
/*****************************************************************************/

/**
 * Dissect GET/SET transactions on the Video Probe and Commit controls.
 *
 * @param  parent_tree  protocol tree to which the probe/commit subtree should be added
 * @param  tvb          the tv_buff with the (remaining) packet data
 * @param  offset       where in tvb to begin dissection.
 *                      On entry this refers to the probe/commit bmHint field.
 *
 * @return offset within tvb at which dissection should continue
 */
static int
dissect_usb_vid_probe(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
    proto_tree *tree = NULL;

    static const int *hint_bits[] = {
        &hf_usb_vid_probe_hint_D[0],
        &hf_usb_vid_probe_hint_D[1],
        &hf_usb_vid_probe_hint_D[2],
        &hf_usb_vid_probe_hint_D[3],
        &hf_usb_vid_probe_hint_D[4],
        NULL
    };

    DISSECTOR_ASSERT(array_length(hint_bits) == (1+array_length(hf_usb_vid_probe_hint_D)));

    if (parent_tree)
    {
        proto_item *item;

        item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Probe/Commit Info");
        tree = proto_item_add_subtree(item, ett_video_probe);
    }

    proto_tree_add_bitmask(tree, tvb, offset, hf_usb_vid_probe_hint,
                           ett_probe_hint, hint_bits, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(tree, hf_usb_vid_format_index,         tvb, offset+2,  1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_frame_index,          tvb, offset+3,  1, ENC_NA);
    proto_tree_add_item(tree, hf_usb_vid_frame_interval,       tvb, offset+4,  4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_probe_key_frame_rate, tvb, offset+8,  2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_probe_p_frame_rate,   tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_probe_comp_quality,   tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_probe_comp_window,    tvb, offset+14, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_probe_delay,          tvb, offset+16, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_probe_max_frame_sz,   tvb, offset+18, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_usb_vid_probe_max_payload_sz, tvb, offset+22, 4, ENC_LITTLE_ENDIAN);
    offset += 26;

    /* UVC 1.1 fields */
    if (tvb_length_remaining(tvb, offset) > 0)
    {
        static const int *framing_bits[] = {
            &hf_usb_vid_probe_framing_D[0],
            &hf_usb_vid_probe_framing_D[1],
            NULL
        };

        DISSECTOR_ASSERT(array_length(framing_bits) == (1+array_length(hf_usb_vid_probe_framing_D)));

        proto_tree_add_item(tree, hf_usb_vid_probe_clock_freq,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_bitmask(tree, tvb, offset, hf_usb_vid_probe_framing,
                               ett_probe_framing, framing_bits, ENC_NA);
        offset++;

        proto_tree_add_item(tree, hf_usb_vid_probe_preferred_ver, tvb, offset,   1, ENC_NA);
        proto_tree_add_item(tree, hf_usb_vid_probe_min_ver,       tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(tree, hf_usb_vid_probe_max_ver,       tvb, offset+2, 1, ENC_NA);
        offset += 3;
    }

    return offset;
}

/**
 * Fetch the table that describes known control selectors for the specified unit/terminal.
 *
 * @param  entity_id      Unit or terminal of interest
 * @param  usb_conv_info  Information about the interface the entity is part of
 *
 * @return Table describing control selectors for the specified entity (may be NULL)
 */
static const value_string_ext*
get_control_selector_values(guint8 entity_id, usb_conv_info_t *usb_conv_info)
{
    video_conv_info_t      *video_conv_info;
    video_entity_t         *entity = NULL;
    const value_string_ext *selectors = NULL;

    if (usb_conv_info == NULL)
        return NULL;

    video_conv_info = (video_conv_info_t *)usb_conv_info->class_data;
    if (video_conv_info)
        entity = (video_entity_t*) wmem_tree_lookup32(video_conv_info->entities, entity_id);

    if (entity_id == 0)
    {
        /* Interface Request*/
        switch (usb_conv_info->interfaceSubclass)
        {
            case SC_VIDEOCONTROL:
                selectors = &cs_control_interface_ext;
                break;

            case SC_VIDEOSTREAMING:
                selectors = &cs_streaming_interface_ext;
                break;

            default:
                break;
        }
    }
    else if (entity)
    {
        switch (entity->subtype)
        {
            case VC_INPUT_TERMINAL:
                if (entity->terminalType == ITT_CAMERA)
                {
                    selectors = &cs_camera_terminal_ext;
                }
                break;

            case VC_PROCESSING_UNIT:
                selectors = &cs_processing_unit_ext;
                break;

            case VC_SELECTOR_UNIT:
                selectors = &cs_selector_unit_ext;
                break;

            default:
                break;
        }
    }

    return selectors;
}

/**
 * Fetch the name of an entity's control.
 *
 * @param  entity_id      Unit or terminal of interest
 * @param  control_sel    Control of interest
 * @param  usb_conv_info  Information about the interface the entity is part of
 *
 * @return Table describing control selectors for the specified entity (may be NULL)
 */
static const gchar*
get_control_selector_name(guint8 entity_id, guint8 control_sel, usb_conv_info_t *usb_conv_info)
{
    const gchar            *control_name = NULL;
    const value_string_ext *selectors    = NULL;

    selectors = get_control_selector_values(entity_id, usb_conv_info);

    if (selectors)
        control_name = try_val_to_str_ext(control_sel, selectors);

    return control_name;
}

/* Dissect the response to a GET INFO request */
static int
dissect_usb_vid_control_info(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    static const int *capability_bits[] = {
        &hf_usb_vid_control_info_D[0],
        &hf_usb_vid_control_info_D[1],
        &hf_usb_vid_control_info_D[2],
        &hf_usb_vid_control_info_D[3],
        &hf_usb_vid_control_info_D[4],
        &hf_usb_vid_control_info_D[5],
        &hf_usb_vid_control_info_D[6],
        NULL
    };

    DISSECTOR_ASSERT(array_length(capability_bits) == (1+array_length(hf_usb_vid_control_info_D)));

    proto_tree_add_bitmask(tree, tvb, offset, hf_usb_vid_control_info,
                           ett_control_capabilities, capability_bits, ENC_NA);

    return offset+1;
}

/* Dissect all remaining bytes in the tvb as a specified type of UVC value.
 * These are displayed as an unsigned integer where possible, otherwise just as
 * a text item.
 *
 * @param tree     the protocol tree to which an item will be added
 * @param tvb      the tv_buff with the (remaining) packet data
 * @param offset   How far into tvb the value data begins
 * @param request  Identifies type of value - either bRequest from a CONTROL
 *                 transfer (i.e., USB_SETUP_GET_MAX), or bValue from an
 *                 INTERRUPT transfer (i.e., CONTROL_CHANGE_MAX).
 */
static void
dissect_usb_vid_control_value(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 request)
{
    gint        value_size;
    const char *fallback_name;
    int         hf;

    switch (request)
    {
        case USB_SETUP_GET_DEF:
            hf = hf_usb_vid_control_default;
            fallback_name = "Default Value";
            break;

        case USB_SETUP_GET_MIN:
        case CONTROL_CHANGE_MIN:
            hf = hf_usb_vid_control_min;
            fallback_name = "Min Value";
            break;

        case USB_SETUP_GET_MAX:
        case CONTROL_CHANGE_MAX:
            hf = hf_usb_vid_control_max;
            fallback_name = "Max Value";
            break;

        case USB_SETUP_GET_RES:
            hf = hf_usb_vid_control_res;
            fallback_name = "Resolution";
            break;

        case USB_SETUP_GET_CUR:
        case USB_SETUP_SET_CUR:
        case CONTROL_CHANGE_VALUE:
            hf = hf_usb_vid_control_cur;
            fallback_name = "Current Value";
            break;

        /* @todo UVC 1.5 USB_SETUP_x_ALL?
         *       They are poorly specified.
         */

        default:
            hf = -1;
            fallback_name = "Value";
            break;
    }

    value_size = tvb_reported_length_remaining(tvb, offset);

    if (hf != -1)
    {
        header_field_info *hfinfo;
        hfinfo = proto_registrar_get_nth(hf);
        DISSECTOR_ASSERT(IS_FT_INT(hfinfo->type) || IS_FT_UINT(hfinfo->type));
    }

    if ((hf != -1) && (value_size <= 4))
    {
        proto_tree_add_item(tree, hf, tvb, offset, value_size, ENC_LITTLE_ENDIAN);
    }
    else
    {
        /* @todo Display as FT_BYTES with a big-endian disclaimer?
         * See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7933
         */
        proto_tree_add_text(tree, tvb, offset, value_size, "%s", fallback_name);
    }
}

/**
 * Dissect video class GET/SET transactions.
 *
 * @param  pinfo           Information associated with the packet being dissected
 * @param  tree            protocol tree to which fields should be added
 * @param  tvb             the tv_buff with the (remaining) packet data
 * @param  offset          where in tvb to begin dissection.
 *                         On entry this refers to the bRequest field of the SETUP
 *                         transaction.
 * @param  is_request      true if the packet is host-to-device,
 *                         false if device-to-host
 * @param  usb_trans_info  Information specific to this request/response pair
 * @param  usb_conv_info   Information about the conversation with the host
 */
static int
dissect_usb_vid_get_set(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                        int offset, gboolean is_request,
                        usb_trans_info_t *usb_trans_info,
                        usb_conv_info_t *usb_conv_info)
{
    const gchar *short_name = NULL;
    guint8       control_sel;
    guint8       entity_id;

    entity_id   = usb_trans_info->setup.wIndex >> 8;
    control_sel = usb_trans_info->setup.wValue >> 8;

    /* Display something informative in the INFO column */
    col_append_str(pinfo->cinfo, COL_INFO, " [");
    short_name = get_control_selector_name(entity_id, control_sel, usb_conv_info);

    if (short_name)
        col_append_str(pinfo->cinfo, COL_INFO, short_name);
    else
    {
        short_name = "Unknown";

        if (entity_id == 0)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Interface %u control 0x%x",
                            usb_conv_info->interfaceNum, control_sel);
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Unit %u control 0x%x",
                            entity_id, control_sel);
        }
    }

    col_append_str(pinfo->cinfo, COL_INFO, "]");
    col_set_fence(pinfo->cinfo, COL_INFO);

    /* Add information on request context,
     * as GENERATED fields if not directly available (for filtering)
     */
    if (is_request)
    {
        /* Move gaze to control selector (MSB of wValue) */
        offset++;
        proto_tree_add_uint_format_value(tree, hf_usb_vid_control_selector, tvb,
                                     offset, 1, control_sel, "%s (0x%02x)", short_name, control_sel);
        offset++;

        proto_tree_add_item(tree, hf_usb_vid_control_interface, tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(tree, hf_usb_vid_control_entity, tvb, offset, 1, ENC_NA);
        offset++;

        proto_tree_add_item(tree, hf_usb_vid_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* If there is an extended pseudo header, skip over it to reach the payload */
        if ((usb_trans_info->setup.request == USB_SETUP_SET_CUR) && (usb_trans_info->header_info & USB_HEADER_IS_64_BYTES))
            offset += 16;
    }
    else
    {
        proto_item *ti;

        ti = proto_tree_add_uint(tree, hf_usb_vid_control_interface, tvb, 0, 0,
                                 usb_trans_info->setup.wIndex & 0xFF);
        PROTO_ITEM_SET_GENERATED(ti);

        ti = proto_tree_add_uint(tree, hf_usb_vid_control_entity, tvb, 0, 0, entity_id);
        PROTO_ITEM_SET_GENERATED(ti);

        ti = proto_tree_add_uint_format_value(tree, hf_usb_vid_control_selector, tvb,
                                     0, 0, control_sel, "%s (0x%02x)", short_name, control_sel);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    if (!is_request || (usb_trans_info->setup.request == USB_SETUP_SET_CUR))
    {
        gint value_size = tvb_reported_length_remaining(tvb, offset);

        if (value_size != 0)
        {
            if ((entity_id == 0) && (usb_conv_info->interfaceSubclass == SC_VIDEOSTREAMING))
            {
                if ((control_sel == VS_PROBE_CONTROL) || (control_sel == VS_COMMIT_CONTROL))
                {
                    int old_offset = offset;
                    offset = dissect_usb_vid_probe(tree, tvb, offset);
                    value_size -= (offset - old_offset);
                }
            }
            else
            {
                if (usb_trans_info->setup.request == USB_SETUP_GET_INFO)
                {
                    dissect_usb_vid_control_info(tree, tvb, offset);
                    offset++;
                    value_size--;
                }
                else if (usb_trans_info->setup.request == USB_SETUP_GET_LEN)
                {
                    proto_tree_add_item(tree, hf_usb_vid_control_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    value_size -= 2;
                }
                else if (   (usb_trans_info->setup.request == USB_SETUP_GET_CUR)
                         && (entity_id == 0)
                         && (usb_conv_info->interfaceSubclass == SC_VIDEOCONTROL)
                         && (control_sel == VC_REQUEST_ERROR_CODE_CONTROL))
                {
                    proto_tree_add_item(tree, hf_usb_vid_request_error, tvb, offset, 1, ENC_NA);
                    offset++;
                    value_size--;
                }
                else
                {
                    dissect_usb_vid_control_value(tree, tvb, offset, usb_trans_info->setup.request);
                    offset += value_size;
                    value_size = 0;
                }
            }

            if (value_size > 0)
            {
                proto_tree_add_text(tree, tvb, offset, -1, "Control data");
                offset += value_size;
            }
        }
    }

    return offset;
}

/* Table for dispatch of video class SETUP transactions based on bRequest.
 * At the moment this is overkill since the same function handles all defined
 * requests.
 */
typedef int (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree,
        tvbuff_t *tvb, int offset,
        gboolean is_request,
        usb_trans_info_t *usb_trans_info,
        usb_conv_info_t *usb_conv_info);

typedef struct _usb_setup_dissector_table_t
{
    guint8 request;
    usb_setup_dissector dissector;
} usb_setup_dissector_table_t;

static const usb_setup_dissector_table_t setup_dissectors[] = {
        {USB_SETUP_SET_CUR,      dissect_usb_vid_get_set},
        {USB_SETUP_SET_CUR_ALL,  dissect_usb_vid_get_set},
        {USB_SETUP_GET_CUR,      dissect_usb_vid_get_set},
        {USB_SETUP_GET_MIN,      dissect_usb_vid_get_set},
        {USB_SETUP_GET_MAX,      dissect_usb_vid_get_set},
        {USB_SETUP_GET_RES,      dissect_usb_vid_get_set},
        {USB_SETUP_GET_LEN,      dissect_usb_vid_get_set},
        {USB_SETUP_GET_INFO,     dissect_usb_vid_get_set},
        {USB_SETUP_GET_DEF,      dissect_usb_vid_get_set},
        {USB_SETUP_GET_CUR_ALL,  dissect_usb_vid_get_set},
        {USB_SETUP_GET_MIN_ALL,  dissect_usb_vid_get_set},
        {USB_SETUP_GET_MAX_ALL,  dissect_usb_vid_get_set},
        {USB_SETUP_GET_RES_ALL,  dissect_usb_vid_get_set},
        {0, NULL}
};

static const value_string setup_request_names_vals[] = {
        {USB_SETUP_SET_CUR,      "SET CUR"},
        {USB_SETUP_SET_CUR_ALL,  "SET CUR ALL"},
        {USB_SETUP_GET_CUR,      "GET CUR"},
        {USB_SETUP_GET_MIN,      "GET MIN"},
        {USB_SETUP_GET_MAX,      "GET MAX"},
        {USB_SETUP_GET_RES,      "GET RES"},
        {USB_SETUP_GET_LEN,      "GET LEN"},
        {USB_SETUP_GET_INFO,     "GET INFO"},
        {USB_SETUP_GET_DEF,      "GET DEF"},
        {USB_SETUP_GET_CUR_ALL,  "GET CUR ALL"},
        {USB_SETUP_GET_MIN_ALL,  "GET MIN ALL"},
        {USB_SETUP_GET_MAX_ALL,  "GET MAX ALL"},
        {USB_SETUP_GET_RES_ALL,  "GET RES ALL"},
        {USB_SETUP_GET_DEF_ALL,  "GET DEF ALL"},
        {0, NULL}
};

/* Registered dissector for video class-specific control requests.
 * Dispatch to an appropriate dissector function.
 *
 * @param tvb    the tv_buff with the (remaining) packet data.
 *               On entry, the gaze is set to SETUP bRequest field.
 * @param pinfo  the packet info of this packet (additional info)
 * @param tree   the protocol tree to be built or NULL
 * @param data   Not used
 *
 * @return   0   no class specific dissector was found
 * @return  <0   not enough data
 * @return  >0   amount of data in the descriptor
 */
static int
dissect_usb_vid_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gboolean             is_request = (pinfo->srcport == NO_ENDPOINT);
    usb_conv_info_t     *usb_conv_info;
    usb_trans_info_t    *usb_trans_info;
    int                  offset     = 0;
    usb_setup_dissector  dissector  = NULL;
    const usb_setup_dissector_table_t *tmp;

    /* Reject the packet if data or usb_trans_info are NULL */
    if (data == NULL || ((usb_conv_info_t *)data)->usb_trans_info == NULL)
        return 0;
    usb_conv_info = (usb_conv_info_t *)data;
    usb_trans_info = usb_conv_info->usb_trans_info;

    /* See if we can find a class specific dissector for this request */
    for (tmp=setup_dissectors; tmp->dissector; tmp++)
    {
        if (tmp->request == usb_trans_info->setup.request)
        {
            dissector = tmp->dissector;
            break;
        }
    }
    /* No we could not find any class specific dissector for this request
     * return FALSE and let USB try any of the standard requests.
     */
    if (!dissector)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBVIDEO");
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                val_to_str(usb_trans_info->setup.request, setup_request_names_vals, "Unknown type %x"),
                is_request?"Request ":"Response");

    if (is_request)
    {
        proto_tree_add_item(tree, hf_usb_vid_request, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    offset = dissector(pinfo, tree, tvb, offset, is_request, usb_trans_info, usb_conv_info);
    return offset;
}

/* Registered dissector for video class-specific URB_INTERRUPT
 *
 * @param tvb    the tv_buff with the (remaining) packet data
 * @param pinfo  the packet info of this packet (additional info)
 * @param tree   the protocol tree to be built or NULL
 * @param data   Unused API parameter
 *
 * @return   0   no class specific dissector was found
 * @return  <0   not enough data
 * @return  >0   amount of data in the descriptor
 */
static int
dissect_usb_vid_interrupt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    usb_conv_info_t *usb_conv_info;
    gint bytes_available;
    int  offset = 0;

    usb_conv_info   = (usb_conv_info_t *)data;
    bytes_available = tvb_length_remaining(tvb, offset);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBVIDEO");

    if (bytes_available > 0)
    {
        guint8 originating_interface;
        guint8 originating_entity;

        originating_interface = tvb_get_guint8(tvb, offset) & INT_ORIGINATOR_MASK;
        proto_tree_add_item(tree, hf_usb_vid_interrupt_bStatusType, tvb, offset, 1, ENC_NA);
        offset++;

        originating_entity = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_usb_vid_interrupt_bOriginator, tvb, offset, 1, ENC_NA);
        offset++;

        if (originating_interface == INT_VIDEOCONTROL)
        {
            guint8 control_sel;
            guint8 attribute;
            const gchar *control_name;

            proto_tree_add_item(tree, hf_usb_vid_control_interrupt_bEvent, tvb, offset, 1, ENC_NA);
            offset++;

            control_sel = tvb_get_guint8(tvb, offset);
            control_name = get_control_selector_name(originating_entity, control_sel, usb_conv_info);
            if (!control_name)
                control_name = "Unknown";

            proto_tree_add_uint_format_value(tree, hf_usb_vid_control_selector, tvb,
                                             offset, 1, control_sel, "%s (0x%02x)",
                                             control_name, control_sel);
            offset++;

            attribute = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_usb_vid_interrupt_bAttribute, tvb, offset, 1, ENC_NA);
            offset++;

            switch (attribute)
            {
                case CONTROL_CHANGE_FAILURE:
                    proto_tree_add_item(tree, hf_usb_vid_request_error, tvb, offset, 1, ENC_NA);
                    offset++;
                    break;

                case CONTROL_CHANGE_INFO:
                    offset = dissect_usb_vid_control_info(tree, tvb, offset);
                    break;

                case CONTROL_CHANGE_VALUE:
                case CONTROL_CHANGE_MIN:
                case CONTROL_CHANGE_MAX:
                    dissect_usb_vid_control_value(tree, tvb, offset, attribute);
                    offset += tvb_reported_length_remaining(tvb, offset);
                    break;

                default:
                    proto_tree_add_text(tree, tvb, offset, -1, "Value data");
                    offset += tvb_reported_length_remaining(tvb, offset);
                    break;
            }
        }
        else if (originating_interface == INT_VIDEOSTREAMING)
        {
            /* @todo */
        }
    }
    else
        offset = -2;

    return offset;
}

void
proto_register_usb_vid(void)
{
    static hf_register_info hf[] = {
        /***** Setup *****/
            { &hf_usb_vid_request,
                    { "bRequest", "usbvideo.setup.bRequest", FT_UINT8, BASE_HEX, VALS(setup_request_names_vals), 0x0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_length,
                    { "wLength", "usbvideo.setup.wLength", FT_UINT16, BASE_DEC, NULL, 0x0,
                            NULL, HFILL }
            },

        /***** Request Error Control *****/
            { &hf_usb_vid_request_error,
                    { "bRequestErrorCode", "usbvideo.reqerror.code",
                            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                            &request_error_codes_ext, 0,
                            "Request Error Code", HFILL }
            },

        /***** Unit/Terminal Controls *****/
            { &hf_usb_vid_control_selector,
                    { "Control Selector", "usbvideo.control.selector", FT_UINT8, BASE_HEX, NULL, 0x0,
                            "ID of the control within its entity", HFILL }
            },

            { &hf_usb_vid_control_entity,
                    { "Entity", "usbvideo.control.entity", FT_UINT8, BASE_HEX, NULL, 0x0,
                            "Unit or terminal to which the control belongs", HFILL }
            },

            { &hf_usb_vid_control_interface,
                    { "Interface", "usbvideo.control.interface", FT_UINT8, BASE_HEX, NULL, 0x0,
                            "Interface to which the control belongs", HFILL }
            },

            { &hf_usb_vid_control_info,
                    { "Info (Capabilities/State)", "usbvideo.control.info",
                            FT_UINT8, BASE_HEX, NULL, 0,
                            "Control capabilities and current state", HFILL }
            },

            { &hf_usb_vid_control_info_D[0],
                    { "Supports GET", "usbvideo.control.info.D0",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<0),
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_info_D[1],
                    { "Supports SET", "usbvideo.control.info.D1",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<1),
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_info_D[2],
                    { "Disabled due to automatic mode", "usbvideo.control.info.D2",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<2),
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_info_D[3],
                    { "Autoupdate", "usbvideo.control.info.D3",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<3),
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_info_D[4],
                    { "Asynchronous", "usbvideo.control.info.D4",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<4),
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_info_D[5],
                    { "Disabled due to incompatibility with Commit state", "usbvideo.control.info.D5",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<5),
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_info_D[6],
                    { "Reserved", "usbvideo.control.info.D6",
                            FT_UINT8, BASE_HEX, NULL, (3<<6),
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_length,
                    { "Control Length", "usbvideo.control.len",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Control size in bytes", HFILL }
            },

            { &hf_usb_vid_control_default,
                    { "Default value", "usbvideo.control.value.default",
                            FT_UINT32, BASE_DEC_HEX, NULL, 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_min,
                    { "Minimum value", "usbvideo.control.value.min",
                            FT_UINT32, BASE_DEC_HEX, NULL, 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_max,
                    { "Maximum value", "usbvideo.control.value.max",
                            FT_UINT32, BASE_DEC_HEX, NULL, 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_res,
                    { "Resolution", "usbvideo.control.value.res",
                            FT_UINT32, BASE_DEC_HEX, NULL, 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_cur,
                    { "Current value", "usbvideo.control.value.cur",
                            FT_UINT32, BASE_DEC_HEX, NULL, 0,
                            NULL, HFILL }
            },

        /***** Terminal Descriptors *****/

            /* @todo Decide whether to unify .name fields */
            { &hf_usb_vid_control_ifdesc_iTerminal,
                    { "iTerminal", "usbvideo.terminal.name", FT_UINT8, BASE_DEC, NULL, 0x0,
                            "String Descriptor describing this terminal", HFILL }
            },

            /* @todo Decide whether to unify .terminal.id and .unit.id under .entityID */
            { &hf_usb_vid_control_ifdesc_terminal_id,
                    { "bTerminalID", "usbvideo.terminal.id", FT_UINT8, BASE_DEC, NULL, 0x0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_ifdesc_terminal_type,
                    { "wTerminalType", "usbvideo.terminal.type",
                            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &vc_terminal_types_ext, 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_control_ifdesc_assoc_terminal,
                    { "bAssocTerminal", "usbvideo.terminal.assocTerminal", FT_UINT8, BASE_DEC, NULL, 0x0,
                            "Associated Terminal", HFILL }
            },

        /***** Camera Terminal Descriptor *****/

            { &hf_usb_vid_cam_objective_focal_len_min,
                    { "wObjectiveFocalLengthMin", "usbvideo.camera.objectiveFocalLengthMin",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Minimum Focal Length for Optical Zoom", HFILL }
            },

            { &hf_usb_vid_cam_objective_focal_len_max,
                    { "wObjectiveFocalLengthMax", "usbvideo.camera.objectiveFocalLengthMax",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Minimum Focal Length for Optical Zoom", HFILL }
            },

            { &hf_usb_vid_cam_ocular_focal_len,
                    { "wOcularFocalLength", "usbvideo.camera.ocularFocalLength",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Ocular Focal Length for Optical Zoom", HFILL }
            },

            { &hf_usb_vid_cam_control_D[0],
                    { "Scanning Mode", "usbvideo.camera.control.D0",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<0),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[1],
                    { "Auto Exposure Mode", "usbvideo.camera.control.D1",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<1),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[2],
                    { "Auto Exposure Priority", "usbvideo.camera.control.D2",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<2),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[3],
                    { "Exposure Time (Absolute)", "usbvideo.camera.control.D3",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<3),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[4],
                    { "Exposure Time (Relative)", "usbvideo.camera.control.D4",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<4),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[5],
                    { "Focus (Absolute)", "usbvideo.camera.control.D5",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<5),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[6],
                    { "Focus (Relative)", "usbvideo.camera.control.D6",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<6),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[7],
                    { "Iris (Absolute)", "usbvideo.camera.control.D7",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<7),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[8],
                    { "Iris (Relative)", "usbvideo.camera.control.D8",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<8),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[9],
                    { "Zoom (Absolute)", "usbvideo.camera.control.D9",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<9),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[10],
                    { "Zoom (Relative)", "usbvideo.camera.control.D10",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<10),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[11],
                    { "PanTilt (Absolute)", "usbvideo.camera.control.D11",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<11),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[12],
                    { "PanTilt (Relative)", "usbvideo.camera.control.D12",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<12),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[13],
                    { "Roll (Absolute)", "usbvideo.camera.control.D13",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<13),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[14],
                    { "Roll (Relative)", "usbvideo.camera.control.D14",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<14),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[15],
                    { "D15", "usbvideo.camera.control.D15",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<15),
                            "Reserved", HFILL }
            },

            { &hf_usb_vid_cam_control_D[16],
                    { "D16", "usbvideo.camera.control.D16",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<16),
                            "Reserved", HFILL }
            },

            { &hf_usb_vid_cam_control_D[17],
                    { "Auto Focus", "usbvideo.camera.control.D17",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<17),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[18],
                    { "Privacy", "usbvideo.camera.control.D18",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<18),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[19],
                    { "Focus (Simple)", "usbvideo.camera.control.D19",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<19),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[20],
                    { "Window", "usbvideo.camera.control.D20",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<20),
                            NULL, HFILL }
            },

            { &hf_usb_vid_cam_control_D[21],
                    { "Region of Interest", "usbvideo.camera.control.D21",
                            FT_BOOLEAN,
                            array_length(hf_usb_vid_cam_control_D),
                            TFS(&tfs_yes_no), (1<<21),
                            NULL, HFILL }
            },

        /***** Unit Descriptors *****/

            { &hf_usb_vid_control_ifdesc_unit_id,
                    { "bUnitID", "usbvideo.unit.id", FT_UINT8, BASE_DEC, NULL, 0x0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_num_inputs,
                    { "bNrInPins", "usbvideo.unit.numInputs",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Number of input pins", HFILL }
            },

            { &hf_usb_vid_sources,
                    { "baSourceID", "usbvideo.unit.sources",
                            FT_BYTES, BASE_NONE, NULL, 0,
                            "Input entity IDs", HFILL }
            },


        /***** Processing Unit Descriptor *****/

            { &hf_usb_vid_iProcessing,
                    { "iProcessing", "usbvideo.processor.name", FT_UINT8, BASE_DEC, NULL, 0x0,
                            "String Descriptor describing this terminal", HFILL }
            },

            { &hf_usb_vid_proc_control_D[0],
                    { "Brightness", "usbvideo.processor.control.D0",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<0),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[1],
                    { "Contrast", "usbvideo.processor.control.D1",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<1),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[2],
                    { "Hue", "usbvideo.processor.control.D2",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<2),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[3],
                    { "Saturation", "usbvideo.processor.control.D3",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<3),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[4],
                    { "Sharpness", "usbvideo.processor.control.D4",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<4),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[5],
                    { "Gamma", "usbvideo.processor.control.D5",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<5),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[6],
                    { "White Balance Temperature", "usbvideo.processor.control.D6",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<6),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[7],
                    { "White Balance Component", "usbvideo.processor.control.D7",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<7),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[8],
                    { "Backlight Compensation", "usbvideo.processor.control.D8",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<8),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[9],
                    { "Gain", "usbvideo.processor.control.D9",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<9),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[10],
                    { "Power Line Frequency", "usbvideo.processor.control.D10",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<10),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[11],
                    { "Hue, Auto", "usbvideo.processor.control.D11",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<11),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[12],
                    { "White Balance Temperature, Auto", "usbvideo.processor.control.D12",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<12),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[13],
                    { "White Balance Component, Auto", "usbvideo.processor.control.D13",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<13),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[14],
                    { "Digital Multiplier", "usbvideo.processor.control.D14",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<14),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[15],
                    { "Digital Multiplier Limit", "usbvideo.processor.control.D15",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<15),
                            "Reserved", HFILL }
            },

            { &hf_usb_vid_proc_control_D[16],
                    { "Analog Video Standard", "usbvideo.processor.control.D16",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<16),
                            "Reserved", HFILL }
            },

            { &hf_usb_vid_proc_control_D[17],
                    { "Analog Video Lock Status", "usbvideo.processor.control.D17",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<17),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_control_D[18],
                    { "Contrast, Auto", "usbvideo.processor.control.D18",
                            FT_BOOLEAN, 24, TFS(&tfs_yes_no), (1<<18),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_standards,
                    { "bmVideoStandards", "usbvideo.processor.standards",
                            FT_UINT8, BASE_HEX, NULL, 0,
                            "Supported analog video standards", HFILL }
            },

            { &hf_usb_vid_proc_standards_D[0],
                    { "None", "usbvideo.processor.standards.D0",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<0),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_standards_D[1],
                    { "NTSC - 525/60", "usbvideo.processor.standards.D1",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<1),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_standards_D[2],
                    { "PAL - 625/50", "usbvideo.processor.standards.D2",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<2),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_standards_D[3],
                    { "SECAM - 625/50", "usbvideo.processor.standards.D3",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<3),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_standards_D[4],
                    { "NTSC - 625/50", "usbvideo.processor.standards.D4",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<4),
                            NULL, HFILL }
            },

            { &hf_usb_vid_proc_standards_D[5],
                    { "PAL - 525/60", "usbvideo.processor.standards.D5",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<5),
                            NULL, HFILL }
            },

            { &hf_usb_vid_max_multiplier,
                    { "wMaxMultiplier", "usbvideo.processor.maxMultiplier",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "100 x max digital multiplication", HFILL }
            },

        /***** Selector Unit Descriptor *****/

            { &hf_usb_vid_iSelector,
                    { "iSelector", "usbvideo.selector.name", FT_UINT8, BASE_DEC, NULL, 0x0,
                            "String Descriptor describing this terminal", HFILL }
            },

        /***** Extension Unit Descriptor *****/

            { &hf_usb_vid_iExtension,
                    { "iExtension", "usbvideo.extension.name", FT_UINT8, BASE_DEC, NULL, 0x0,
                            "String Descriptor describing this terminal", HFILL }
            },

            { &hf_usb_vid_exten_guid,
                    { "guid", "usbvideo.extension.guid",
                            FT_GUID, BASE_NONE, NULL, 0,
                            "Identifier", HFILL }
            },

            { &hf_usb_vid_exten_num_controls,
                    { "bNumControls", "usbvideo.extension.numControls",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Number of controls", HFILL }
            },

        /***** Probe/Commit *****/

            { &hf_usb_vid_probe_hint,
                    { "bmHint", "usbvideo.probe.hint",
                            FT_UINT16, BASE_HEX, NULL, 0,
                            "Fields to hold constant during negotiation", HFILL }
            },

            { &hf_usb_vid_probe_hint_D[0],
                    { "dwFrameInterval", "usbvideo.probe.hint.D0",
                            FT_BOOLEAN, 5, TFS(&probe_hint_meaning), (1<<0),
                            "Frame Rate", HFILL }
            },
            { &hf_usb_vid_probe_hint_D[1],
                    { "wKeyFrameRate", "usbvideo.probe.hint.D1",
                            FT_BOOLEAN, 5, TFS(&probe_hint_meaning), (1<<1),
                            "Key Frame Rate", HFILL }
            },
            { &hf_usb_vid_probe_hint_D[2],
                    { "wPFrameRate", "usbvideo.probe.hint.D2",
                            FT_BOOLEAN, 5, TFS(&probe_hint_meaning), (1<<2),
                            "P-Frame Rate", HFILL }
            },
            { &hf_usb_vid_probe_hint_D[3],
                    { "wCompQuality", "usbvideo.probe.hint.D3",
                            FT_BOOLEAN, 5, TFS(&probe_hint_meaning), (1<<3),
                            "Compression Quality", HFILL }
            },
            { &hf_usb_vid_probe_hint_D[4],
                    { "wCompWindowSize", "usbvideo.probe.hint.D4",
                            FT_BOOLEAN, 5, TFS(&probe_hint_meaning), (1<<4),
                            "Compression Window Size", HFILL }
            },

            { &hf_usb_vid_probe_key_frame_rate,
                    { "wKeyFrameRate", "usbvideo.probe.keyFrameRate",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Key frame rate", HFILL }
            },

            { &hf_usb_vid_probe_p_frame_rate,
                    { "wPFrameRate", "usbvideo.probe.pFrameRate",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "P frame rate", HFILL }
            },

            { &hf_usb_vid_probe_comp_quality,
                    { "wCompQuality", "usbvideo.probe.compQuality",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Compression quality [0-10000]", HFILL }
            },

            { &hf_usb_vid_probe_comp_window,
                    { "wCompWindow", "usbvideo.probe.compWindow",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Window size for average bit rate control", HFILL }
            },
            { &hf_usb_vid_probe_delay,
                    { "wDelay", "usbvideo.probe.delay",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Latency in ms from capture to USB", HFILL }
            },
            { &hf_usb_vid_probe_max_frame_sz,
                    { "dwMaxVideoFrameSize", "usbvideo.probe.maxVideoFrameSize",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            NULL, HFILL }
            },
            { &hf_usb_vid_probe_max_payload_sz,
                    { "dwMaxPayloadTransferSize", "usbvideo.probe.maxPayloadTransferSize",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            NULL, HFILL }
            },
            { &hf_usb_vid_probe_clock_freq,
                    { "dwClockFrequency", "usbvideo.probe.clockFrequency",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Device clock frequency in Hz", HFILL }
            },

            { &hf_usb_vid_probe_framing,
                    { "bmFramingInfo", "usbvideo.probe.framing",
                            FT_UINT16, BASE_HEX, NULL, 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_probe_framing_D[0],
                    { "Frame ID required", "usbvideo.probe.framing.D0",
                            FT_BOOLEAN, 2, TFS(&tfs_yes_no), (1<<0),
                            NULL, HFILL }
            },
            { &hf_usb_vid_probe_framing_D[1],
                    { "EOF utilized", "usbvideo.probe.framing.D1",
                            FT_BOOLEAN, 2, TFS(&tfs_yes_no), (1<<1),
                            NULL, HFILL }
            },

            { &hf_usb_vid_probe_preferred_ver,
                    { "bPreferredVersion", "usbvideo.probe.preferredVersion",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Preferred payload format version", HFILL }
            },
            { &hf_usb_vid_probe_min_ver,
                    { "bMinVersion", "usbvideo.probe.minVersion",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Min supported payload format version", HFILL }
            },
            { &hf_usb_vid_probe_max_ver,
                    { "bPreferredVersion", "usbvideo.probe.maxVer",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Max supported payload format version", HFILL }
            },

            { &hf_usb_vid_control_ifdesc_dwClockFrequency,
                    { "dwClockFrequency", "usbvideo.probe.clockFrequency",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Device clock frequency (Hz) for selected format", HFILL }
            },

        /***** Format Descriptors *****/

            { &hf_usb_vid_format_index,
                    { "bFormatIndex", "usbvideo.format.index",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Index of this format descriptor", HFILL }
            },

            { &hf_usb_vid_format_num_frame_descriptors,
                    { "bNumFrameDescriptors", "usbvideo.format.numFrameDescriptors",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Number of frame descriptors for this format", HFILL }
            },

            { &hf_usb_vid_format_guid,
                    { "guidFormat", "usbvideo.format.guid",
                            FT_GUID, BASE_NONE, NULL, 0,
                            "Stream encoding format", HFILL }
            },

            { &hf_usb_vid_format_bits_per_pixel,
                    { "bBitsPerPixel", "usbvideo.format.bitsPerPixel",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Bits per pixel", HFILL }
            },

            { &hf_usb_vid_default_frame_index,
                    { "bDefaultFrameIndex", "usbvideo.format.defaultFrameIndex",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Optimum frame index for this stream", HFILL }
            },

            { &hf_usb_vid_aspect_ratio_x,
                    { "bAspectRatioX", "usbvideo.format.aspectRatioX",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "X dimension of picture aspect ratio", HFILL }
            },

            { &hf_usb_vid_aspect_ratio_y,
                    { "bAspectRatioY", "usbvideo.format.aspectRatioY",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Y dimension of picture aspect ratio", HFILL }
            },

            { &hf_usb_vid_is_interlaced,
                    { "Interlaced stream", "usbvideo.format.interlace.D0",
                            FT_BOOLEAN, 8, TFS(&is_interlaced_meaning), (1<<0),
                            NULL, HFILL }
            },

            { &hf_usb_vid_interlaced_fields,
                    { "Fields per frame", "usbvideo.format.interlace.D1",
                            FT_BOOLEAN, 8, TFS(&interlaced_fields_meaning), (1<<1),
                            NULL, HFILL }
            },

            { &hf_usb_vid_field_1_first,
                    { "Field 1 first", "usbvideo.format.interlace.D2",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<2),
                            NULL, HFILL }
            },

            { &hf_usb_vid_field_pattern,
                    { "Field pattern", "usbvideo.format.interlace.pattern",
                            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                            &field_pattern_meaning_ext, (3<<4),
                            NULL, HFILL }
            },

            { &hf_usb_vid_copy_protect,
                    { "bCopyProtect", "usbvideo.format.copyProtect",
                            FT_UINT8, BASE_DEC, VALS(copy_protect_meaning), 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_variable_size,
                    { "Variable size", "usbvideo.format.variableSize",
                            FT_BOOLEAN, BASE_DEC, NULL, 0,
                            NULL, HFILL }
            },

        /***** MJPEG Format Descriptor *****/

            { &hf_usb_vid_mjpeg_flags,
                    { "bmFlags", "usbvideo.mjpeg.flags",
                            FT_UINT8, BASE_HEX, NULL, 0,
                            "Characteristics", HFILL }
            },

            { &hf_usb_vid_mjpeg_fixed_samples,
                    { "Fixed size samples", "usbvideo.mjpeg.fixed_size",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<0),
                            NULL, HFILL }
            },

        /***** Frame Descriptors *****/

            { &hf_usb_vid_frame_index,
                    { "bFrameIndex", "usbvideo.frame.index",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Index of this frame descriptor", HFILL }
            },

            { &hf_usb_vid_frame_capabilities,
                    { "bmCapabilities", "usbvideo.frame.capabilities",
                            FT_UINT8, BASE_HEX, NULL, 0,
                            "Capabilities", HFILL }
            },

            { &hf_usb_vid_frame_stills_supported,
                    { "Still image", "usbvideo.frame.stills",
                            FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), (1<<0),
                            NULL, HFILL }
            },

            { &hf_usb_vid_frame_interval,
                    { "dwFrameInterval", "usbvideo.frame.interval",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Frame interval multiple of 100 ns", HFILL }
            },

            { &hf_usb_vid_frame_fixed_frame_rate,
                    { "Fixed frame rate", "usbvideo.frame.fixedRate",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<1),
                            NULL, HFILL }
            },
            { &hf_usb_vid_frame_width,
                    { "wWidth", "usbvideo.frame.width",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Width of frame in pixels", HFILL }
            },
            { &hf_usb_vid_frame_height,
                    { "wHeight", "usbvideo.frame.height",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Height of frame in pixels", HFILL }
            },
            { &hf_usb_vid_frame_min_bit_rate,
                    { "dwMinBitRate", "usbvideo.frame.minBitRate",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Minimum bit rate in bps", HFILL }
            },
            { &hf_usb_vid_frame_max_bit_rate,
                    { "dwMaxBitRate", "usbvideo.frame.maxBitRate",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Maximum bit rate in bps", HFILL }
            },

            { &hf_usb_vid_frame_max_frame_sz,
                    { "dwMaxVideoFrameBufferSize", "usbvideo.frame.maxBuffer",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Maximum bytes per frame", HFILL }
            },
            { &hf_usb_vid_frame_default_interval,
                    { "dwDefaultFrameInterval", "usbvideo.frame.interval.default",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Suggested default", HFILL }
            },

            { &hf_usb_vid_frame_interval_type,
                    { "bFrameIntervalType", "usbvideo.frame.interval.type",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Frame rate control (continuous/discrete)", HFILL }
            },

            { &hf_usb_vid_frame_min_interval,
                    { "dwMinFrameInterval", "usbvideo.frame.interval.min",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Shortest frame interval (* 100 ns)", HFILL }
            },

            { &hf_usb_vid_frame_max_interval,
                    { "dwMaxFrameInterval", "usbvideo.frame.interval.max",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Longest frame interval (* 100 ns)", HFILL }
            },
            { &hf_usb_vid_frame_step_interval,
                    { "dwMinFrameInterval", "usbvideo.frame.interval.step",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Granularity of frame interval (* 100 ns)", HFILL }
            },

            { &hf_usb_vid_frame_bytes_per_line,
                    { "dwBytesPerLine", "usbvideo.frame.bytesPerLine",
                            FT_UINT32, BASE_DEC, NULL, 0,
                            "Fixed number of bytes per video line", HFILL }
            },

        /***** Colorformat Descriptor *****/

            { &hf_usb_vid_color_primaries,
                    { "bColorPrimaries", "usbvideo.color.primaries",
                            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                            &color_primaries_meaning_ext, 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_transfer_characteristics,
                    { "bTransferCharacteristics", "usbvideo.color.transferCharacteristics",
                            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                            &color_transfer_characteristics_ext, 0,
                            NULL, HFILL }
            },

            { &hf_usb_vid_matrix_coefficients,
                    { "bMatrixCoefficients", "usbvideo.color.matrixCoefficients",
                            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                            &matrix_coefficients_meaning_ext, 0,
                            NULL, HFILL }
            },

        /***** Video Control Header Descriptor *****/

            { &hf_usb_vid_control_ifdesc_bcdUVC,
                    { "bcdUVC", "usbvideo.bcdUVC",
                            FT_UINT16, BASE_HEX, NULL, 0,
                            "Video Device Class Specification release number", HFILL }
            },

            { &hf_usb_vid_control_ifdesc_bInCollection,
                    { "bInCollection", "usbvideo.numStreamingInterfaces",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Number of VideoStreaming interfaces", HFILL }
            },

            { &hf_usb_vid_control_ifdesc_baInterfaceNr,
                    { "baInterfaceNr", "usbvideo.streamingInterfaceNumbers",
                            FT_BYTES, BASE_NONE, NULL, 0,
                            "Interface numbers of VideoStreaming interfaces", HFILL }},

        /***** Video Streaming Input Header Descriptor *****/

            { &hf_usb_vid_streaming_ifdesc_bNumFormats,
                    { "bNumFormats", "usbvideo.streaming.numFormats",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Number of video payload format descriptors", HFILL }
            },

            { &hf_usb_vid_streaming_bmInfo,
                    { "bmInfo", "usbvideo.streaming.info",
                            FT_UINT8, BASE_HEX, NULL, 0,
                            "Capabilities", HFILL }
            },

            { &hf_usb_vid_streaming_info_D[0],
                    { "Dynamic Format Change", "usbvideo.streaming.info.D0",
                            FT_BOOLEAN, 8, TFS(&tfs_yes_no), (1<<0),
                            "Dynamic Format Change", HFILL }
            },

            { &hf_usb_vid_streaming_control_D[0],
                    { "wKeyFrameRate", "usbvideo.streaming.control.D0",
                            FT_BOOLEAN, 6, TFS(&tfs_yes_no), (1<<0),
                            "Probe and Commit support", HFILL }
            },

            { &hf_usb_vid_streaming_control_D[1],
                    { "wPFrameRate", "usbvideo.streaming.control.D1",
                            FT_BOOLEAN, 6, TFS(&tfs_yes_no), (1<<1),
                            "Probe and Commit support", HFILL }
            },

            { &hf_usb_vid_streaming_control_D[2],
                    { "wCompQuality", "usbvideo.streaming.control.D2",
                            FT_BOOLEAN, 6, TFS(&tfs_yes_no), (1<<2),
                            "Probe and Commit support", HFILL }
            },

            { &hf_usb_vid_streaming_control_D[3],
                    { "wCompWindowSize", "usbvideo.streaming.control.D3",
                            FT_BOOLEAN, 6, TFS(&tfs_yes_no), (1<<3),
                            "Probe and Commit support", HFILL }
            },

            { &hf_usb_vid_streaming_control_D[4],
                    { "Generate Key Frame", "usbvideo.streaming.control.D4",
                            FT_BOOLEAN, 6, TFS(&tfs_yes_no), (1<<4),
                            "Probe and Commit support", HFILL }
            },

            { &hf_usb_vid_streaming_control_D[5],
                    { "Update Frame Segment", "usbvideo.streaming.control.D5",
                            FT_BOOLEAN, 6, TFS(&tfs_yes_no), (1<<5),
                            "Probe and Commit support", HFILL }
            },

            { &hf_usb_vid_streaming_terminal_link,
                    { "bTerminalLink", "usbvideo.streaming.terminalLink", FT_UINT8, BASE_DEC, NULL, 0x0,
                            "Output terminal ID", HFILL }
            },

            { &hf_usb_vid_streaming_still_capture_method,
                    { "bStillCaptureMethod", "usbvideo.streaming.stillCaptureMethod",
                            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                            &vs_still_capture_methods_ext, 0,
                            "Method of Still Image Capture", HFILL }
            },

            { &hf_usb_vid_streaming_trigger_support,
                    { "HW Triggering", "usbvideo.streaming.triggerSupport",
                            FT_BOOLEAN, BASE_DEC, TFS(&tfs_supported_not_supported), 0,
                            "Is HW triggering supported", HFILL }
            },

            { &hf_usb_vid_streaming_trigger_usage,
                    { "bTriggerUsage", "usbvideo.streaming.triggerUsage",
                            FT_UINT8, BASE_DEC, VALS(vs_trigger_usage), 0,
                            "How host SW should respond to trigger", HFILL }
            },

        /***** Interrupt URB *****/

            { &hf_usb_vid_interrupt_bStatusType,
                    { "Status Type", "usbvideo.interrupt.statusType",
                            FT_UINT8, BASE_HEX, VALS(interrupt_status_types), 0xF,
                            NULL, HFILL }
            },

            { &hf_usb_vid_interrupt_bAttribute,
                    { "Change Type", "usbvideo.interrupt.attribute",
                            FT_UINT8, BASE_HEX | BASE_EXT_STRING,
                            &control_change_types_ext, 0,
                            "Type of control change", HFILL }
            },

            { &hf_usb_vid_interrupt_bOriginator,
                    { "Originator", "usbvideo.interrupt.originator",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "ID of the entity that reports this interrupt", HFILL }
            },

            { &hf_usb_vid_control_interrupt_bEvent,
                    { "Event", "usbvideo.interrupt.controlEvent",
                            FT_UINT8, BASE_HEX, VALS(control_interrupt_events), 0,
                            "Type of event", HFILL }
            },

        /***** Video Control Endpoint Descriptor *****/

            { &hf_usb_vid_epdesc_subtype,
                    { "Subtype", "usbvideo.ep.descriptorSubType",
                            FT_UINT8, BASE_DEC, VALS(vc_ep_descriptor_subtypes), 0,
                            "Descriptor Subtype", HFILL }
            },

            { &hf_usb_vid_epdesc_max_transfer_sz,
                    { "wMaxTransferSize", "usbvideo.ep.maxInterruptSize", FT_UINT16,
                      BASE_DEC, NULL, 0x0, "Max interrupt structure size", HFILL }
            },

        /***** Fields used in multiple contexts *****/

            { &hf_usb_vid_ifdesc_wTotalLength,
                    { "wTotalLength", "usbvideo.totalLength",
                            FT_UINT16, BASE_DEC, NULL, 0,
                            "Video interface descriptor size", HFILL }
            },

            { &hf_usb_vid_bControlSize,
                    { "bControlSize", "usbvideo.bmcontrolSize",
                            FT_UINT8, BASE_DEC, NULL, 0,
                            "Size of bmControls field", HFILL }
            },

            { &hf_usb_vid_bmControl,
                    { "bmControl", "usbvideo.availableControls",
                            FT_UINT32, BASE_HEX, NULL, 0,
                            "Available controls", HFILL }
            },

            { &hf_usb_vid_control_ifdesc_src_id,
                    { "bSourceID", "usbvideo.sourceID", FT_UINT8, BASE_DEC, NULL, 0x0,
                            "Entity to which this terminal/unit is connected", HFILL }
            },

        /**********/

            { &hf_usb_vid_control_ifdesc_subtype,
                    { "Subtype", "usbvideo.control.descriptorSubType",
                            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                            &vc_if_descriptor_subtypes_ext, 0,
                            "Descriptor Subtype", HFILL }
            },

            { &hf_usb_vid_streaming_ifdesc_subtype,
                    { "Subtype", "usbvideo.streaming.descriptorSubType",
                            FT_UINT8, BASE_DEC | BASE_EXT_STRING,
                            &vs_if_descriptor_subtypes_ext, 0,
                            "Descriptor Subtype", HFILL }
            },
    };

    static gint *usb_vid_subtrees[] = {
            &ett_usb_vid,
            &ett_descriptor_video_endpoint,
            &ett_descriptor_video_control,
            &ett_descriptor_video_streaming,
            &ett_camera_controls,
            &ett_processing_controls,
            &ett_streaming_controls,
            &ett_streaming_info,
            &ett_interlace_flags,
            &ett_frame_capability_flags,
            &ett_mjpeg_flags,
            &ett_video_probe,
            &ett_probe_hint,
            &ett_probe_framing,
            &ett_video_standards,
            &ett_control_capabilities
    };

    static ei_register_info ei[] = {
        { &ei_usb_vid_subtype_unknown, { "usbvideo.subtype.unknown", PI_UNDECODED, PI_WARN, "Unknown VC subtype", EXPFILL }},
        { &ei_usb_vid_bitmask_len, { "usbvideo.bitmask_len_error", PI_UNDECODED, PI_WARN, "Only least-significant bytes decoded", EXPFILL }},
    };

    expert_module_t* expert_usb_vid;

    proto_usb_vid = proto_register_protocol("USB Video", "USBVIDEO", "usbvideo");
    proto_register_field_array(proto_usb_vid, hf, array_length(hf));
    proto_register_subtree_array(usb_vid_subtrees, array_length(usb_vid_subtrees));
    expert_usb_vid = expert_register_protocol(proto_usb_vid);
    expert_register_field_array(expert_usb_vid, ei, array_length(ei));
}

void
proto_reg_handoff_usb_vid(void)
{
    dissector_handle_t usb_vid_control_handle;
    dissector_handle_t usb_vid_descriptor_handle;
    dissector_handle_t usb_vid_interrupt_handle;

    usb_vid_control_handle = new_create_dissector_handle(dissect_usb_vid_control, proto_usb_vid);
    dissector_add_uint("usb.control", IF_CLASS_VIDEO, usb_vid_control_handle);

    usb_vid_descriptor_handle = new_create_dissector_handle(dissect_usb_vid_descriptor, proto_usb_vid);
    dissector_add_uint("usb.descriptor", IF_CLASS_VIDEO, usb_vid_descriptor_handle);

    usb_vid_interrupt_handle = new_create_dissector_handle(dissect_usb_vid_interrupt, proto_usb_vid);
    dissector_add_uint("usb.interrupt", IF_CLASS_VIDEO, usb_vid_interrupt_handle);
}
/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
