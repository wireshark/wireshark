/* packet-usb-hid.c
 *
 * USB HID dissector
 * By Adam Nielsen <a.nielsen@shikadi.net> 2009
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* See specification at
 * https://www.usb.org/sites/default/files/hid1_11.pdf
 * https://www.usb.org/sites/default/files/hut1_22.pdf
 */

#include "config.h"


#include <epan/packet.h>
#include "wsutil/sign_ext.h"
#include "wsutil/pint.h"
#include "packet-usb.h"
#include "packet-usb-hid.h"
#include "packet-btsdp.h"


void proto_register_usb_hid(void);
void proto_reg_handoff_usb_hid(void);

/* Dissector handles */
static dissector_handle_t usb_hid_control_handle;
static dissector_handle_t usb_hid_interrupt_handle;
static dissector_handle_t usb_hid_descr_handle;

/* protocols and header fields */
static int proto_usb_hid;
static int hf_usb_hid_item_bSize;
static int hf_usb_hid_item_bType;
static int hf_usb_hid_mainitem_bTag;
static int hf_usb_hid_globalitem_bTag;
static int hf_usb_hid_localitem_bTag;
static int hf_usb_hid_longitem_bTag;
static int hf_usb_hid_item_bDataSize;
static int hf_usb_hid_item_bLongItemTag;
static int hf_usb_hid_item_unk_data;

static int hf_usb_hid_mainitem_bit0;
static int hf_usb_hid_mainitem_bit1;
static int hf_usb_hid_mainitem_bit2;
static int hf_usb_hid_mainitem_bit3;
static int hf_usb_hid_mainitem_bit4;
static int hf_usb_hid_mainitem_bit5;
static int hf_usb_hid_mainitem_bit6;
static int hf_usb_hid_mainitem_bit7;
static int hf_usb_hid_mainitem_bit7_input;
static int hf_usb_hid_mainitem_bit8;
static int hf_usb_hid_mainitem_colltype;

static int hf_usb_hid_globalitem_usage;
static int hf_usb_hid_globalitem_log_min;
static int hf_usb_hid_globalitem_log_max;
static int hf_usb_hid_globalitem_phy_min;
static int hf_usb_hid_globalitem_phy_max;
static int hf_usb_hid_globalitem_unit_exp;
static int hf_usb_hid_globalitem_unit_sys;
static int hf_usb_hid_globalitem_unit_len;
static int hf_usb_hid_globalitem_unit_mass;
static int hf_usb_hid_globalitem_unit_time;
static int hf_usb_hid_globalitem_unit_temp;
static int hf_usb_hid_globalitem_unit_current;
static int hf_usb_hid_globalitem_unit_brightness;
static int hf_usb_hid_globalitem_report_size;
static int hf_usb_hid_globalitem_report_id;
static int hf_usb_hid_globalitem_report_count;
static int hf_usb_hid_globalitem_push;
static int hf_usb_hid_globalitem_pop;

static int hf_usb_hid_localitem_usage;
static int hf_usb_hid_localitem_usage_min;
static int hf_usb_hid_localitem_usage_max;
static int hf_usb_hid_localitem_desig_index;
static int hf_usb_hid_localitem_desig_min;
static int hf_usb_hid_localitem_desig_max;
static int hf_usb_hid_localitem_string_index;
static int hf_usb_hid_localitem_string_min;
static int hf_usb_hid_localitem_string_max;
static int hf_usb_hid_localitem_delimiter;

static int ett_usb_hid_report;
static int ett_usb_hid_item_header;
static int ett_usb_hid_wValue;
static int ett_usb_hid_descriptor;
static int ett_usb_hid_data;
static int ett_usb_hid_unknown_data;
static int ett_usb_hid_array;

static int hf_usb_hid_request;
static int hf_usb_hid_value;
static int hf_usb_hid_index;
static int hf_usb_hid_length;
static int hf_usb_hid_report_type;
static int hf_usb_hid_report_id;
static int hf_usb_hid_duration;
static int hf_usb_hid_zero;

static int hf_usb_hid_bcdHID;
static int hf_usb_hid_bCountryCode;
static int hf_usb_hid_bNumDescriptors;
static int hf_usb_hid_bDescriptorIndex;
static int hf_usb_hid_bDescriptorType;
static int hf_usb_hid_wInterfaceNumber;
static int hf_usb_hid_wDescriptorLength;

static int hf_usbhid_boot_report_keyboard_modifier_right_gui;
static int hf_usbhid_boot_report_keyboard_modifier_right_alt;
static int hf_usbhid_boot_report_keyboard_modifier_right_shift;
static int hf_usbhid_boot_report_keyboard_modifier_right_ctrl;
static int hf_usbhid_boot_report_keyboard_modifier_left_gui;
static int hf_usbhid_boot_report_keyboard_modifier_left_alt;
static int hf_usbhid_boot_report_keyboard_modifier_left_shift;
static int hf_usbhid_boot_report_keyboard_modifier_left_ctrl;
static int hf_usbhid_boot_report_keyboard_reserved;
static int hf_usbhid_boot_report_keyboard_keycode_1;
static int hf_usbhid_boot_report_keyboard_keycode_2;
static int hf_usbhid_boot_report_keyboard_keycode_3;
static int hf_usbhid_boot_report_keyboard_keycode_4;
static int hf_usbhid_boot_report_keyboard_keycode_5;
static int hf_usbhid_boot_report_keyboard_keycode_6;
static int hf_usbhid_boot_report_keyboard_leds_constants;
static int hf_usbhid_boot_report_keyboard_leds_kana;
static int hf_usbhid_boot_report_keyboard_leds_compose;
static int hf_usbhid_boot_report_keyboard_leds_scroll_lock;
static int hf_usbhid_boot_report_keyboard_leds_caps_lock;
static int hf_usbhid_boot_report_keyboard_leds_num_lock;
static int hf_usbhid_boot_report_mouse_button_8;
static int hf_usbhid_boot_report_mouse_button_7;
static int hf_usbhid_boot_report_mouse_button_6;
static int hf_usbhid_boot_report_mouse_button_5;
static int hf_usbhid_boot_report_mouse_button_4;
static int hf_usbhid_boot_report_mouse_button_middle;
static int hf_usbhid_boot_report_mouse_button_right;
static int hf_usbhid_boot_report_mouse_button_left;
static int hf_usbhid_boot_report_mouse_x_displacement;
static int hf_usbhid_boot_report_mouse_y_displacement;
static int hf_usbhid_boot_report_mouse_horizontal_scroll_wheel;
static int hf_usbhid_boot_report_mouse_vertical_scroll_wheel;
static int hf_usbhid_data;
static int hf_usbhid_unknown_data;
static int hf_usbhid_vendor_data;
static int hf_usbhid_report_id;
static int hf_usbhid_padding;
static int hf_usbhid_axis_x;
static int hf_usbhid_axis_y;
static int hf_usbhid_axis_z;
static int hf_usbhid_axis_rx;
static int hf_usbhid_axis_ry;
static int hf_usbhid_axis_rz;
static int hf_usbhid_axis_slider;
static int hf_usbhid_axis_vx;
static int hf_usbhid_axis_vy;
static int hf_usbhid_axis_vz;
static int hf_usbhid_axis_vbrx;
static int hf_usbhid_axis_vbry;
static int hf_usbhid_axis_vbrz;
static int hf_usbhid_axis_vno;
static int hf_usbhid_button;
static int hf_usbhid_key;
static int hf_usbhid_array;
static int hf_usbhid_array_usage;

static const true_false_string tfs_mainitem_bit0 = {"Constant", "Data"};
static const true_false_string tfs_mainitem_bit1 = {"Variable", "Array"};
static const true_false_string tfs_mainitem_bit2 = {"Relative", "Absolute"};
static const true_false_string tfs_mainitem_bit3 = {"Wrap", "No Wrap"};
static const true_false_string tfs_mainitem_bit4 = {"Non Linear", "Linear"};
static const true_false_string tfs_mainitem_bit5 = {"No Preferred", "Preferred State"};
static const true_false_string tfs_mainitem_bit6 = {"Null state", "No Null position"};
static const true_false_string tfs_mainitem_bit7 = {"Volatile", "Non Volatile"};
static const true_false_string tfs_mainitem_bit8 = {"Buffered Bytes", "Bit Field"};


struct usb_hid_global_state {
    unsigned int usage_page;
};

static wmem_tree_t *report_descriptors;


/* local items */
#define HID_USAGE_MIN       (1 << 0)
#define HID_USAGE_MAX       (1 << 1)

/* global items */
#define HID_REPORT_ID       (1 << 2)
#define HID_REPORT_COUNT    (1 << 3)
#define HID_REPORT_SIZE     (1 << 4)
#define HID_LOGICAL_MIN     (1 << 5)
#define HID_LOGICAL_MAX     (1 << 6)
#define HID_USAGE_PAGE      (1 << 7)

/* main items */
#define HID_INPUT           (1 << 8)
#define HID_OUTPUT          (1 << 9)
#define HID_FEATURE         (1 << 10)

#define HID_EXTENDED_USAGE  (1 << 11)

/* masks */

#define HID_GLOBAL_MASK     (HID_REPORT_ID | \
                             HID_REPORT_COUNT | \
                             HID_REPORT_SIZE | \
                             HID_LOGICAL_MIN | \
                             HID_LOGICAL_MAX | \
                             HID_USAGE_PAGE)

#define HID_REQUIRED_MASK   (HID_REPORT_COUNT | \
                             HID_REPORT_SIZE | \
                             HID_LOGICAL_MIN | \
                             HID_LOGICAL_MAX)


#define HID_MAIN_CONSTANT       (1 << 0) /* data / constant                 */
#define HID_MAIN_TYPE           (1 << 1) /* array / variable                */
#define HID_MAIN_RELATIVE       (1 << 2) /* absolute / relative             */
#define HID_MAIN_WRAP           (1 << 3) /* no wrap / wrap                  */
#define HID_MAIN_NON_LINEAR     (1 << 4) /* linear / non linear             */
#define HID_MAIN_NO_PREFERRED   (1 << 5) /* preferred state / no preferred  */
#define HID_MAIN_NULL_STATE     (1 << 6) /* no null position / null state   */
#define HID_MAIN_BUFFERED_BYTES (1 << 8) /* bit field / buffered bytes      */


#define HID_MAIN_ARRAY          (0 << 1)
#define HID_MAIN_VARIABLE       (1 << 1)


#define HID_USAGE_UNSET         0
#define HID_USAGE_SINGLE        1
#define HID_USAGE_RANGE         2


#define USAGE_ID(usage)    (usage & 0x0000FFFF)
#define USAGE_PAGE(usage) ((usage & 0xFFFF0000) >> 16)

typedef struct _hid_field hid_field_t;

struct _hid_field {
    wmem_array_t   *usages;

    uint32_t        report_id;  /* optional */
    uint32_t        report_count;
    uint32_t        report_size;
    int32_t         logical_min;
    int32_t         logical_max;
    uint32_t        properties;

    hid_field_t *next;
};


typedef struct _report_descriptor report_descriptor_t;

struct _report_descriptor {
    usb_conv_info_t         usb_info;

    int                     desc_length;
    uint8_t                *desc_body;

    bool                    uses_report_id;
    wmem_array_t           *fields_in;
    wmem_array_t           *fields_out;
    /* TODO: features */

    report_descriptor_t    *next;
};

#define USBHID_GENERIC_DESKTOP_CONTROLS_X           0x0030
#define USBHID_GENERIC_DESKTOP_CONTROLS_Y           0x0031
#define USBHID_GENERIC_DESKTOP_CONTROLS_Z           0x0032
#define USBHID_GENERIC_DESKTOP_CONTROLS_RX          0x0033
#define USBHID_GENERIC_DESKTOP_CONTROLS_RY          0x0034
#define USBHID_GENERIC_DESKTOP_CONTROLS_RZ          0x0035
#define USBHID_GENERIC_DESKTOP_CONTROLS_SLIDER      0x0036

#define USBHID_GENERIC_DESKTOP_CONTROLS_VX          0x0040
#define USBHID_GENERIC_DESKTOP_CONTROLS_VY          0x0041
#define USBHID_GENERIC_DESKTOP_CONTROLS_VZ          0x0042
#define USBHID_GENERIC_DESKTOP_CONTROLS_VBRX        0x0043
#define USBHID_GENERIC_DESKTOP_CONTROLS_VBRY        0x0044
#define USBHID_GENERIC_DESKTOP_CONTROLS_VBRZ        0x0045
#define USBHID_GENERIC_DESKTOP_CONTROLS_VNO         0x0046

/* HID class specific descriptor types */
#define USB_DT_HID        0x21
#define USB_DT_HID_REPORT 0x22
static const value_string hid_descriptor_type_vals[] = {
    {USB_DT_HID, "HID"},
    {USB_DT_HID_REPORT, "HID Report"},
    {0, NULL}
};
static value_string_ext hid_descriptor_type_vals_ext =
               VALUE_STRING_EXT_INIT(hid_descriptor_type_vals);


#define USBHID_SIZE_MASK  0x03
#define USBHID_TYPE_MASK  0x0C
#define USBHID_TAG_MASK   0xF0

static const value_string usb_hid_item_bSize_vals[] = {
    {0, "0 bytes"},
    {1, "1 byte"},
    {2, "2 bytes"},
    {3, "4 bytes"},
    {0, NULL}
};

#define USBHID_ITEMTYPE_MAIN    0
#define USBHID_ITEMTYPE_GLOBAL  1
#define USBHID_ITEMTYPE_LOCAL   2
#define USBHID_ITEMTYPE_LONG    3
static const value_string usb_hid_item_bType_vals[] = {
    {USBHID_ITEMTYPE_MAIN,   "Main"},
    {USBHID_ITEMTYPE_GLOBAL, "Global"},
    {USBHID_ITEMTYPE_LOCAL,  "Local"},
    {USBHID_ITEMTYPE_LONG,   "Long item"},
    {0, NULL}
};

#define USBHID_MAINITEM_TAG_INPUT           8
#define USBHID_MAINITEM_TAG_OUTPUT          9
#define USBHID_MAINITEM_TAG_FEATURE        11
#define USBHID_MAINITEM_TAG_COLLECTION     10
#define USBHID_MAINITEM_TAG_ENDCOLLECTION  12
static const value_string usb_hid_mainitem_bTag_vals[] = {
    {USBHID_MAINITEM_TAG_INPUT,         "Input"},
    {USBHID_MAINITEM_TAG_OUTPUT,        "Output"},
    {USBHID_MAINITEM_TAG_FEATURE,       "Feature"},
    {USBHID_MAINITEM_TAG_COLLECTION,    "Collection"},
    {USBHID_MAINITEM_TAG_ENDCOLLECTION, "End Collection"},
    {0, NULL}
};
#define USBHID_GLOBALITEM_TAG_USAGE_PAGE    0
#define USBHID_GLOBALITEM_TAG_LOG_MIN       1
#define USBHID_GLOBALITEM_TAG_LOG_MAX       2
#define USBHID_GLOBALITEM_TAG_PHY_MIN       3
#define USBHID_GLOBALITEM_TAG_PHY_MAX       4
#define USBHID_GLOBALITEM_TAG_UNIT_EXP      5
#define USBHID_GLOBALITEM_TAG_UNIT          6
#define USBHID_GLOBALITEM_TAG_REPORT_SIZE   7
#define USBHID_GLOBALITEM_TAG_REPORT_ID     8
#define USBHID_GLOBALITEM_TAG_REPORT_COUNT  9
#define USBHID_GLOBALITEM_TAG_PUSH         10
#define USBHID_GLOBALITEM_TAG_POP          11
static const value_string usb_hid_globalitem_bTag_vals[] = {
    {USBHID_GLOBALITEM_TAG_USAGE_PAGE,   "Usage Page"},
    {USBHID_GLOBALITEM_TAG_LOG_MIN,      "Logical Minimum"},
    {USBHID_GLOBALITEM_TAG_LOG_MAX,      "Logical Maximum"},
    {USBHID_GLOBALITEM_TAG_PHY_MIN,      "Physical Minimum"},
    {USBHID_GLOBALITEM_TAG_PHY_MAX,      "Physical Maximum"},
    {USBHID_GLOBALITEM_TAG_UNIT_EXP,     "Unit Exponent"},
    {USBHID_GLOBALITEM_TAG_UNIT,         "Unit"},
    {USBHID_GLOBALITEM_TAG_REPORT_SIZE,  "Report Size"},
    {USBHID_GLOBALITEM_TAG_REPORT_ID,    "Report ID"},
    {USBHID_GLOBALITEM_TAG_REPORT_COUNT, "Report Count"},
    {USBHID_GLOBALITEM_TAG_PUSH,         "Push"},
    {USBHID_GLOBALITEM_TAG_POP,          "Pop"},
    {12, "[Reserved]"},
    {13, "[Reserved]"},
    {14, "[Reserved]"},
    {15, "[Reserved]"},
    {0, NULL}
};
#define USBHID_LOCALITEM_TAG_USAGE          0
#define USBHID_LOCALITEM_TAG_USAGE_MIN      1
#define USBHID_LOCALITEM_TAG_USAGE_MAX      2
#define USBHID_LOCALITEM_TAG_DESIG_INDEX    3
#define USBHID_LOCALITEM_TAG_DESIG_MIN      4
#define USBHID_LOCALITEM_TAG_DESIG_MAX      5
/* No 6 in spec */
#define USBHID_LOCALITEM_TAG_STRING_INDEX   7
#define USBHID_LOCALITEM_TAG_STRING_MIN     8
#define USBHID_LOCALITEM_TAG_STRING_MAX     9
#define USBHID_LOCALITEM_TAG_DELIMITER     10 /* Also listed as reserved in spec! */
static const value_string usb_hid_localitem_bTag_vals[] = {
    {USBHID_LOCALITEM_TAG_USAGE,        "Usage"},
    {USBHID_LOCALITEM_TAG_USAGE_MIN,    "Usage Minimum"},
    {USBHID_LOCALITEM_TAG_USAGE_MAX,    "Usage Maximum"},
    {USBHID_LOCALITEM_TAG_DESIG_INDEX,  "Designator Index"},
    {USBHID_LOCALITEM_TAG_DESIG_MIN,    "Designator Minimum"},
    {USBHID_LOCALITEM_TAG_DESIG_MAX,    "Designator Maximum"},
    {USBHID_LOCALITEM_TAG_STRING_INDEX, "String Index"},
    {USBHID_LOCALITEM_TAG_STRING_MIN,   "String Minimum"},
    {USBHID_LOCALITEM_TAG_STRING_MAX,   "String Maximum"},
    {USBHID_LOCALITEM_TAG_DELIMITER,    "Delimiter"},
    {11, "[Reserved]"},
    {12, "[Reserved]"},
    {13, "[Reserved]"},
    {14, "[Reserved]"},
    {15, "[Reserved]"},
    {0, NULL}
};
static const value_string usb_hid_longitem_bTag_vals[] = {
    {15, "Long item"},
    {0, NULL}
};

static const range_string usb_hid_mainitem_colltype_vals[] = {
    {0x00, 0x00, "Physical"},
    {0x01, 0x01, "Application"},
    {0x02, 0x02, "Logical"},
    {0x03, 0x03, "Report"},
    {0x04, 0x04, "Named array"},
    {0x05, 0x05, "Usage switch"},
    {0x06, 0x06, "Usage modifier"},
    {0x07, 0x7F, "[Reserved]"},
    {0x80, 0xFF, "[Vendor-defined]"},
    {0, 0, NULL}
};

static const value_string usb_hid_globalitem_unit_exp_vals[] = {
    {0x0, "n^0"},
    {0x1, "n^1"},
    {0x2, "n^2"},
    {0x3, "n^3"},
    {0x4, "n^4"},
    {0x5, "n^5"},
    {0x6, "n^6"},
    {0x7, "n^7"},
    {0x8, "n^-8"},
    {0x9, "n^-7"},
    {0xA, "n^-6"},
    {0xB, "n^-5"},
    {0xC, "n^-4"},
    {0xD, "n^-3"},
    {0xE, "n^-2"},
    {0xF, "n^-1"},
    {0, NULL}
};

#define GENERIC_DESKTOP_CONTROLS_PAGE   0x01
#define SIMULATION_CONTROLS_PAGE        0x02
#define VR_CONTROLS_PAGE                0x03
#define SPORT_CONTROLS_PAGE             0x04
#define GAME_CONTROLS_PAGE              0x05
#define GENERIC_DEVICE_CONTROLS_PAGE    0x06
#define KEYBOARD_KEYPAD_PAGE            0x07
#define LED_PAGE                        0x08
#define BUTTON_PAGE                     0x09
#define ORDINAL_PAGE                    0x0A
#define TELEPHONY_PAGE                  0x0B
#define CONSUMER_PAGE                   0x0C
#define DIGITIZER_PAGE                  0x0D
#define HAPTICS_PAGE                    0x0E
#define PID_PAGE                        0x0F
#define UNICODE_PAGE                    0x10
#define EYE_AND_HEAD_TRACKER_PAGE       0x12
#define ALPHANUMERIC_DISPLAY_PAGE       0x14
#define SENSOR_PAGE                     0x20
#define MEDICAL_INSTRUMENTS_PAGE        0x40
#define BRAILLE_DISPLAY_PAGE            0x41
#define LIGHTING_AND_ILLUMINATION_PAGE  0x59
#define USB_MONITOR_PAGE                0x80
#define USB_ENUMERATED_VALUES_PAGE      0x81
#define VESA_VIRTUAL_CONTROLS_PAGE      0x82
#define POWER_DEVICE_PAGE               0x84
#define BATTERY_SYSTEM_PAGE             0x85
#define BARCODE_SCANNER_PAGE            0x8C
#define WEIGHING_PAGE                   0x8D
#define MSR_PAGE                        0x8E
#define RESERVED_POS_PAGE               0x8F
#define CAMERA_CONTROL_PAGE             0x90
#define ARCADE_PAGE                     0x91
#define GAMING_DEVICE_PAGE              0x92
#define FIDO_ALLIANCE_PAGE              0xF1D0
#define VENDOR_PAGE_HBYTE               0xFF00
static const value_string usb_hid_item_usage_page_vals[] = {
    {0x00, "Undefined"},
    {GENERIC_DESKTOP_CONTROLS_PAGE,     "Generic Desktop Controls"},
    {SIMULATION_CONTROLS_PAGE,          "Simulation Controls"},
    {VR_CONTROLS_PAGE,                  "VR Controls"},
    {SPORT_CONTROLS_PAGE,               "Sport Controls"},
    {GAME_CONTROLS_PAGE,                "Game Controls"},
    {GENERIC_DEVICE_CONTROLS_PAGE,      "Generic Device Controls"},
    {KEYBOARD_KEYPAD_PAGE,              "Keyboard/Keypad"},
    {LED_PAGE,                          "LED"},
    {BUTTON_PAGE,                       "Button"},
    {ORDINAL_PAGE,                      "Ordinal"},
    {TELEPHONY_PAGE,                    "Telephony"},
    {CONSUMER_PAGE,                     "Consumer"},
    {DIGITIZER_PAGE,                    "Digitizer"},
    {HAPTICS_PAGE,                      "Haptics"},
    {PID_PAGE,                          "Physical Interface Device (PID)"},
    {UNICODE_PAGE,                      "Unicode"},
    {EYE_AND_HEAD_TRACKER_PAGE,         "Eye and Head Tracker"},
    {ALPHANUMERIC_DISPLAY_PAGE,         "Alphanumeric Display"},
    {SENSOR_PAGE,                       "Sensor"},
    {MEDICAL_INSTRUMENTS_PAGE,          "Medical Instruments"},
    {BRAILLE_DISPLAY_PAGE,              "Braille Display"},
    {LIGHTING_AND_ILLUMINATION_PAGE,    "Lighting and Illumination"},
    {USB_MONITOR_PAGE,                  "USB Monitor"},
    {USB_ENUMERATED_VALUES_PAGE,        "USB Enumerated Values"},
    {VESA_VIRTUAL_CONTROLS_PAGE,        "VESA Virtual Controls"},
    {POWER_DEVICE_PAGE,                 "Power Device"},
    {BATTERY_SYSTEM_PAGE,               "Battery Device"},
    {BARCODE_SCANNER_PAGE,              "Barcode Scanner"},
    {WEIGHING_PAGE,                     "Weighing"},
    {MSR_PAGE,                          "Magnetic Stripe Reading (MSR) Devices"},
    {RESERVED_POS_PAGE,                 "[Reserved Point of Sale page]"},
    {CAMERA_CONTROL_PAGE,               "Camera Control Page"},
    {ARCADE_PAGE,                       "Arcade"},
    {GAMING_DEVICE_PAGE,                "Gaming Device"},
    {FIDO_ALLIANCE_PAGE ,               "FIDO Alliance"},
    {0, NULL}
};

static const value_string usb_hid_generic_desktop_controls_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Pointer"},
    {0x02, "Mouse"},
    {0x04, "Joystick"},
    {0x05, "Game Pad"},
    {0x06, "Keyboard"},
    {0x07, "Keypad"},
    {0x08, "Multi-axis Controller"},
    {0x09, "Tablet PC System Controls"},
    {0x0A, "Water Cooling Device"},
    {0x0B, "Computer Chassis Device"},
    {0x0C, "Wireless Radio Controls"},
    {0x0D, "Portable Device Control"},
    {0x0E, "System Multi-Axis Controller"},
    {0x0F, "Spatial Controller"},
    {0x10, "Assistive Control"},
    {0x11, "Device Dock"},
    {0x12, "Dockable Device"},
    {0x30, "X"},
    {0x31, "Y"},
    {0x32, "Z"},
    {0x33, "Rx"},
    {0x34, "Ry"},
    {0x35, "Rz"},
    {0x36, "Slider"},
    {0x37, "Dial"},
    {0x38, "Wheel"},
    {0x39, "Hat switch"},
    {0x3A, "Counted Buffer"},
    {0x3B, "Byte Count"},
    {0x3C, "Motion Wakeup"},
    {0x3D, "Start"},
    {0x3E, "Select"},
    {0x40, "Vx"},
    {0x41, "Vy"},
    {0x42, "Vz"},
    {0x43, "Vbrx"},
    {0x44, "Vbry"},
    {0x45, "Vbrz"},
    {0x46, "Vno"},
    {0x47, "Feature Notification"},
    {0x48, "Resolution Multiplier"},
    {0x49, "Qx"},
    {0x4A, "Qy"},
    {0x4B, "Qz"},
    {0x4C, "Qw"},
    {0x80, "System Control"},
    {0x81, "System Power Down"},
    {0x82, "System Sleep"},
    {0x83, "System Wake Up"},
    {0x84, "System Context Menu"},
    {0x85, "System Main Menu"},
    {0x86, "System App Menu"},
    {0x87, "System Menu Help"},
    {0x88, "System Menu Exit"},
    {0x89, "System Menu Select"},
    {0x8A, "System Menu Right"},
    {0x8B, "System Menu Left"},
    {0x8C, "System Menu Up"},
    {0x8D, "System Menu Down"},
    {0x8E, "System Cold Restart"},
    {0x8F, "System Warm Restart"},
    {0x90, "D-pad Up"},
    {0x91, "D-pad Down"},
    {0x92, "D-pad Right"},
    {0x93, "D-pad Left"},
    {0x94, "Index Trigger"},
    {0x95, "Palm Trigger"},
    {0x96, "Thumbstick"},
    {0x97, "System Function Shift"},
    {0x98, "System Function Shift Lock"},
    {0x99, "System Function Shift Lock Indicator"},
    {0x9A, "System Dismiss Notification"},
    {0x9B, "System Do Not Disturb"},
    {0xA0, "System Dock"},
    {0xA1, "System Undock"},
    {0xA2, "System Setup"},
    {0xA3, "System Break"},
    {0xA4, "System Debugger Break"},
    {0xA5, "Application Break"},
    {0xA6, "Application Debugger Break"},
    {0xA7, "System Speaker Mute"},
    {0xA8, "System Hibernate"},
    {0xB0, "System Display Invert"},
    {0xB1, "System Display Internal"},
    {0xB2, "System Display External"},
    {0xB3, "System Display Both"},
    {0xB4, "System Display Dual"},
    {0xB5, "System Display Toggle Int/Ext"},
    {0xB6, "System Display Swap Primary/Secondary"},
    {0xB7, "System Display LCD Autoscale"},
    {0xC0, "Sensor Zone"},
    {0xC1, "RPM"},
    {0xC2, "Coolant Level"},
    {0xC3, "Coolant Critical Level"},
    {0xC4, "Coolant Pump"},
    {0xC5, "Chassis Enclosure"},
    {0xC6, "Wireless Radio Button"},
    {0xC7, "Wireless Radio LED"},
    {0xC8, "Wireless Radio Slider Switch"},
    {0xC9, "System Display Rotation Lock Button"},
    {0xCA, "System Display Rotation Lock Slider Switch"},
    {0xCB, "Control Enable"},
    {0xD0, "Dockable Device Unique ID"},
    {0xD1, "Dockable Device Vendor ID"},
    {0xD2, "Dockable Device Primary Usage Page"},
    {0xD3, "Dockable Device Primary Usage ID"},
    {0xD4, "Dockable Device Docking State"},
    {0xD5, "Dockable Device Display Occlusion"},
    {0xD6, "Dockable Device Object Type"},
    {0, NULL}
};
static const value_string usb_hid_simulation_control_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Flight Simulation Device"},
    {0x02, "Automobile Simulation Device"},
    {0x03, "Tank Simulation Device"},
    {0x04, "Spaceship Simulation Device"},
    {0x05, "Submarine Simulation Device"},
    {0x06, "Sailing Simulation Device"},
    {0x07, "Motorcycle Simulation Device"},
    {0x08, "Sports Simulation Device"},
    {0x09, "Airplane Simulation Device"},
    {0x0A, "Helicopter Simulation Device"},
    {0x0B, "Magic Carpet Simulation Device"},
    {0x0C, "Bicycle Simulation Device"},
    {0x20, "Flight Control Stick"},
    {0x21, "Flight Stick"},
    {0x22, "Cyclic Control"},
    {0x23, "Cyclic Trim"},
    {0x24, "Flight Yoke"},
    {0x25, "Track Control"},
    {0xB0, "Aileron"},
    {0xB1, "Aileron Trim"},
    {0xB2, "Anti-Torque Control"},
    {0xB3, "Autopilot Enable"},
    {0xB4, "Chaff Release"},
    {0xB5, "Collective Control"},
    {0xB6, "Dive Brake"},
    {0xB7, "Electronic Countermeasures"},
    {0xB8, "Elevator"},
    {0xB9, "Elevator Trim"},
    {0xBA, "Rudder"},
    {0xBB, "Throttle"},
    {0xBC, "Flight Communications"},
    {0xBD, "Flare Release"},
    {0xBE, "Landing Gear"},
    {0xBF, "Toe Brake"},
    {0xC0, "Trigger"},
    {0xC1, "Weapons Arm"},
    {0xC2, "Weapons Select"},
    {0xC3, "Wing Flaps"},
    {0xC4, "Accelerator"},
    {0xC5, "Brake"},
    {0xC6, "Clutch"},
    {0xC7, "Shifter"},
    {0xC8, "Steering"},
    {0xC9, "Turret Direction"},
    {0xCA, "Barrel Elevation"},
    {0xCB, "Dive Plane"},
    {0xCC, "Ballast"},
    {0xCD, "Bicycle Crank"},
    {0xCE, "Handle Bars"},
    {0xCF, "Front Brake"},
    {0xD0, "Rear Brake"},
    {0, NULL}
};
static const value_string usb_hid_vr_controls_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Belt"},
    {0x02, "Body Suit"},
    {0x03, "Flexor"},
    {0x04, "Glove"},
    {0x05, "Head Tracker"},
    {0x06, "Head Mounted Display"},
    {0x07, "Hand Tracker"},
    {0x08, "Oculometer"},
    {0x09, "Vest"},
    {0x0A, "Animatronic Device"},
    {0x20, "Stereo Enable"},
    {0x21, "Display Enable"},
    {0, NULL}
};
static const value_string usb_hid_sport_controls_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Baseball Bat"},
    {0x02, "Golf Club"},
    {0x03, "Rowing Machine"},
    {0x04, "Treadmill"},
    {0x30, "Oar"},
    {0x31, "Slope"},
    {0x32, "Rate"},
    {0x33, "Stick Speed"},
    {0x34, "Stick Face Angle"},
    {0x35, "Stick Heel/Toe"},
    {0x36, "Stick Follow Through"},
    {0x37, "Stick Tempo"},
    {0x38, "Stick Type"},
    {0x39, "Stick Height"},
    {0x50, "Putter"},
    {0x51, "1 Iron"},
    {0x52, "2 Iron"},
    {0x53, "3 Iron"},
    {0x54, "4 Iron"},
    {0x55, "5 Iron"},
    {0x56, "6 Iron"},
    {0x57, "7 Iron"},
    {0x58, "8 Iron"},
    {0x59, "9 Iron"},
    {0x5A, "10 Iron"},
    {0x5B, "11 Iron"},
    {0x5C, "Sand Wedge"},
    {0x5D, "Loft Wedge"},
    {0x5E, "Power Wedge"},
    {0x5F, "1 Wood"},
    {0x60, "3 Wood"},
    {0x61, "5 Wood"},
    {0x62, "7 Wood"},
    {0x63, "9 Wood"},
    {0, NULL}
};
static const value_string usb_hid_game_controls_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "3D Game Controller"},
    {0x02, "Pinball Device"},
    {0x03, "Gun Device"},
    {0x20, "Point of View"},
    {0x21, "Turn Right/Left"},
    {0x22, "Pitch Forward/Backward"},
    {0x23, "Roll Right/Left"},
    {0x24, "Move Right/Left"},
    {0x25, "Move Forward/Backward"},
    {0x26, "Move Up/Down"},
    {0x27, "Lean Right/Left"},
    {0x28, "Lean Forward/Backward"},
    {0x29, "Height of POV"},
    {0x2A, "Flipper"},
    {0x2B, "Secondary Flipper"},
    {0x2C, "Bump"},
    {0x2D, "New Game"},
    {0x2E, "Shoot Ball"},
    {0x2F, "Player"},
    {0x30, "Gun Bolt"},
    {0x31, "Gun Clip"},
    {0x32, "Gun Selector"},
    {0x33, "Gun Single Shot"},
    {0x34, "Gun Burst"},
    {0x35, "Gun Automatic"},
    {0x36, "Gun Safety"},
    {0x37, "Gamepad Fire/Jump"},
    {0x39, "Gamepad Trigger"},
    {0x3A, "Form-fitting Gamepad"},
    {0, NULL}
};
static const value_string usb_hid_generic_device_controls_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Background/Nonuser Controls"},
    {0x20, "Battery Strength"},
    {0x21, "Wireless Channel"},
    {0x22, "Wireless ID"},
    {0x23, "Discover Wireless Control"},
    {0x24, "Security Code Character Entered"},
    {0x25, "Security Code Character Erased"},
    {0x26, "Security Code Cleared"},
    {0x27, "Sequence ID"},
    {0x28, "Sequence ID Reset"},
    {0x29, "RF Signal Strength"},
    {0x2A, "Software Version"},
    {0x2B, "Protocol Version"},
    {0x2C, "Hardware Version"},
    {0x2D, "Major"},
    {0x2E, "Minor"},
    {0x2F, "Revision"},
    {0x30, "Handedness"},
    {0x31, "Either Hand"},
    {0x32, "Left Hand"},
    {0x33, "Right Hand"},
    {0x34, "Both Hands"},
    {0x40, "Grip Pose Offset"},
    {0x41, "Pointer Pose Offset"},
    {0, NULL}
};
static const value_string usb_hid_keyboard_keypad_usage_page_vals[] = {
    {0x00, "Reserved (no event indicated)"},
    {0x01, "Keyboard ErrorRollOver"},
    {0x02, "Keyboard POSTFail"},
    {0x03, "Keyboard ErrorUndefined"},
    {0x04, "Keyboard a and A"},
    {0x05, "Keyboard b and B"},
    {0x06, "Keyboard c and C"},
    {0x07, "Keyboard d and D"},
    {0x08, "Keyboard e and E"},
    {0x09, "Keyboard f and F"},
    {0x0A, "Keyboard g and G"},
    {0x0B, "Keyboard h and H"},
    {0x0C, "Keyboard i and I"},
    {0x0D, "Keyboard j and J"},
    {0x0E, "Keyboard k and K"},
    {0x0F, "Keyboard l and L"},
    {0x10, "Keyboard m and M"},
    {0x11, "Keyboard n and N"},
    {0x12, "Keyboard o and O"},
    {0x13, "Keyboard p and P"},
    {0x14, "Keyboard q and Q"},
    {0x15, "Keyboard r and R"},
    {0x16, "Keyboard s and S"},
    {0x17, "Keyboard t and T"},
    {0x18, "Keyboard u and U"},
    {0x19, "Keyboard v and V"},
    {0x1A, "Keyboard w and W"},
    {0x1B, "Keyboard x and X"},
    {0x1C, "Keyboard y and Y"},
    {0x1D, "Keyboard z and Z"},
    {0x1E, "Keyboard 1 and !"},
    {0x1F, "Keyboard 2 and @"},
    {0x20, "Keyboard 3 and #"},
    {0x21, "Keyboard 4 and $"},
    {0x22, "Keyboard 5 and %"},
    {0x23, "Keyboard 6 and ^"},
    {0x24, "Keyboard 7 and &"},
    {0x25, "Keyboard 8 and *"},
    {0x26, "Keyboard 9 and ("},
    {0x27, "Keyboard 0 and )"},
    {0x28, "Keyboard Return (ENTER)"},
    {0x29, "Keyboard ESCAPE"},
    {0x2A, "Keyboard DELETE (Backspace)"},
    {0x2B, "Keyboard Tab"},
    {0x2C, "Keyboard Spacebar"},
    {0x2D, "Keyboard - and (underscore)"},
    {0x2E, "Keyboard = and +"},
    {0x2F, "Keyboard [ and {"},
    {0x30, "Keyboard ] and }"},
    {0x31, "Keyboard \\ and |"},
    {0x32, "Keyboard Non-US # and ~"},
    {0x33, "Keyboard ; and :"},
    {0x34, "Keyboard ' and \""},
    {0x35, "Keyboard Grave Accent and Tilde"},
    {0x36, "Keyboard , and <"},
    {0x37, "Keyboard . and >"},
    {0x38, "Keyboard / and ?"},
    {0x39, "Keyboard Caps Lock"},
    {0x3A, "Keyboard F1"},
    {0x3B, "Keyboard F2"},
    {0x3C, "Keyboard F3"},
    {0x3D, "Keyboard F4"},
    {0x3E, "Keyboard F5"},
    {0x3F, "Keyboard F6"},
    {0x40, "Keyboard F7"},
    {0x41, "Keyboard F8"},
    {0x42, "Keyboard F9"},
    {0x43, "Keyboard F10"},
    {0x44, "Keyboard F11"},
    {0x45, "Keyboard F12"},
    {0x46, "Keyboard PrintScreen"},
    {0x47, "Keyboard Scroll Lock"},
    {0x48, "Keyboard Pause"},
    {0x49, "Keyboard Insert"},
    {0x4A, "Keyboard Home"},
    {0x4B, "Keyboard PageUp"},
    {0x4C, "Keyboard Delete Forward"},
    {0x4D, "Keyboard End"},
    {0x4E, "Keyboard PageDown"},
    {0x4F, "Keyboard RightArrow"},
    {0x50, "Keyboard LeftArrow"},
    {0x51, "Keyboard DownArrow"},
    {0x52, "Keyboard UpArrow"},
    {0x53, "Keypad Num Lock and Clear"},
    {0x54, "Keypad /"},
    {0x55, "Keypad *"},
    {0x56, "Keypad -"},
    {0x57, "Keypad +"},
    {0x58, "Keypad ENTER"},
    {0x59, "Keypad 1 and End"},
    {0x5A, "Keypad 2 and Down Arrow"},
    {0x5B, "Keypad 3 and PageDn"},
    {0x5C, "Keypad 4 and Left Arrow"},
    {0x5D, "Keypad 5"},
    {0x5E, "Keypad 6 and Right Arrow"},
    {0x5F, "Keypad 7 and Home"},
    {0x60, "Keypad 8 and Up Arrow"},
    {0x61, "Keypad 9 and PageUp"},
    {0x62, "Keypad 0 and Insert"},
    {0x63, "Keypad . and Delete"},
    {0x64, "Keyboard Non-US \\ and |"},
    {0x65, "Keyboard Application"},
    {0x66, "Keyboard Power"},
    {0x67, "Keypad ="},
    {0x68, "Keyboard F13"},
    {0x69, "Keyboard F14"},
    {0x6A, "Keyboard F15"},
    {0x6B, "Keyboard F16"},
    {0x6C, "Keyboard F17"},
    {0x6D, "Keyboard F18"},
    {0x6E, "Keyboard F19"},
    {0x6F, "Keyboard F20"},
    {0x70, "Keyboard F21"},
    {0x71, "Keyboard F22"},
    {0x72, "Keyboard F23"},
    {0x73, "Keyboard F24"},
    {0x74, "Keyboard Execute"},
    {0x75, "Keyboard Help"},
    {0x76, "Keyboard Menu"},
    {0x77, "Keyboard Select"},
    {0x78, "Keyboard Stop"},
    {0x79, "Keyboard Again"},
    {0x7A, "Keyboard Undo"},
    {0x7B, "Keyboard Cut"},
    {0x7C, "Keyboard Copy"},
    {0x7D, "Keyboard Paste"},
    {0x7E, "Keyboard Find"},
    {0x7F, "Keyboard Mute"},
    {0x80, "Keyboard Volume Up"},
    {0x81, "Keyboard Volume Down"},
    {0x82, "Keyboard Locking Caps Lock"},
    {0x83, "Keyboard Locking Num Lock"},
    {0x84, "Keyboard Locking Scroll Lock"},
    {0x85, "Keypad Comma"},
    {0x86, "Keypad Equal Sign"},
    {0x87, "Keyboard International1"},
    {0x88, "Keyboard International2"},
    {0x89, "Keyboard International3"},
    {0x8A, "Keyboard International4"},
    {0x8B, "Keyboard International5"},
    {0x8C, "Keyboard International6"},
    {0x8D, "Keyboard International7"},
    {0x8E, "Keyboard International8"},
    {0x8F, "Keyboard International9"},
    {0x90, "Keyboard LANG1"},
    {0x91, "Keyboard LANG2"},
    {0x92, "Keyboard LANG3"},
    {0x93, "Keyboard LANG4"},
    {0x94, "Keyboard LANG5"},
    {0x95, "Keyboard LANG6"},
    {0x96, "Keyboard LANG7"},
    {0x97, "Keyboard LANG8"},
    {0x98, "Keyboard LANG9"},
    {0x99, "Keyboard Alternate Erase"},
    {0x9A, "Keyboard SysReq/Attention"},
    {0x9B, "Keyboard Cancel"},
    {0x9C, "Keyboard Clear"},
    {0x9D, "Keyboard Prior"},
    {0x9E, "Keyboard Return"},
    {0x9F, "Keyboard Separator"},
    {0xA0, "Keyboard Out"},
    {0xA1, "Keyboard Oper"},
    {0xA2, "Keyboard Clear/Again"},
    {0xA3, "Keyboard CrSel/Props"},
    {0xA4, "Keyboard ExSel"},
    {0xB0, "Keypad 00"},
    {0xB1, "Keypad 000"},
    {0xB2, "Thousands Separator"},
    {0xB3, "Decimal Separator"},
    {0xB4, "Currency Unit"},
    {0xB5, "Currency Sub-unit"},
    {0xB6, "Keypad ("},
    {0xB7, "Keypad )"},
    {0xB8, "Keypad {"},
    {0xB9, "Keypad }"},
    {0xBA, "Keypad Tab"},
    {0xBB, "Keypad Backspace"},
    {0xBC, "Keypad A"},
    {0xBD, "Keypad B"},
    {0xBE, "Keypad C"},
    {0xBF, "Keypad D"},
    {0xC0, "Keypad E"},
    {0xC1, "Keypad F"},
    {0xC2, "Keypad XOR"},
    {0xC3, "Keypad ^"},
    {0xC4, "Keypad %"},
    {0xC5, "Keypad <"},
    {0xC6, "Keypad >"},
    {0xC7, "Keypad &"},
    {0xC8, "Keypad &&"},
    {0xC9, "Keypad |"},
    {0xCA, "Keypad ||"},
    {0xCB, "Keypad :"},
    {0xCC, "Keypad #"},
    {0xCD, "Keypad Space"},
    {0xCE, "Keypad @"},
    {0xCF, "Keypad !"},
    {0xD0, "Keypad Memory Store"},
    {0xD1, "Keypad Memory Recall"},
    {0xD2, "Keypad Memory Clear"},
    {0xD3, "Keypad Memory Add"},
    {0xD4, "Keypad Memory Subtract"},
    {0xD5, "Keypad Memory Multiply"},
    {0xD6, "Keypad Memory Divide"},
    {0xD7, "Keypad +/-"},
    {0xD8, "Keypad Clear"},
    {0xD9, "Keypad Clear Entry"},
    {0xDA, "Keypad Binary"},
    {0xDB, "Keypad Octal"},
    {0xDC, "Keypad Decimal"},
    {0xDD, "Keypad Hexadecimal"},
    {0xE0, "Keyboard LeftControl"},
    {0xE1, "Keyboard LeftShift"},
    {0xE2, "Keyboard LeftAlt"},
    {0xE3, "Keyboard Left GUI"},
    {0xE4, "Keyboard RightControl"},
    {0xE5, "Keyboard RightShift"},
    {0xE6, "Keyboard RightAlt"},
    {0xE7, "Keyboard Right GUI"},
    {0, NULL}
};
static const value_string usb_hid_led_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Num Lock"},
    {0x02, "Caps Lock"},
    {0x03, "Scroll Lock"},
    {0x04, "Compose"},
    {0x05, "Kana"},
    {0x06, "Power"},
    {0x07, "Shift"},
    {0x08, "Do Not Disturb"},
    {0x09, "Mute"},
    {0x0A, "Tone Enable"},
    {0x0B, "High Cut Filter"},
    {0x0C, "Low Cut Filter"},
    {0x0D, "Equalizer Enable"},
    {0x0E, "Sound Field On"},
    {0x0F, "Surround On"},
    {0x10, "Repeat"},
    {0x11, "Stereo"},
    {0x12, "Sampling Rate Detect"},
    {0x13, "Spinning"},
    {0x14, "CAV"},
    {0x15, "CLV"},
    {0x16, "Recording Format Detect"},
    {0x17, "Off-Hook"},
    {0x18, "Ring"},
    {0x19, "Message Waiting"},
    {0x1A, "Data Mode"},
    {0x1B, "Battery Operation"},
    {0x1C, "Battery OK"},
    {0x1D, "Battery Low"},
    {0x1E, "Speaker"},
    {0x1F, "Head Set"},
    {0x20, "Hold"},
    {0x21, "Microphone"},
    {0x22, "Coverage"},
    {0x23, "Night Mode"},
    {0x24, "Send Calls"},
    {0x25, "Call Pickup"},
    {0x26, "Conference"},
    {0x27, "Stand-by"},
    {0x28, "Camera On"},
    {0x29, "Camera Off"},
    {0x2A, "On-Line"},
    {0x2B, "Off-Line"},
    {0x2C, "Busy"},
    {0x2D, "Ready"},
    {0x2E, "Paper-Out"},
    {0x2F, "Paper-Jam"},
    {0x30, "Remote"},
    {0x31, "Forward"},
    {0x32, "Reverse"},
    {0x33, "Stop"},
    {0x34, "Rewind"},
    {0x35, "Fast Forward"},
    {0x36, "Play"},
    {0x37, "Pause"},
    {0x38, "Record"},
    {0x39, "Error"},
    {0x3A, "Usage Selected Indicator"},
    {0x3B, "Usage In Use Indicator"},
    {0x3C, "Usage Multi Mode Indicator"},
    {0x3D, "Indicator On"},
    {0x3E, "Indicator Flash"},
    {0x3F, "Indicator Slow Blink"},
    {0x40, "Indicator Fast Blink"},
    {0x41, "Indicator Off"},
    {0x42, "Flash On Time"},
    {0x43, "Slow Blink On Time"},
    {0x44, "Slow Blink Off Time"},
    {0x45, "Fast Blink On Time"},
    {0x46, "Fast Blink Off Time"},
    {0x47, "Usage Indicator Color"},
    {0x48, "Indicator Red"},
    {0x49, "Indicator Green"},
    {0x4A, "Indicator Amber"},
    {0x4B, "Generic Indicator"},
    {0x4C, "System Suspend"},
    {0x4D, "External Power Connected"},
    {0x4E, "Indicator Blue"},
    {0x4F, "Indicator Orange"},
    {0x50, "Good Status"},
    {0x51, "Warning Status"},
    {0x52, "RGB LED"},
    {0x53, "Red LED Channel"},
    {0x54, "Blue LED Channel"},
    {0x55, "Green LED Channel"},
    {0x56, "LED Intensity"},
    {0x60, "Player Indicator"},
    {0x61, "Player 1"},
    {0x62, "Player 2"},
    {0x63, "Player 3"},
    {0x64, "Player 4"},
    {0x65, "Player 5"},
    {0x66, "Player 6"},
    {0x67, "Player 7"},
    {0x68, "Player 8"},
    {0, NULL}
};
static const value_string usb_hid_button_usage_page_vals[] = {
    {0x00, "No button pressed"},
    {0x01, "Button 1 (primary/trigger)"},
    {0x02, "Button 2 (secondary)"},
    {0x03, "Button 3 (tertiary)"},
    /* Other Buttons parsed as "Button %u" in get_usage_page_item_string */
    {0, NULL}
};
static const value_string usb_hid_ordinal_usage_page_vals[] = {
    {0x00, "Reserved"},
    /* Instances parsed as "Instance %u" in get_usage_page_item_string */
    {0, NULL}
};
static const value_string usb_hid_telephony_device_usage_page_vals[] = {
    {0x000, "Undefined"},
    {0x001, "Phone"},
    {0x002, "Answering Machine"},
    {0x003, "Message Controls"},
    {0x004, "Handset"},
    {0x005, "Headset"},
    {0x006, "Telephony Key Pad"},
    {0x007, "Programmable Button"},
    {0x020, "Hook Switch"},
    {0x021, "Flash"},
    {0x022, "Feature"},
    {0x023, "Hold"},
    {0x024, "Redial"},
    {0x025, "Transfer"},
    {0x026, "Drop"},
    {0x027, "Park"},
    {0x028, "Forward Calls"},
    {0x029, "Alternate Function"},
    {0x02A, "Line"},
    {0x02B, "Speaker Phone"},
    {0x02C, "Conference"},
    {0x02D, "Ring Enable"},
    {0x02E, "Ring Select"},
    {0x02F, "Phone Mute"},
    {0x030, "Caller ID"},
    {0x031, "Send"},
    {0x050, "Speed Dial"},
    {0x051, "Store Number"},
    {0x052, "Recall Number"},
    {0x053, "Phone Directory"},
    {0x070, "Voice Mail"},
    {0x071, "Screen Calls"},
    {0x072, "Do Not Disturb"},
    {0x073, "Message"},
    {0x074, "Answer On/Off"},
    {0x090, "Inside Dial Tone"},
    {0x091, "Outside Dial Tone"},
    {0x092, "Inside Ring Tone"},
    {0x093, "Outside Ring Tone"},
    {0x094, "Priority Ring Tone"},
    {0x095, "Inside Ringback"},
    {0x096, "Priority Ringback"},
    {0x097, "Line Busy Tone"},
    {0x098, "Reorder Tone"},
    {0x099, "Call Waiting Tone"},
    {0x09A, "Confirmation Tone 1"},
    {0x09B, "Confirmation Tone 2"},
    {0x09C, "Tones Off"},
    {0x09D, "Outside Ringback"},
    {0x09E, "Ringer"},
    {0x0B0, "Phone Key 0"},
    {0x0B1, "Phone Key 1"},
    {0x0B2, "Phone Key 2"},
    {0x0B3, "Phone Key 3"},
    {0x0B4, "Phone Key 4"},
    {0x0B5, "Phone Key 5"},
    {0x0B6, "Phone Key 6"},
    {0x0B7, "Phone Key 7"},
    {0x0B8, "Phone Key 8"},
    {0x0B9, "Phone Key 9"},
    {0x0BA, "Phone Key Star"},
    {0x0BB, "Phone Key Pound"},
    {0x0BC, "Phone Key A"},
    {0x0BD, "Phone Key B"},
    {0x0BE, "Phone Key C"},
    {0x0BF, "Phone Key D"},
    {0x0C0, "Phone Call History Key"},
    {0x0C1, "Phone Caller ID Key"},
    {0x0C2, "Phone Settings Key"},
    {0x0F0, "Host Control"},
    {0x0F1, "Host Available"},
    {0x0F2, "Host Call Active"},
    {0x0F3, "Activate Handset Audio"},
    {0x0F4, "Ring Type"},
    {0x0F5, "Re-dialable Phone Number"},
    {0x0F8, "Stop Ring Tone"},
    {0x0F9, "PSTN Ring Tone"},
    {0x0FA, "Host Ring Tone"},
    {0x0FB, "Alert Sound Error"},
    {0x0FC, "Alert Sound Confirm"},
    {0x0FD, "Alert Sound Notification"},
    {0x0FE, "Silent Ring"},
    {0x108, "Email Message Waiting"},
    {0x109, "Voicemail Message Waiting"},
    {0x10A, "Host Hold"},
    {0x110, "Incoming Call History Count"},
    {0x111, "Outgoing Call History Count"},
    {0x112, "Incoming Call History"},
    {0x113, "Outgoing Call History"},
    {0x114, "Phone Locale"},
    {0x140, "Phone Time Second"},
    {0x141, "Phone Time Minute"},
    {0x142, "Phone Time Hour"},
    {0x143, "Phone Date Day"},
    {0x144, "Phone Date Month"},
    {0x145, "Phone Date Year"},
    {0x146, "Handset Nickname"},
    {0x147, "Address Book ID"},
    {0x14A, "Call Duration"},
    {0x14B, "Dual Mode Phone"},
    {0, NULL}
};
static const value_string usb_hid_consumer_usage_page_vals[] = {
    {0x000, "Undefined"},
    {0x001, "Consumer Control"},
    {0x002, "Numeric Key Pad"},
    {0x003, "Programmable Buttons"},
    {0x004, "Microphone"},
    {0x005, "Headphone"},
    {0x006, "Graphic Equalizer"},
    {0x020, "+10"},
    {0x021, "+100"},
    {0x022, "AM/PM"},
    {0x030, "Power"},
    {0x031, "Reset"},
    {0x032, "Sleep"},
    {0x033, "Sleep After"},
    {0x034, "Sleep Mode"},
    {0x035, "Illumination"},
    {0x036, "Function Buttons"},
    {0x040, "Menu"},
    {0x041, "Menu Pick"},
    {0x042, "Menu Up"},
    {0x043, "Menu Down"},
    {0x044, "Menu Left"},
    {0x045, "Menu Right"},
    {0x046, "Menu Escape"},
    {0x047, "Menu Value Increase"},
    {0x048, "Menu Value Decrease"},
    {0x060, "Data On Screen"},
    {0x061, "Closed Caption"},
    {0x062, "Closed Caption Select"},
    {0x063, "VCR/TV"},
    {0x064, "Broadcast Mode"},
    {0x065, "Snapshot"},
    {0x066, "Still"},
    {0x067, "Picture-in-Picture Toggle"},
    {0x068, "Picture-in-Picture Swap"},
    {0x069, "Red Menu Button"},
    {0x06A, "Green Menu Button"},
    {0x06B, "Blue Menu Button"},
    {0x06C, "Yellow Menu Button"},
    {0x06D, "Aspect"},
    {0x06E, "3D Mode Select"},
    {0x06F, "Display Brightness Increment"},
    {0x070, "Display Brightness Decrement"},
    {0x071, "Display Brightness"},
    {0x072, "Display Backlight Toggle"},
    {0x073, "Display Set Brightness to Minimum"},
    {0x074, "Display Set Brightness to Maximum"},
    {0x075, "Display Set Auto Brightness"},
    {0x076, "Camera Access Enabled"},
    {0x077, "Camera Access Disabled"},
    {0x078, "Camera Access Toggle"},
    {0x079, "Keyboard Brightness Increment"},
    {0x07A, "Keyboard Brightness Decrement"},
    {0x07B, "Keyboard Backlight Set Level"},
    {0x07C, "Keyboard Backlight OOC"},
    {0x07D, "Keyboard Backlight Set Minimum"},
    {0x07E, "Keyboard Backlight Set Maximum"},
    {0x07F, "Keyboard Backlight Auto"},
    {0x080, "Selection"},
    {0x081, "Assign Selection"},
    {0x082, "Mode Step"},
    {0x083, "Recall Last"},
    {0x084, "Enter Channel"},
    {0x085, "Order Movie"},
    {0x086, "Channel"},
    {0x087, "Media Selection"},
    {0x088, "Media Select Computer"},
    {0x089, "Media Select TV"},
    {0x08A, "Media Select WWW"},
    {0x08B, "Media Select DVD"},
    {0x08C, "Media Select Telephone"},
    {0x08D, "Media Select Program Guide"},
    {0x08E, "Media Select Video Phone"},
    {0x08F, "Media Select Games"},
    {0x090, "Media Select Messages"},
    {0x091, "Media Select CD"},
    {0x092, "Media Select VCR"},
    {0x093, "Media Select Tuner"},
    {0x094, "Quit"},
    {0x095, "Help"},
    {0x096, "Media Select Tape"},
    {0x097, "Media Select Cable"},
    {0x098, "Media Select Satellite"},
    {0x099, "Media Select Security"},
    {0x09A, "Media Select Home"},
    {0x09B, "Media Select Call"},
    {0x09C, "Channel Increment"},
    {0x09D, "Channel Decrement"},
    {0x09E, "Media Select SAP"},
    {0x0A0, "VCR Plus"},
    {0x0A1, "Once"},
    {0x0A2, "Daily"},
    {0x0A3, "Weekly"},
    {0x0A4, "Monthly"},
    {0x0B0, "Play"},
    {0x0B1, "Pause"},
    {0x0B2, "Record"},
    {0x0B3, "Fast Forward"},
    {0x0B4, "Rewind"},
    {0x0B5, "Scan Next Track"},
    {0x0B6, "Scan Previous Track"},
    {0x0B7, "Stop"},
    {0x0B8, "Eject"},
    {0x0B9, "Random Play"},
    {0x0BA, "Select Disc"},
    {0x0BB, "Enter Disc"},
    {0x0BC, "Repeat"},
    {0x0BD, "Tracking"},
    {0x0BE, "Track Normal"},
    {0x0BF, "Slow Tracking"},
    {0x0C0, "Frame Forward"},
    {0x0C1, "Frame Back"},
    {0x0C2, "Mark"},
    {0x0C3, "Clear Mark"},
    {0x0C4, "Repeat From Mark"},
    {0x0C5, "Return To Mark"},
    {0x0C6, "Search Mark Forward"},
    {0x0C7, "Search Mark Backwards"},
    {0x0C8, "Counter Reset"},
    {0x0C9, "Show Counter"},
    {0x0CA, "Tracking Increment"},
    {0x0CB, "Tracking Decrement"},
    {0x0CC, "Stop/Eject"},
    {0x0CD, "Play/Pause"},
    {0x0CE, "Play/Skip"},
    {0x0CF, "Voice Command"},
    {0x0D0, "Invoke Capture Interface"},
    {0x0D1, "Start or Stop Game Recording"},
    {0x0D2, "Historical Game Capture"},
    {0x0D3, "Capture Game Screenshot"},
    {0x0D4, "Show or Hide Recording Indicator"},
    {0x0D5, "Start or Stop Microphone Capture"},
    {0x0D6, "Start or Stop Camera Capture"},
    {0x0D7, "Start or Stop Game Broadcast"},
    {0x0D8, "Start or Stop Voice Dictation Session"},
    {0x0E0, "Volume"},
    {0x0E1, "Balance"},
    {0x0E2, "Mute"},
    {0x0E3, "Bass"},
    {0x0E4, "Treble"},
    {0x0E5, "Bass Boost"},
    {0x0E6, "Surround Mode"},
    {0x0E7, "Loudness"},
    {0x0E8, "MPX"},
    {0x0E9, "Volume Increment"},
    {0x0EA, "Volume Decrement"},
    {0x0F0, "Speed Select"},
    {0x0F1, "Playback Speed"},
    {0x0F2, "Standard Play"},
    {0x0F3, "Long Play"},
    {0x0F4, "Extended Play"},
    {0x0F5, "Slow"},
    {0x100, "Fan Enable"},
    {0x101, "Fan Speed"},
    {0x102, "Light Enable"},
    {0x103, "Light Illumination Level"},
    {0x104, "Climate Control Enable"},
    {0x105, "Room Temperature"},
    {0x106, "Security Enable"},
    {0x107, "Fire Alarm"},
    {0x108, "Police Alarm"},
    {0x109, "Proximity"},
    {0x10A, "Motion"},
    {0x10B, "Duress Alarm"},
    {0x10C, "Holdup Alarm"},
    {0x10D, "Medical Alarm"},
    {0x150, "Balance Right"},
    {0x151, "Balance Left"},
    {0x152, "Bass Increment"},
    {0x153, "Bass Decrement"},
    {0x154, "Treble Increment"},
    {0x155, "Treble Decrement"},
    {0x160, "Speaker System"},
    {0x161, "Channel Left"},
    {0x162, "Channel Right"},
    {0x163, "Channel Center"},
    {0x164, "Channel Front"},
    {0x165, "Channel Center Front"},
    {0x166, "Channel Side"},
    {0x167, "Channel Surround"},
    {0x168, "Channel Low Frequency Enhancement"},
    {0x169, "Channel Top"},
    {0x16A, "Channel Unknown"},
    {0x170, "Sub-channel"},
    {0x171, "Sub-channel Increment"},
    {0x172, "Sub-channel Decrement"},
    {0x173, "Alternate Audio Increment"},
    {0x174, "Alternate Audio Decrement"},
    {0x180, "Application Launch Buttons"},
    {0x181, "AL Launch Button Configuration Tool"},
    {0x182, "AL Programmable Button Configuration"},
    {0x183, "AL Consumer Control Configuration"},
    {0x184, "AL Word Processor"},
    {0x185, "AL Text Editor"},
    {0x186, "AL Spreadsheet"},
    {0x187, "AL Graphics Editor"},
    {0x188, "AL Presentation App"},
    {0x189, "AL Database App"},
    {0x18A, "AL Email Reader"},
    {0x18B, "AL Newsreader"},
    {0x18C, "AL Voicemail"},
    {0x18D, "AL Contacts/Address Book"},
    {0x18E, "AL Calendar/Schedule"},
    {0x18F, "AL Task/Project Manager"},
    {0x190, "AL Log/Journal/Timecard"},
    {0x191, "AL Checkbook/Finance"},
    {0x192, "AL Calculator"},
    {0x193, "AL A/V Capture/Playback"},
    {0x194, "AL Local Machine Browser"},
    {0x195, "AL LAN/WAN Browser"},
    {0x196, "AL Internet Browser"},
    {0x197, "AL Remote Networking/ISP Connect"},
    {0x198, "AL Network Conference"},
    {0x199, "AL Network Chat"},
    {0x19A, "AL Telephony/Dialer"},
    {0x19B, "AL Logon"},
    {0x19C, "AL Logoff"},
    {0x19D, "AL Logon/Logoff"},
    {0x19E, "AL Terminal Lock/Screensaver"},
    {0x19F, "AL Control Panel"},
    {0x1A0, "AL Command Line Processor/Run"},
    {0x1A1, "AL Process/Task Manager"},
    {0x1A2, "AL Select Task/Application"},
    {0x1A3, "AL Next Task/Application"},
    {0x1A4, "AL Previous Task/Application"},
    {0x1A5, "AL Preemptive Halt Task/Application"},
    {0x1A6, "AL Integrated Help Center"},
    {0x1A7, "AL Documents"},
    {0x1A8, "AL Thesaurus"},
    {0x1A9, "AL Dictionary"},
    {0x1AA, "AL Desktop"},
    {0x1AB, "AL Spell Check"},
    {0x1AC, "AL Grammar Check"},
    {0x1AD, "AL Wireless Status"},
    {0x1AE, "AL Keyboard Layout"},
    {0x1AF, "AL Virus Protection"},
    {0x1B0, "AL Encryption"},
    {0x1B1, "AL Screen Saver"},
    {0x1B2, "AL Alarms"},
    {0x1B3, "AL Clock"},
    {0x1B4, "AL File Browser"},
    {0x1B5, "AL Power Status"},
    {0x1B6, "AL Image Browser"},
    {0x1B7, "AL Audio Browser"},
    {0x1B8, "AL Movie Browser"},
    {0x1B9, "AL Digital Rights Manager"},
    {0x1BA, "AL Digital Wallet"},
    {0x1BC, "AL Instant Messaging"},
    {0x1BD, "AL OEM Features/ Tips/Tutorial Browser"},
    {0x1BE, "AL OEM Help"},
    {0x1BF, "AL Online Community"},
    {0x1C0, "AL Entertainment Content Browser"},
    {0x1C1, "AL Online Shopping Browser"},
    {0x1C2, "AL SmartCard Information/Help"},
    {0x1C3, "AL Market Monitor/Finance Browser"},
    {0x1C4, "AL Customized Corporate News Browser"},
    {0x1C5, "AL Online Activity Browser"},
    {0x1C6, "AL Research/Search Browser"},
    {0x1C7, "AL Audio Player"},
    {0x1C8, "AL Message Status"},
    {0x1C9, "AL Contact Sync"},
    {0x1CA, "AL Navigation"},
    {0x1CB, "AL Context-aware Desktop Assistant"},
    {0x200, "Generic GUI Application Controls"},
    {0x201, "AC New"},
    {0x202, "AC Open"},
    {0x203, "AC Close"},
    {0x204, "AC Exit"},
    {0x205, "AC Maximize"},
    {0x206, "AC Minimize"},
    {0x207, "AC Save"},
    {0x208, "AC Print"},
    {0x209, "AC Properties"},
    {0x21A, "AC Undo"},
    {0x21B, "AC Copy"},
    {0x21C, "AC Cut"},
    {0x21D, "AC Paste"},
    {0x21E, "AC Select All"},
    {0x21F, "AC Find"},
    {0x220, "AC Find and Replace"},
    {0x221, "AC Search"},
    {0x222, "AC Go To"},
    {0x223, "AC Home"},
    {0x224, "AC Back"},
    {0x225, "AC Forward"},
    {0x226, "AC Stop"},
    {0x227, "AC Refresh"},
    {0x228, "AC Previous Link"},
    {0x229, "AC Next Link"},
    {0x22A, "AC Bookmarks"},
    {0x22B, "AC History"},
    {0x22C, "AC Subscriptions"},
    {0x22D, "AC Zoom In"},
    {0x22E, "AC Zoom Out"},
    {0x22F, "AC Zoom"},
    {0x230, "AC Full Screen View"},
    {0x231, "AC Normal View"},
    {0x232, "AC View Toggle"},
    {0x233, "AC Scroll Up"},
    {0x234, "AC Scroll Down"},
    {0x235, "AC Scroll"},
    {0x236, "AC Pan Left"},
    {0x237, "AC Pan Right"},
    {0x238, "AC Pan"},
    {0x239, "AC New Window"},
    {0x23A, "AC Tile Horizontally"},
    {0x23B, "AC Tile Vertically"},
    {0x23C, "AC Format"},
    {0x23D, "AC Edit"},
    {0x23E, "AC Bold"},
    {0x23F, "AC Italics"},
    {0x240, "AC Underline"},
    {0x241, "AC Strikethrough"},
    {0x242, "AC Subscript"},
    {0x243, "AC Superscript"},
    {0x244, "AC All Caps"},
    {0x245, "AC Rotate"},
    {0x246, "AC Resize"},
    {0x247, "AC Flip Horizontal"},
    {0x248, "AC Flip Vertical"},
    {0x249, "AC Mirror Horizontal"},
    {0x24A, "AC Mirror Vertical"},
    {0x24B, "AC Font Select"},
    {0x24C, "AC Font Color"},
    {0x24D, "AC Font Size"},
    {0x24E, "AC Justify Left"},
    {0x24F, "AC Justify Center H"},
    {0x250, "AC Justify Right"},
    {0x251, "AC Justify Block H"},
    {0x252, "AC Justify Top"},
    {0x253, "AC Justify Center V"},
    {0x254, "AC Justify Bottom"},
    {0x255, "AC Justify Block V"},
    {0x256, "AC Indent Decrease"},
    {0x257, "AC Indent Increase"},
    {0x258, "AC Numbered List"},
    {0x259, "AC Restart Numbering"},
    {0x25A, "AC Bulleted List"},
    {0x25B, "AC Promote"},
    {0x25C, "AC Demote"},
    {0x25D, "AC Yes"},
    {0x25E, "AC No"},
    {0x25F, "AC Cancel"},
    {0x260, "AC Catalog"},
    {0x261, "AC Buy/Checkout"},
    {0x262, "AC Add to Cart"},
    {0x263, "AC Expand"},
    {0x264, "AC Expand All"},
    {0x265, "AC Collapse"},
    {0x266, "AC Collapse All"},
    {0x267, "AC Print Preview"},
    {0x268, "AC Paste Special"},
    {0x269, "AC Insert Mode"},
    {0x26A, "AC Delete"},
    {0x26B, "AC Lock"},
    {0x26C, "AC Unlock"},
    {0x26D, "AC Protect"},
    {0x26E, "AC Unprotect"},
    {0x26F, "AC Attach Comment"},
    {0x270, "AC Delete Comment"},
    {0x271, "AC View Comment"},
    {0x272, "AC Select Word"},
    {0x273, "AC Select Sentence"},
    {0x274, "AC Select Paragraph"},
    {0x275, "AC Select Column"},
    {0x276, "AC Select Row"},
    {0x277, "AC Select Table"},
    {0x278, "AC Select Object"},
    {0x279, "AC Redo/Repeat"},
    {0x27A, "AC Sort"},
    {0x27B, "AC Sort Ascending"},
    {0x27C, "AC Sort Descending"},
    {0x27D, "AC Filter"},
    {0x27E, "AC Set Clock"},
    {0x27F, "AC View Clock"},
    {0x280, "AC Select Time Zone"},
    {0x281, "AC Edit Time Zones"},
    {0x282, "AC Set Alarm"},
    {0x283, "AC Clear Alarm"},
    {0x284, "AC Snooze Alarm"},
    {0x285, "AC Reset Alarm"},
    {0x286, "AC Synchronize"},
    {0x287, "AC Send/Receive"},
    {0x288, "AC Send To"},
    {0x289, "AC Reply"},
    {0x28A, "AC Reply All"},
    {0x28B, "AC Forward Msg"},
    {0x28C, "AC Send"},
    {0x28D, "AC Attach File"},
    {0x28E, "AC Upload"},
    {0x28F, "AC Download (Save Target As)"},
    {0x290, "AC Set Borders"},
    {0x291, "AC Insert Row"},
    {0x292, "AC Insert Column"},
    {0x293, "AC Insert File"},
    {0x294, "AC Insert Picture"},
    {0x295, "AC Insert Object"},
    {0x296, "AC Insert Symbol"},
    {0x297, "AC Save and Close"},
    {0x298, "AC Rename"},
    {0x299, "AC Merge"},
    {0x29A, "AC Split"},
    {0x29B, "AC Distribute Horizontally"},
    {0x29C, "AC Distribute Vertically"},
    {0x29D, "AC Next Keyboard Layout Select"},
    {0x29E, "AC Navigation Guidance"},
    {0x29F, "AC Desktop Show All Windows"},
    {0x2A0, "AC Soft Key Left"},
    {0x2A1, "AC Soft Key Right"},
    {0x2A2, "AC Desktop Show All Applications"},
    {0x2B0, "AC Idle Keep Alive"},
    {0x2C0, "Extended Keyboard Attributes Collection"},
    {0x2C1, "Keyboard Form Factor"},
    {0x2C2, "Keyboard Key Type"},
    {0x2C3, "Keyboard Physical Layout"},
    {0x2C4, "Vendor-Specific Keyboard Physical Layout"},
    {0x2C5, "Keyboard IETF Language Tag Index"},
    {0x2C6, "Implemented Keyboard Input Assist Controls"},
    {0x2C7, "Keyboard Input Assist Previous"},
    {0x2C8, "Keyboard Input Assist Next"},
    {0x2C9, "Keyboard Input Assist Previous Group"},
    {0x2CA, "Keyboard Input Assist Next Group"},
    {0x2CB, "Keyboard Input Assist Accept"},
    {0x2CC, "Keyboard Input Assist Cancel"},
    {0x2D0, "Privacy Screen Toggle"},
    {0x2D1, "Privacy Screen Level Decrement"},
    {0x2D2, "Privacy Screen Level Increment"},
    {0x2D3, "Privacy Screen Level Minimum"},
    {0x2D4, "Privacy Screen Level Maximum"},
    {0x500, "Contact Edited"},
    {0x501, "Contact Added"},
    {0x502, "Contact Record Active"},
    {0x503, "Contact Index"},
    {0x504, "Contact Nickname"},
    {0x505, "Contact First Name"},
    {0x506, "Contact Last Name"},
    {0x507, "Contact Full Name"},
    {0x508, "Contact Phone Number Personal"},
    {0x509, "Contact Phone Number Business"},
    {0x50A, "Contact Phone Number Mobile"},
    {0x50B, "Contact Phone Number Pager"},
    {0x50C, "Contact Phone Number Fax"},
    {0x50D, "Contact Phone Number Other"},
    {0x50E, "Contact Email Personal"},
    {0x50F, "Contact Email Business"},
    {0x510, "Contact Email Other"},
    {0x511, "Contact Email Main"},
    {0x512, "Contact Speed Dial Number"},
    {0x513, "Contact Status Flag"},
    {0x514, "Contact Misc."},
    {0, NULL}
};
static const value_string usb_hid_digitizers_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Digitizer"},
    {0x02, "Pen"},
    {0x03, "Light Pen"},
    {0x04, "Touch Screen"},
    {0x05, "Touch Pad"},
    {0x06, "Whiteboard"},
    {0x07, "Coordinate Measuring Machine"},
    {0x08, "3D Digitizer"},
    {0x09, "Stereo Plotter"},
    {0x0A, "Articulated Arm"},
    {0x0B, "Armature"},
    {0x0C, "Multiple Point Digitizer"},
    {0x0D, "Free Space Wand"},
    {0x0E, "Device Configuration"},
    {0x0F, "Capacitive Heat Map Digitizer"},
    {0x20, "Stylus"},
    {0x21, "Puck"},
    {0x22, "Finger"},
    {0x23, "Device settings"},
    {0x24, "Character Gesture"},
    {0x30, "Tip Pressure"},
    {0x31, "Barrel Pressure"},
    {0x32, "In Range"},
    {0x33, "Touch"},
    {0x34, "Untouch"},
    {0x35, "Tap"},
    {0x36, "Quality"},
    {0x37, "Data Valid"},
    {0x38, "Transducer Index"},
    {0x39, "Tablet Function Keys"},
    {0x3A, "Program Change Keys"},
    {0x3B, "Battery Strength"},
    {0x3C, "Invert"},
    {0x3D, "X Tilt"},
    {0x3E, "Y Tilt"},
    {0x3F, "Azimuth"},
    {0x40, "Altitude"},
    {0x41, "Twist"},
    {0x42, "Tip Switch"},
    {0x43, "Secondary Tip Switch"},
    {0x44, "Barrel Switch"},
    {0x45, "Eraser"},
    {0x46, "Tablet Pick"},
    {0x47, "Touch Valid"},
    {0x48, "Width"},
    {0x49, "Height"},
    {0x51, "Contact Identifier"},
    {0x52, "Device Mode"},
    {0x53, "Device Identifier"},
    {0x54, "Contact Count"},
    {0x55, "Contact Count Maximum"},
    {0x56, "Scan Time"},
    {0x57, "Surface Switch"},
    {0x58, "Button Switch"},
    {0x59, "Pad Type"},
    {0x5A, "Secondary Barrel Switch"},
    {0x5B, "Transducer Serial Number"},
    {0x5C, "Preferred Color"},
    {0x5D, "Preferred Color is Locked"},
    {0x5E, "Preferred Line Width"},
    {0x5F, "Preferred Line Width is Locked"},
    {0x60, "Latency Mode"},
    {0x61, "Gesture Character Quality"},
    {0x62, "Character Gesture Data Length"},
    {0x63, "Character Gesture Data"},
    {0x64, "Gesture Character Encoding"},
    {0x65, "UTF8 Character Gesture Encoding"},
    {0x66, "UTF16 Little Endian Character Gesture Encoding"},
    {0x67, "UTF16 Big Endian Character Gesture Encoding"},
    {0x68, "UTF32 Little Endian Character Gesture Encoding"},
    {0x69, "UTF32 Big Endian Character Gesture Encoding"},
    {0x6A, "Capacitive Heat Map Protocol Vendor ID"},
    {0x6B, "Capacitive Heat Map Protocol Version"},
    {0x6C, "Capacitive Heat Map Frame Data"},
    {0x6D, "Gesture Character Enable"},
    {0x70, "Preferred Line Style"},
    {0x71, "Preferred Line Style is Locked"},
    {0x72, "Ink"},
    {0x73, "Pencil"},
    {0x74, "Highlighter"},
    {0x75, "Chisel Marker"},
    {0x76, "Brush"},
    {0x77, "No Preference"},
    {0x80, "Digitizer Diagnostic"},
    {0x81, "Digitizer Error"},
    {0x82, "Err Normal Status"},
    {0x83, "Err Transducers Exceeded"},
    {0x84, "Err Full Trans Features Unavailable"},
    {0x85, "Err Charge Low"},
    {0x90, "Transducer Software Info"},
    {0x91, "Transducer Vendor Id"},
    {0x92, "Transducer Product Id"},
    {0x93, "Device Supported Protocols"},
    {0x94, "Transducer Supported Protocols"},
    {0x95, "No Protocol"},
    {0x96, "Wacom AES Protocol"},
    {0x97, "USI Protocol"},
    {0x98, "Microsoft Pen Protocol"},
    {0xA0, "Supported Report Rates"},
    {0xA1, "Report Rate"},
    {0xA2, "Transducer Connected"},
    {0xA3, "Switch Disabled"},
    {0xA4, "Switch Unimplemented"},
    {0xA5, "Transducer Switches"},
    {0, NULL}
};
static const value_string usb_hid_haptic_usage_page_vals[] = {
    {0x0000, "Undefined"},
    {0x0001, "Simple Haptic Controller"},
    {0x0010, "Waveform List"},
    {0x0011, "Duration List"},
    {0x0020, "Auto Trigger"},
    {0x0021, "Manual Trigger"},
    {0x0022, "Auto Trigger Associated Control"},
    {0x0023, "Intensity"},
    {0x0024, "Repeat Count"},
    {0x0025, "Retrigger Period"},
    {0x0026, "Waveform Vendor Page"},
    {0x0027, "Waveform Vendor ID"},
    {0x0028, "Waveform Cutoff Time"},
    {0x1001, "Waveform None"},
    {0x1002, "Waveform Stop"},
    {0x1003, "Waveform Click"},
    {0x1004, "Waveform Buzz Continuous"},
    {0x1005, "Waveform Rumble Continuous"},
    {0x1006, "Waveform Press"},
    {0x1007, "Waveform Release"},
    {0, NULL}
};
static const value_string usb_hid_physical_input_device_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Physical Interface Device"},
    {0x20, "Normal"},
    {0x21, "Set Effect Report"},
    {0x22, "Effect Block Index"},
    {0x23, "Parameter Block Offset"},
    {0x24, "ROM Flag"},
    {0x25, "Effect Type"},
    {0x26, "ET Constant Force"},
    {0x27, "ET Ramp"},
    {0x28, "ET Custom Force Data"},
    {0x30, "ET Square"},
    {0x31, "ET Sine"},
    {0x32, "ET Triangle"},
    {0x33, "ET Sawtooth Up"},
    {0x34, "ET Sawtooth Down"},
    {0x40, "ET Spring"},
    {0x41, "ET Damper"},
    {0x42, "ET Inertia"},
    {0x43, "ET Friction"},
    {0x50, "Duration"},
    {0x51, "Sample Period"},
    {0x52, "Gain"},
    {0x53, "Trigger Button"},
    {0x54, "Trigger Repeat Interval"},
    {0x55, "Axes Enable"},
    {0x56, "Direction Enable"},
    {0x57, "Direction"},
    {0x58, "Type Specific Block Offset"},
    {0x59, "Block Type"},
    {0x5A, "Set Envelope Report"},
    {0x5B, "Attack Level"},
    {0x5C, "Attack Time"},
    {0x5D, "Fade Level"},
    {0x5E, "Fade Time"},
    {0x5F, "Set Condition Report"},
    {0x60, "CP Offset"},
    {0x61, "Positive Coefficient"},
    {0x62, "Negative Coefficient"},
    {0x63, "Positive Saturation"},
    {0x64, "Negative Saturation"},
    {0x65, "Dead Band"},
    {0x66, "Download Force Sample"},
    {0x67, "Isoch Custom Force Enable"},
    {0x68, "Custom Force Data Report"},
    {0x69, "Custom Force Data"},
    {0x6A, "Custom Force Vendor Defined Data"},
    {0x6B, "Set Custom Force Report"},
    {0x6C, "Custom Force Data Offset"},
    {0x6D, "Sample Count"},
    {0x6E, "Set Periodic Report"},
    {0x6F, "Offset"},
    {0x70, "Magnitude"},
    {0x71, "Phase"},
    {0x72, "Period"},
    {0x73, "Set Constant Force Report"},
    {0x74, "Set Ramp Force Report"},
    {0x75, "Ramp Start"},
    {0x76, "Ramp End"},
    {0x77, "Effect Operation Report"},
    {0x78, "Effect Operation"},
    {0x79, "Op Effect Start"},
    {0x7A, "Op Effect Start Solo"},
    {0x7B, "Op Effect Stop"},
    {0x7C, "Loop Count"},
    {0x7D, "Device Gain Report"},
    {0x7E, "Device Gain"},
    {0x7F, "PID Pool Report"},
    {0x80, "RAM Pool Size"},
    {0x81, "ROM Pool Size"},
    {0x82, "ROM Effect Block Count"},
    {0x83, "Simultaneous Effects Max"},
    {0x84, "Pool Alignment"},
    {0x85, "PID Pool Move Report"},
    {0x86, "Move Source"},
    {0x87, "Move Destination"},
    {0x88, "Move Length"},
    {0x89, "PID Block Load Report"},
    {0x8B, "Block Load Status"},
    {0x8C, "Block Load Success"},
    {0x8D, "Block Load Full"},
    {0x8E, "Block Load Error"},
    {0x8F, "Block Handle"},
    {0x90, "PID Block Free Report"},
    {0x91, "Type Specific Block Handle"},
    {0x92, "PID State Report"},
    {0x94, "Effect Playing"},
    {0x95, "PID Device Control Report"},
    {0x96, "PID Device Control"},
    {0x97, "DC Enable Actuators"},
    {0x98, "DC Disable Actuators"},
    {0x99, "DC Stop All Effects"},
    {0x9A, "DC Device Reset"},
    {0x9B, "DC Device Pause"},
    {0x9C, "DC Device Continue"},
    {0x9F, "Device Paused"},
    {0xA0, "Actuators Enabled"},
    {0xA4, "Safety Switch"},
    {0xA5, "Actuator Override Switch"},
    {0xA6, "Actuator Power"},
    {0xA7, "Start Delay"},
    {0xA8, "Parameter Block Size"},
    {0xA9, "Device Managed Pool"},
    {0xAA, "Shared Parameter Blocks"},
    {0xAB, "Create New Effect Report"},
    {0xAC, "RAM Pool Available"},
    {0, NULL}
};
static const value_string usb_hid_eye_and_head_tracker_usage_page_vals[] = {
    {0x0000, "Undefined"},
    {0x0001, "Eye Tracker"},
    {0x0002, "Head Tracker"},
    {0x0010, "Tracking Data"},
    {0x0011, "Capabilities"},
    {0x0012, "Configuration"},
    {0x0013, "Status"},
    {0x0014, "Control"},
    {0x0020, "Sensor Timestamp"},
    {0x0021, "Position X"},
    {0x0022, "Position Y"},
    {0x0023, "Position Z"},
    {0x0024, "Gaze Point"},
    {0x0025, "Left Eye Position"},
    {0x0026, "Right Eye Position"},
    {0x0027, "Head Position"},
    {0x0028, "Head Direction Point"},
    {0x0029, "Rotation about X axis"},
    {0x002A, "Rotation about Y axis"},
    {0x002B, "Rotation about Z axis"},
    {0x0100, "Tracker Quality"},
    {0x0101, "Minimum Tracking Distance"},
    {0x0102, "Optimum Tracking Distance"},
    {0x0103, "Maximum Tracking Distance"},
    {0x0104, "Maximum Screen Plane Width"},
    {0x0105, "Maximum Screen Plane Height"},
    {0x0200, "Display Manufacturer ID"},
    {0x0201, "Display Product ID"},
    {0x0202, "Display Serial Number"},
    {0x0203, "Display Manufacturer Date"},
    {0x0204, "Calibrated Screen Width"},
    {0x0205, "Calibrated Screen Height"},
    {0x0300, "Sampling Frequency"},
    {0x0301, "Configuration Status"},
    {0x0400, "Device Mode Request"},
    {0, NULL}
};
static const value_string usb_hid_alphanumeric_display_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Alphanumeric Display"},
    {0x02, "Auxiliary Display"},
    {0x20, "Display Attributes Report"},
    {0x21, "ASCII Character Set"},
    {0x22, "Data Read Back"},
    {0x23, "Font Read Back"},
    {0x24, "Display Control Report"},
    {0x25, "Clear Display"},
    {0x26, "Display Enable"},
    {0x27, "Screen Saver Delay"},
    {0x28, "Screen Saver Enable"},
    {0x29, "Vertical Scroll"},
    {0x2A, "Horizontal Scroll"},
    {0x2B, "Character Report"},
    {0x2C, "Display Data"},
    {0x2D, "Display Status"},
    {0x2E, "Stat Not Ready"},
    {0x2F, "Stat Ready"},
    {0x30, "Err Not a loadable character"},
    {0x31, "Err Font data cannot be read"},
    {0x32, "Cursor Position Report"},
    {0x33, "Row"},
    {0x34, "Column"},
    {0x35, "Rows"},
    {0x36, "Columns"},
    {0x37, "Cursor Pixel Positioning"},
    {0x38, "Cursor Mode"},
    {0x39, "Cursor Enable"},
    {0x3A, "Cursor Blink"},
    {0x3B, "Font Report"},
    {0x3C, "Font Data"},
    {0x3D, "Character Width"},
    {0x3E, "Character Height"},
    {0x3F, "Character Spacing Horizontal"},
    {0x40, "Character Spacing Vertical"},
    {0x41, "Unicode Character Set"},
    {0x42, "Font 7-Segment"},
    {0x43, "7-Segment Direct Map"},
    {0x44, "Font 14-Segment"},
    {0x45, "14-Segment Direct Map"},
    {0x46, "Display Brightness"},
    {0x47, "Display Contrast"},
    {0x48, "Character Attribute"},
    {0x49, "Attribute Readback"},
    {0x4A, "Attribute Data"},
    {0x4B, "Char Attr Enhance"},
    {0x4C, "Char Attr Underline"},
    {0x4D, "Char Attr Blink"},
    {0x80, "Bitmap Size X"},
    {0x81, "Bitmap Size Y"},
    {0x82, "Max Blit Size"},
    {0x83, "Bit Depth Format"},
    {0x84, "Display Orientation"},
    {0x85, "Palette Report"},
    {0x86, "Palette Data Size"},
    {0x87, "Palette Data Offset"},
    {0x88, "Palette Data"},
    {0x8A, "Blit Report"},
    {0x8B, "Blit Rectangle X1"},
    {0x8C, "Blit Rectangle Y1"},
    {0x8D, "Blit Rectangle X2"},
    {0x8E, "Blit Rectangle Y2"},
    {0x8F, "Blit Data"},
    {0x90, "Soft Button"},
    {0x91, "Soft Button ID"},
    {0x92, "Soft Button Side"},
    {0x93, "Soft Button Offset 1"},
    {0x94, "Soft Button Offset 2"},
    {0x95, "Soft Button Report"},
    {0xC2, "Soft Keys"},
    {0xCC, "Display Data Extensions"},
    {0xCF, "Character Mapping"},
    {0xDD, "Unicode Equivalent"},
    {0xDF, "Character Page Mapping"},
    {0xFF, "Request Report"},
    {0, NULL}
};
static const value_string usb_hid_sensor_usage_page_vals[] = {
    {0x0000, "Undefined"},
    {0x0001, "Sensor"},
    {0x0010, "Biometric"},
    {0x0011, "Biometric: Human Presence"},
    {0x0012, "Biometric: Human Proximity"},
    {0x0013, "Biometric: Human Touch"},
    {0x0014, "Biometric: Blood Pressure"},
    {0x0015, "Biometric: Body Temperature"},
    {0x0016, "Biometric: Heart Rate"},
    {0x0017, "Biometric: Heart Rate Variability"},
    {0x0018, "Biometric: Peripheral Oxygen Saturation"},
    {0x0019, "Biometric: Respiratory Rate"},
    {0x0020, "Electrical"},
    {0x0021, "Electrical: Capacitance"},
    {0x0022, "Electrical: Current"},
    {0x0023, "Electrical: Power"},
    {0x0024, "Electrical: Inductance"},
    {0x0025, "Electrical: Resistance"},
    {0x0026, "Electrical: Voltage"},
    {0x0027, "Electrical: Potentiometer"},
    {0x0028, "Electrical: Frequency"},
    {0x0029, "Electrical: Period"},
    {0x0030, "Environmental"},
    {0x0031, "Environmental: Atmospheric Pressure"},
    {0x0032, "Environmental: Humidity"},
    {0x0033, "Environmental: Temperature"},
    {0x0034, "Environmental: Wind Direction"},
    {0x0035, "Environmental: Wind Speed"},
    {0x0036, "Environmental: Air Quality"},
    {0x0037, "Environmental: Heat Index"},
    {0x0038, "Environmental: Surface Temperature"},
    {0x0039, "Environmental: Volatile Organic Compounds"},
    {0x003A, "Environmental: Object Presence"},
    {0x003B, "Environmental: Object Proximity"},
    {0x0040, "Light"},
    {0x0041, "Light: Ambient Light"},
    {0x0042, "Light: Consumer Infrared"},
    {0x0043, "Light: Infrared Light"},
    {0x0044, "Light: Visible Light"},
    {0x0045, "Light: Ultraviolet Light"},
    {0x0050, "Location"},
    {0x0051, "Location: Broadcast"},
    {0x0052, "Location: Dead Reckoning"},
    {0x0053, "Location: GPS (Global Positioning System)"},
    {0x0054, "Location: Lookup"},
    {0x0055, "Location: Other"},
    {0x0056, "Location: Static"},
    {0x0057, "Location: Triangulation"},
    {0x0060, "Mechanical"},
    {0x0061, "Mechanical: Boolean Switch"},
    {0x0062, "Mechanical: Boolean Switch Array"},
    {0x0063, "Mechanical: Multivalue Switch"},
    {0x0064, "Mechanical: Force"},
    {0x0065, "Mechanical: Pressure"},
    {0x0066, "Mechanical: Strain"},
    {0x0067, "Mechanical: Weight"},
    {0x0068, "Mechanical: Haptic Vibrator"},
    {0x0069, "Mechanical: Hall Effect Switch"},
    {0x0070, "Motion"},
    {0x0071, "Motion: Accelerometer 1D"},
    {0x0072, "Motion: Accelerometer 2D"},
    {0x0073, "Motion: Accelerometer 3D"},
    {0x0074, "Motion: Gyrometer 1D"},
    {0x0075, "Motion: Gyrometer 2D"},
    {0x0076, "Motion: Gyrometer 3D"},
    {0x0077, "Motion: Motion Detector"},
    {0x0078, "Motion: Speedometer"},
    {0x0079, "Motion: Accelerometer"},
    {0x007A, "Motion: Gyrometer"},
    {0x007B, "Motion: Gravity Vector"},
    {0x007C, "Motion: Linear Accelerometer"},
    {0x0080, "Orientation"},
    {0x0081, "Orientation: Compass 1D"},
    {0x0082, "Orientation: Compass 2D"},
    {0x0083, "Orientation: Compass 3D"},
    {0x0084, "Orientation: Inclinometer 1D"},
    {0x0085, "Orientation: Inclinometer 2D"},
    {0x0086, "Orientation: Inclinometer 3D"},
    {0x0087, "Orientation: Distance 1D"},
    {0x0088, "Orientation: Distance 2D"},
    {0x0089, "Orientation: Distance 3D"},
    {0x008A, "Orientation: Device Orientation"},
    {0x008B, "Orientation: Compass"},
    {0x008C, "Orientation: Inclinometer"},
    {0x008D, "Orientation: Distance"},
    {0x008E, "Orientation: Relative Orientation"},
    {0x008F, "Orientation: Simple Orientation"},
    {0x0090, "Scanner"},
    {0x0091, "Scanner: Barcode"},
    {0x0092, "Scanner: RFID"},
    {0x0093, "Scanner: NFC"},
    {0x00A0, "Time"},
    {0x00A1, "Time: Alarm Timer"},
    {0x00A2, "Time: Real Time Clock"},
    {0x00B0, "Personal Activity"},
    {0x00B1, "Personal Activity: Activity Detection"},
    {0x00B2, "Personal Activity: Device Position"},
    {0x00B3, "Personal Activity: Pedometer"},
    {0x00B4, "Personal Activity: Step Detection"},
    {0x00C0, "Orientation Extended"},
    {0x00C1, "Orientation Extended: Geomagnetic Orientation"},
    {0x00C2, "Orientation Extended: Magnetometer"},
    {0x00D0, "Gesture"},
    {0x00D1, "Gesture: Chassis Flip Gesture"},
    {0x00D2, "Gesture: Hinge Fold Gesture"},
    {0x00E0, "Other"},
    {0x00E1, "Other: Custom"},
    {0x00E2, "Other: Generic"},
    {0x00E3, "Other: Generic Enumerator"},
    {0x00E4, "Other: Hinge Angle"},
    {0x0200, "Event"},
    {0x0201, "Event: Sensor State"},
    {0x0202, "Event: Sensor Event"},
    {0x0300, "Property"},
    {0x0301, "Property: Friendly Name"},
    {0x0302, "Property: Persistent Unique ID"},
    {0x0303, "Property: Sensor Status"},
    {0x0304, "Property: Minimum Report Interval"},
    {0x0305, "Property: Sensor Manufacturer"},
    {0x0306, "Property: Sensor Model"},
    {0x0307, "Property: Sensor Serial Number"},
    {0x0308, "Property: Sensor Description"},
    {0x0309, "Property: Sensor Connection Type"},
    {0x030A, "Property: Sensor Device Path"},
    {0x030B, "Property: Hardware Revision"},
    {0x030C, "Property: Firmware Version"},
    {0x030D, "Property: Release Date"},
    {0x030E, "Property: Report Interval"},
    {0x030F, "Property: Change Sensitivity Absolute"},
    {0x0310, "Property: Change Sensitivity Percent of Range"},
    {0x0311, "Property: Change Sensitivity Percent Relative"},
    {0x0312, "Property: Accuracy"},
    {0x0313, "Property: Resolution"},
    {0x0314, "Property: Maximum"},
    {0x0315, "Property: Minimum"},
    {0x0316, "Property: Reporting State"},
    {0x0317, "Property: Sampling Rate"},
    {0x0318, "Property: Response Curve"},
    {0x0319, "Property: Power State"},
    {0x031A, "Property: Maximum FIFO Events"},
    {0x031B, "Property: Report Latency"},
    {0x031C, "Property: Flush FIFO Events"},
    {0x031D, "Property: Maximum Power Consumption"},
    {0x031E, "Property: Is Primary"},
    {0x0400, "Data Field: Location"},
    {0x0401, "Reserved (Data Field: Location)"},
    {0x0402, "Data Field: Altitude Antenna Sea Level"},
    {0x0403, "Data Field: Differential Reference Station ID"},
    {0x0404, "Data Field: Altitude Ellipsoid Error"},
    {0x0405, "Data Field: Altitude Ellipsoid"},
    {0x0406, "Data Field: Altitude Sea Level Error"},
    {0x0407, "Data Field: Altitude Sea Level"},
    {0x0408, "Data Field: Differential GPS Data Age"},
    {0x0409, "Data Field: Error Radius"},
    {0x040A, "Data Field: Fix Quality"},
    {0x040B, "Data Field: Fix Type"},
    {0x040C, "Data Field: Geoidal Separation"},
    {0x040D, "Data Field: GPS Operation Mode"},
    {0x040E, "Data Field: GPS Selection Mode"},
    {0x040F, "Data Field: GPS Status"},
    {0x0410, "Data Field: Position Dilution of Precision"},
    {0x0411, "Data Field: Horizontal Dilution of Precision"},
    {0x0412, "Data Field: Vertical Dilution of Precision"},
    {0x0413, "Data Field: Latitude"},
    {0x0414, "Data Field: Longitude"},
    {0x0415, "Data Field: True Heading"},
    {0x0416, "Data Field: Magnetic Heading"},
    {0x0417, "Data Field: Magnetic Variation"},
    {0x0418, "Data Field: Speed"},
    {0x0419, "Data Field: Satellites in View"},
    {0x041A, "Data Field: Satellites in View Azimuth"},
    {0x041B, "Data Field: Satellites in View Elevation"},
    {0x041C, "Data Field: Satellites in View IDs"},
    {0x041D, "Data Field: Satellites in View PRNs"},
    {0x041E, "Data Field: Satellites in View S/N Ratios"},
    {0x041F, "Data Field: Satellites Used Count"},
    {0x0420, "Data Field: Satellites Used PRNs"},
    {0x0421, "Data Field: NMEA Sentence"},
    {0x0422, "Data Field: Address Line 1"},
    {0x0423, "Data Field: Address Line 2"},
    {0x0424, "Data Field: City"},
    {0x0425, "Data Field: State or Province"},
    {0x0426, "Data Field: Country or Region"},
    {0x0427, "Data Field: Postal Code"},
    {0x042A, "Property: Location"},
    {0x042B, "Property: Location Desired Accuracy"},
    {0x0430, "Data Field: Environmental"},
    {0x0431, "Data Field: Atmospheric Pressure"},
    {0x0432, "Reserved (Data Field: Environmental)"},
    {0x0433, "Data Field: Relative Humidity"},
    {0x0434, "Data Field: Temperature"},
    {0x0435, "Data Field: Wind Direction"},
    {0x0436, "Data Field: Wind Speed"},
    {0x0437, "Data Field: Air Quality Index"},
    {0x0438, "Data Field: Equivalent CO2"},
    {0x0439, "Data Field: Volatile Organic Compound Concentration"},
    {0x043A, "Data Field: Object Presence"},
    {0x043B, "Data Field: Object Proximity Range"},
    {0x043C, "Data Field: Object Proximity Out of Range"},
    {0x0440, "Property: Environmental"},
    {0x0441, "Property: Reference Pressure"},
    {0x0450, "Data Field: Motion"},
    {0x0451, "Data Field: Motion State"},
    {0x0452, "Data Field: Acceleration"},
    {0x0453, "Data Field: Acceleration Axis X"},
    {0x0454, "Data Field: Acceleration Axis Y"},
    {0x0455, "Data Field: Acceleration Axis Z"},
    {0x0456, "Data Field: Angular Velocity"},
    {0x0457, "Data Field: Angular Velocity about X Axis"},
    {0x0458, "Data Field: Angular Velocity about Y Axis"},
    {0x0459, "Data Field: Angular Velocity about Z Axis"},
    {0x045A, "Data Field: Angular Position"},
    {0x045B, "Data Field: Angular Position about X Axis"},
    {0x045C, "Data Field: Angular Position about Y Axis"},
    {0x045D, "Data Field: Angular Position about Z Axis"},
    {0x045E, "Data Field: Motion Speed"},
    {0x045F, "Data Field: Motion Intensity"},
    {0x0470, "Data Field: Orientation"},
    {0x0471, "Data Field: Heading"},
    {0x0472, "Data Field: Heading X Axis"},
    {0x0473, "Data Field: Heading Y Axis"},
    {0x0474, "Data Field: Heading Z Axis"},
    {0x0475, "Data Field: Heading Compensated Magnetic North"},
    {0x0476, "Data Field: Heading Compensated True North"},
    {0x0477, "Data Field: Heading Magnetic North"},
    {0x0478, "Data Field: Heading True North"},
    {0x0479, "Data Field: Distance"},
    {0x047A, "Data Field: Distance X Axis"},
    {0x047B, "Data Field: Distance Y Axis"},
    {0x047C, "Data Field: Distance Z Axis"},
    {0x047D, "Data Field: Distance Out-of-Range"},
    {0x047E, "Data Field: Tilt"},
    {0x047F, "Data Field: Tilt X Axis"},
    {0x0480, "Data Field: Tilt Y Axis"},
    {0x0481, "Data Field: Tilt Z Axis"},
    {0x0482, "Data Field: Rotation Matrix"},
    {0x0483, "Data Field: Quaternion"},
    {0x0484, "Data Field: Magnetic Flux"},
    {0x0485, "Data Field: Magnetic Flux X Axis"},
    {0x0486, "Data Field: Magnetic Flux Y Axis"},
    {0x0487, "Data Field: Magnetic Flux Z Axis"},
    {0x0488, "Data Field: Magnetometer Accuracy"},
    {0x0489, "Data Field: Simple Orientation Direction"},
    {0x0490, "Data Field: Mechanical"},
    {0x0491, "Data Field: Boolean Switch State"},
    {0x0492, "Data Field: Boolean Switch Array States"},
    {0x0493, "Data Field: Multivalue Switch Value"},
    {0x0494, "Data Field: Force"},
    {0x0495, "Data Field: Absolute Pressure"},
    {0x0496, "Data Field: Gauge Pressure"},
    {0x0497, "Data Field: Strain"},
    {0x0498, "Data Field: Weight"},
    {0x04A0, "Property: Mechanical"},
    {0x04A1, "Property: Vibration State"},
    {0x04A2, "Property: Forward Vibration Speed"},
    {0x04A3, "Property: Backward Vibration Speed"},
    {0x04B0, "Data Field: Biometric"},
    {0x04B1, "Data Field: Human Presence"},
    {0x04B2, "Data Field: Human Proximity Range"},
    {0x04B3, "Data Field: Human Proximity Out of Range"},
    {0x04B4, "Data Field: Human Touch State"},
    {0x04B5, "Data Field: Blood Pressure"},
    {0x04B6, "Data Field: Blood Pressure Diastolic"},
    {0x04B7, "Data Field: Blood Pressure Systolic"},
    {0x04B8, "Data Field: Heart Rate"},
    {0x04B9, "Data Field: Resting Heart Rate"},
    {0x04BA, "Data Field: Heartbeat Interval"},
    {0x04BB, "Data Field: Respiratory Rate"},
    {0x04BC, "Data Field: SpO2"},
    {0x04D0, "Data Field: Light"},
    {0x04D1, "Data Field: Illuminance"},
    {0x04D2, "Data Field: Color Temperature"},
    {0x04D3, "Data Field: Chromaticity"},
    {0x04D4, "Data Field: Chromaticity X"},
    {0x04D5, "Data Field: Chromaticity Y"},
    {0x04D6, "Data Field: Consumer IR Sentence Receive"},
    {0x04D7, "Data Field: Infrared Light"},
    {0x04D8, "Data Field: Red Light"},
    {0x04D9, "Data Field: Green Light"},
    {0x04DA, "Data Field: Blue Light"},
    {0x04DB, "Data Field: Ultraviolet A Light"},
    {0x04DC, "Data Field: Ultraviolet B Light"},
    {0x04DD, "Data Field: Ultraviolet Index"},
    {0x04DE, "Data Field: Near Infrared Light"},
    {0x04DF, "Property: Light"},
    {0x04E0, "Property: Consumer IR Sentence Send"},
    {0x04E2, "Property: Auto Brightness Preferred"},
    {0x04E3, "Property: Auto Color Preferred"},
    {0x04F0, "Data Field: Scanner"},
    {0x04F1, "Data Field: RFID Tag 40 Bit"},
    {0x04F2, "Data Field: NFC Sentence Receive"},
    {0x04F8, "Property: Scanner"},
    {0x04F9, "Property: NFC Sentence Send"},
    {0x0500, "Data Field: Electrical"},
    {0x0501, "Data Field: Capacitance"},
    {0x0502, "Data Field: Current"},
    {0x0503, "Data Field: Electrical Power"},
    {0x0504, "Data Field: Inductance"},
    {0x0505, "Data Field: Resistance"},
    {0x0506, "Data Field: Voltage"},
    {0x0507, "Data Field: Frequency"},
    {0x0508, "Data Field: Period"},
    {0x0509, "Data Field: Percent of Range"},
    {0x0520, "Data Field: Time"},
    {0x0521, "Data Field: Year"},
    {0x0522, "Data Field: Month"},
    {0x0523, "Data Field: Day"},
    {0x0524, "Data Field: Day of Week"},
    {0x0525, "Data Field: Hour"},
    {0x0526, "Data Field: Minute"},
    {0x0527, "Data Field: Second"},
    {0x0528, "Data Field: Millisecond"},
    {0x0529, "Data Field: Timestamp"},
    {0x052A, "Data Field: Julian Day of Year"},
    {0x052B, "Data Field: Time Since System Boot"},
    {0x0530, "Property: Time"},
    {0x0531, "Property: Time Zone Offset from UTC"},
    {0x0532, "Property: Time Zone Name"},
    {0x0533, "Property: Daylight Savings Time Observed"},
    {0x0534, "Property: Time Trim Adjustment"},
    {0x0535, "Property: Arm Alarm"},
    {0x0540, "Data Field: Custom"},
    {0x0541, "Data Field: Custom Usage"},
    {0x0542, "Data Field: Custom Boolean Array"},
    {0x0543, "Data Field: Custom Value"},
    {0x0544, "Data Field: Custom Value 1"},
    {0x0545, "Data Field: Custom Value 2"},
    {0x0546, "Data Field: Custom Value 3"},
    {0x0547, "Data Field: Custom Value 4"},
    {0x0548, "Data Field: Custom Value 5"},
    {0x0549, "Data Field: Custom Value 6"},
    {0x054A, "Data Field: Custom Value 7"},
    {0x054B, "Data Field: Custom Value 8"},
    {0x054C, "Data Field: Custom Value 9"},
    {0x054D, "Data Field: Custom Value 10"},
    {0x054E, "Data Field: Custom Value 11"},
    {0x054F, "Data Field: Custom Value 12"},
    {0x0550, "Data Field: Custom Value 13"},
    {0x0551, "Data Field: Custom Value 14"},
    {0x0552, "Data Field: Custom Value 15"},
    {0x0553, "Data Field: Custom Value 16"},
    {0x0554, "Data Field: Custom Value 17"},
    {0x0555, "Data Field: Custom Value 18"},
    {0x0556, "Data Field: Custom Value 19"},
    {0x0557, "Data Field: Custom Value 20"},
    {0x0558, "Data Field: Custom Value 21"},
    {0x0559, "Data Field: Custom Value 22"},
    {0x055A, "Data Field: Custom Value 23"},
    {0x055B, "Data Field: Custom Value 24"},
    {0x055C, "Data Field: Custom Value 25"},
    {0x055D, "Data Field: Custom Value 26"},
    {0x055E, "Data Field: Custom Value 27"},
    {0x055F, "Data Field: Custom Value 28"},
    {0x0560, "Data Field: Generic"},
    {0x0561, "Data Field: Generic GUID or PROPERTYKEY"},
    {0x0562, "Data Field: Generic Category GUID"},
    {0x0563, "Data Field: Generic Type GUID"},
    {0x0564, "Data Field: Generic Event PROPERTYKEY"},
    {0x0565, "Data Field: Generic Property PROPERTYKEY"},
    {0x0566, "Data Field: Generic Data Field PROPERTYKEY"},
    {0x0567, "Data Field: Generic Event"},
    {0x0568, "Data Field: Generic Property"},
    {0x0569, "Data Field: Generic Data Field"},
    {0x056A, "Data Field: Enumerator Table Row Index"},
    {0x056B, "Data Field: Enumerator Table Row Count"},
    {0x056C, "Data Field: Generic GUID or PROPERTYKEY kind"},
    {0x056D, "Data Field: Generic GUID"},
    {0x056E, "Data Field: Generic PROPERTYKEY"},
    {0x056F, "Data Field: Generic Top Level Collection ID"},
    {0x0570, "Data Field: Generic Report ID"},
    {0x0571, "Data Field: Generic Report Item Position Index"},
    {0x0572, "Data Field: Generic Firmware VARTYPE"},
    {0x0573, "Data Field: Generic Unit of Measure"},
    {0x0574, "Data Field: Generic Unit Exponent"},
    {0x0575, "Data Field: Generic Report Size"},
    {0x0576, "Data Field: Generic Report Count"},
    {0x0580, "Property: Generic"},
    {0x0581, "Property: Enumerator Table Row Index"},
    {0x0582, "Property: Enumerator Table Row Count"},
    {0x0590, "Data Field: Personal Activity"},
    {0x0591, "Data Field: Activity Type"},
    {0x0592, "Data Field: Activity State"},
    {0x0593, "Data Field: Device Position"},
    {0x0594, "Data Field: Step Count"},
    {0x0595, "Data Field: Step Count Reset"},
    {0x0596, "Data Field: Step Duration"},
    {0x0597, "Data Field: Step Type"},
    {0x05A0, "Property: Minimum Activity Detection Interval"},
    {0x05A1, "Property: Supported Activity Types"},
    {0x05A2, "Property: Subscribed Activity Types"},
    {0x05A3, "Property: Supported Step Types"},
    {0x05A4, "Property: Subscribed Step Types"},
    {0x05A5, "Property: Floor Height"},
    {0x05B0, "Data Field: Custom Type ID"},
    {0x05C0, "Property: Custom"},
    {0x05C1, "Property: Custom Value 1"},
    {0x05C2, "Property: Custom Value 2"},
    {0x05C3, "Property: Custom Value 3"},
    {0x05C4, "Property: Custom Value 4"},
    {0x05C5, "Property: Custom Value 5"},
    {0x05C6, "Property: Custom Value 6"},
    {0x05C7, "Property: Custom Value 7"},
    {0x05C8, "Property: Custom Value 8"},
    {0x05C9, "Property: Custom Value 9"},
    {0x05CA, "Property: Custom Value 10"},
    {0x05CB, "Property: Custom Value 11"},
    {0x05CC, "Property: Custom Value 12"},
    {0x05CD, "Property: Custom Value 13"},
    {0x05CE, "Property: Custom Value 14"},
    {0x05CF, "Property: Custom Value 15"},
    {0x05D0, "Property: Custom Value 16"},
    {0x05E0, "Data Field: Hinge"},
    {0x05E1, "Data Field: Hinge Angle"},
    {0x05F0, "Data Field: Gesture Sensor"},
    {0x05F1, "Data Field: Gesture State"},
    {0x05F2, "Data Field: Hinge Fold Initial Angle"},
    {0x05F3, "Data Field: Hinge Fold Final Angle"},
    {0x05F4, "Data Field: Hinge Fold Contributing Panel"},
    {0x05F5, "Data Field: Hinge Fold Type"},
    {0x0800, "Sensor State: Undefined"},
    {0x0801, "Sensor State: Ready"},
    {0x0802, "Sensor State: Not Available"},
    {0x0803, "Sensor State: No Data"},
    {0x0804, "Sensor State: Initializing"},
    {0x0805, "Sensor State: Access Denied"},
    {0x0806, "Sensor State: Error"},
    {0x0810, "Sensor Event: Unknown"},
    {0x0811, "Sensor Event: State Changed"},
    {0x0812, "Sensor Event: Property Changed"},
    {0x0813, "Sensor Event: Data Updated"},
    {0x0814, "Sensor Event: Poll Response"},
    {0x0815, "Sensor Event: Change Sensitivity"},
    {0x0816, "Sensor Event: Range Maximum Reached"},
    {0x0817, "Sensor Event: Range Minimum Reached"},
    {0x0818, "Sensor Event: High Threshold Cross Upward"},
    {0x0819, "Sensor Event: High Threshold Cross Downward"},
    {0x081A, "Sensor Event: Low Threshold Cross Upward"},
    {0x081B, "Sensor Event: Low Threshold Cross Downward"},
    {0x081C, "Sensor Event: Zero Threshold Cross Upward"},
    {0x081D, "Sensor Event: Zero Threshold Cross Downward"},
    {0x081E, "Sensor Event: Period Exceeded"},
    {0x081F, "Sensor Event: Frequency Exceeded"},
    {0x0820, "Sensor Event: Complex Trigger"},
    {0x0830, "Connection Type: PC Integrated"},
    {0x0831, "Connection Type: PC Attached"},
    {0x0832, "Connection Type: PC External"},
    {0x0840, "Reporting State: Report No Events"},
    {0x0841, "Reporting State: Report All Events"},
    {0x0842, "Reporting State: Report Threshold Events"},
    {0x0843, "Reporting State: Wake On No Events"},
    {0x0844, "Reporting State: Wake On All Events"},
    {0x0845, "Reporting State: Wake On Threshold Events"},
    {0x0850, "Power State: Undefined"},
    {0x0851, "Power State: D0 Full Power"},
    {0x0852, "Power State: D1 Low Power"},
    {0x0853, "Power State: D2 Standby Power with Wakeup"},
    {0x0854, "Power State: D3 Sleep with Wakeup"},
    {0x0855, "Power State: D4 Power Off"},
    {0x0860, "Accuracy: Default"},
    {0x0861, "Accuracy: High"},
    {0x0862, "Accuracy: Medium"},
    {0x0863, "Accuracy: Low"},
    {0x0870, "Fix Quality: No Fix"},
    {0x0871, "Fix Quality: GPS"},
    {0x0872, "Fix Quality: DGPS"},
    {0x0880, "Fix Type: No Fix"},
    {0x0881, "Fix Type: GPS SPS Mode, Fix Valid"},
    {0x0882, "Fix Type: DGPS SPS Mode, Fix Valid"},
    {0x0883, "Fix Type: GPS PPS Mode, Fix Valid"},
    {0x0884, "Fix Type: Real Time Kinematic"},
    {0x0885, "Fix Type: Float RTK"},
    {0x0886, "Fix Type: Estimated (dead reckoned)"},
    {0x0887, "Fix Type: Manual Input Mode"},
    {0x0888, "Fix Type: Simulator Mode"},
    {0x0890, "GPS Operation Mode: Manual"},
    {0x0891, "GPS Operation Mode: Automatic"},
    {0x08A0, "GPS Selection Mode: Autonomous"},
    {0x08A1, "GPS Selection Mode: DGPS"},
    {0x08A2, "GPS Selection Mode: Estimated (dead reckoned)"},
    {0x08A3, "GPS Selection Mode: Manual Input"},
    {0x08A4, "GPS Selection Mode: Simulator"},
    {0x08A5, "GPS Selection Mode: Data Not Valid"},
    {0x08B0, "GPS Status Data: Valid"},
    {0x08B1, "GPS Status Data: Not Valid"},
    {0x08C0, "Day of Week: Sunday"},
    {0x08C1, "Day of Week: Monday"},
    {0x08C2, "Day of Week: Tuesday"},
    {0x08C3, "Day of Week: Wednesday"},
    {0x08C4, "Day of Week: Thursday"},
    {0x08C5, "Day of Week: Friday"},
    {0x08C6, "Day of Week: Saturday"},
    {0x08D0, "Kind: Category"},
    {0x08D1, "Kind: Type"},
    {0x08D2, "Kind: Event"},
    {0x08D3, "Kind: Property"},
    {0x08D4, "Kind: Data Field"},
    {0x08E0, "Magnetometer Accuracy: Low"},
    {0x08E1, "Magnetometer Accuracy: Medium"},
    {0x08E2, "Magnetometer Accuracy: High"},
    {0x08F0, "Simple Orientation Direction: Not Rotated"},
    {0x08F1, "Simple Orientation Direction: Rotated 90 Degrees CCW"},
    {0x08F2, "Simple Orientation Direction: Rotated 180 Degrees CCW"},
    {0x08F3, "Simple Orientation Direction: Rotated 270 Degrees CCW"},
    {0x08F4, "Simple Orientation Direction: Face Up"},
    {0x08F5, "Simple Orientation Direction: Face Down"},
    {0x0900, "VT_NULL: Empty"},
    {0x0901, "VT_BOOL: Boolean"},
    {0x0902, "VT_UI1: Byte"},
    {0x0903, "VT_I1: Character"},
    {0x0904, "VT_UI2: Unsigned Short"},
    {0x0905, "VT_I2: Short"},
    {0x0906, "VT_UI4: Unsigned Long"},
    {0x0907, "VT_I4: Long"},
    {0x0908, "VT_UI8: Unsigned Long Long"},
    {0x0909, "VT_I8: Long Long"},
    {0x090A, "VT_R4: Float"},
    {0x090B, "VT_R8: Double"},
    {0x090C, "VT_WSTR: Wide String"},
    {0x090D, "VT_STR: Narrow String"},
    {0x090E, "VT_CLSID: Guid"},
    {0x090F, "VT_VECTOR|VT_UI1: Opaque Structure"},
    {0x0910, "VT_F16E0: HID 16-bit Float with Unit Exponent 0"},
    {0x0911, "VT_F16E1: HID 16-bit Float with Unit Exponent 1"},
    {0x0912, "VT_F16E2: HID 16-bit Float with Unit Exponent 2"},
    {0x0913, "VT_F16E3: HID 16-bit Float with Unit Exponent 3"},
    {0x0914, "VT_F16E4: HID 16-bit Float with Unit Exponent 4"},
    {0x0915, "VT_F16E5: HID 16-bit Float with Unit Exponent 5"},
    {0x0916, "VT_F16E6: HID 16-bit Float with Unit Exponent 6"},
    {0x0917, "VT_F16E7: HID 16-bit Float with Unit Exponent 7"},
    {0x0918, "VT_F16E8: HID 16-bit Float with Unit Exponent 8"},
    {0x0919, "VT_F16E9: HID 16-bit Float with Unit Exponent 9"},
    {0x091A, "VT_F16EA: HID 16-bit Float with Unit Exponent A"},
    {0x091B, "VT_F16EB: HID 16-bit Float with Unit Exponent B"},
    {0x091C, "VT_F16EC: HID 16-bit Float with Unit Exponent C"},
    {0x091D, "VT_F16ED: HID 16-bit Float with Unit Exponent D"},
    {0x091E, "VT_F16EE: HID 16-bit Float with Unit Exponent E"},
    {0x091F, "VT_F16EF: HID 16-bit Float with Unit Exponent F"},
    {0x0920, "VT_F32E0: HID 32-bit Float with Unit Exponent 0"},
    {0x0921, "VT_F32E1: HID 32-bit Float with Unit Exponent 1"},
    {0x0922, "VT_F32E2: HID 32-bit Float with Unit Exponent 2"},
    {0x0923, "VT_F32E3: HID 32-bit Float with Unit Exponent 3"},
    {0x0924, "VT_F32E4: HID 32-bit Float with Unit Exponent 4"},
    {0x0925, "VT_F32E5: HID 32-bit Float with Unit Exponent 5"},
    {0x0926, "VT_F32E6: HID 32-bit Float with Unit Exponent 6"},
    {0x0927, "VT_F32E7: HID 32-bit Float with Unit Exponent 7"},
    {0x0928, "VT_F32E8: HID 32-bit Float with Unit Exponent 8"},
    {0x0929, "VT_F32E9: HID 32-bit Float with Unit Exponent 9"},
    {0x092A, "VT_F32EA: HID 32-bit Float with Unit Exponent A"},
    {0x092B, "VT_F32EB: HID 32-bit Float with Unit Exponent B"},
    {0x092C, "VT_F32EC: HID 32-bit Float with Unit Exponent C"},
    {0x092D, "VT_F32ED: HID 32-bit Float with Unit Exponent D"},
    {0x092E, "VT_F32EE: HID 32-bit Float with Unit Exponent E"},
    {0x092F, "VT_F32EF: HID 32-bit Float with Unit Exponent F"},
    {0x0930, "Activity Type: Unknown"},
    {0x0931, "Activity Type: Stationary"},
    {0x0932, "Activity Type: Fidgeting"},
    {0x0933, "Activity Type: Walking"},
    {0x0934, "Activity Type: Running"},
    {0x0935, "Activity Type: In Vehicle"},
    {0x0936, "Activity Type: Biking"},
    {0x0937, "Activity Type: Idle"},
    {0x0940, "Unit: Not Specified"},
    {0x0941, "Unit: Lux"},
    {0x0942, "Unit: Degrees Kelvin"},
    {0x0943, "Unit: Degrees Celsius"},
    {0x0944, "Unit: Pascal"},
    {0x0945, "Unit: Newton"},
    {0x0946, "Unit: Meters/Second"},
    {0x0947, "Unit: Kilogram"},
    {0x0948, "Unit: Meter"},
    {0x0949, "Unit: Meters/Second/Second"},
    {0x094A, "Unit: Farad"},
    {0x094B, "Unit: Ampere"},
    {0x094C, "Unit: Watt"},
    {0x094D, "Unit: Henry"},
    {0x094E, "Unit: Ohm"},
    {0x094F, "Unit: Volt"},
    {0x0950, "Unit: Hertz"},
    {0x0951, "Unit: Bar"},
    {0x0952, "Unit: Degrees Anti-clockwise"},
    {0x0953, "Unit: Degrees Clockwise"},
    {0x0954, "Unit: Degrees"},
    {0x0955, "Unit: Degrees/Second"},
    {0x0956, "Unit: Degrees/Second/Second"},
    {0x0957, "Unit: Knot"},
    {0x0958, "Unit: Percent"},
    {0x0959, "Unit: Second"},
    {0x095A, "Unit: Millisecond"},
    {0x095B, "Unit: G"},
    {0x095C, "Unit: Bytes"},
    {0x095D, "Unit: Milligauss"},
    {0x095E, "Unit: Bits"},
    {0x0960, "Activity State: No State Change"},
    {0x0961, "Activity State: Start Activity"},
    {0x0962, "Activity State: End Activity"},
    {0x0970, "Exponent 0: 1"},
    {0x0971, "Exponent 1: 10"},
    {0x0972, "Exponent 2: 100"},
    {0x0973, "Exponent 3: 1 000"},
    {0x0974, "Exponent 4: 10 000"},
    {0x0975, "Exponent 5: 100 000"},
    {0x0976, "Exponent 6: 1 000 000"},
    {0x0977, "Exponent 7: 10 000 000"},
    {0x0978, "Exponent 8: 0.00 000 001"},
    {0x0979, "Exponent 9: 0.0 000 001"},
    {0x097A, "Exponent A: 0.000 001"},
    {0x097B, "Exponent B: 0.00 001"},
    {0x097C, "Exponent C: 0.0 001"},
    {0x097D, "Exponent D: 0.001"},
    {0x097E, "Exponent E: 0.01"},
    {0x097F, "Exponent F: 0.1"},
    {0x0980, "Device Position: Unknown"},
    {0x0981, "Device Position: Unchanged"},
    {0x0982, "Device Position: On Desk"},
    {0x0983, "Device Position: In Hand"},
    {0x0984, "Device Position: Moving in Bag"},
    {0x0985, "Device Position: Stationary in Bag"},
    {0x0990, "Step Type: Unknown"},
    {0x0991, "Step Type: Running"},
    {0x0992, "Step Type: Walking"},
    {0x09A0, "Gesture State: Unknown"},
    {0x09A1, "Gesture State: Started"},
    {0x09A2, "Gesture State: Completed"},
    {0x09A3, "Gesture State: Cancelled"},
    {0x09B0, "Hinge Fold Contributing Panel: Unknown"},
    {0x09B1, "Hinge Fold Contributing Panel: Panel 1"},
    {0x09B2, "Hinge Fold Contributing Panel: Panel 2"},
    {0x09B3, "Hinge Fold Contributing Panel: Both"},
    {0x09B4, "Hinge Fold Type: Unknown"},
    {0x09B5, "Hinge Fold Type: Increasing"},
    {0x09B6, "Hinge Fold Type: Decreasing"},
    {0x1000, "Modifier: Change Sensitivity Absolute"},
    {0x2000, "Modifier: Maximum"},
    {0x3000, "Modifier: Minimum"},
    {0x4000, "Modifier: Accuracy"},
    {0x5000, "Modifier: Resolution"},
    {0x6000, "Modifier: Threshold High"},
    {0x7000, "Modifier: Threshold Low"},
    {0x8000, "Modifier: Calibration Offset"},
    {0x9000, "Modifier: Calibration Multiplier"},
    {0xA000, "Modifier: Report Interval"},
    {0xB000, "Modifier: Frequency Max"},
    {0xC000, "Modifier: Period Max"},
    {0xD000, "Modifier: Change Sensitivity Percent of Range"},
    {0xE000, "Modifier: Change Sensitivity Percent Relative"},
    {0xF000, "Modifier: Vendor Reserved"},
    {0, NULL}
};
static const range_string usb_hid_sensor_usage_page_ranges[] = {
    {0x001A, 0x001F, "Reserved (Biometric)"},
    {0x002A, 0x002F, "Reserved (Electrical)"},
    {0x003C, 0x003F, "Reserved (Environmental)"},
    {0x0046, 0x004F, "Reserved (Light)"},
    {0x0058, 0x005F, "Reserved (Location)"},
    {0x006A, 0x006F, "Reserved (Mechanical)"},
    {0x007D, 0x007F, "Reserved (Motion)"},
    {0x0094, 0x009F, "Reserved (Scanner)"},
    {0x00A3, 0x00AF, "Reserved (Time)"},
    {0x00B5, 0x00BF, "Reserved (Personal Activity)"},
    {0x00C3, 0x00CF, "Reserved (Orientation Extended)"},
    {0x00D3, 0x00DF, "Reserved (Gesture)"},
    {0x00E5, 0x00EF, "Reserved (Other)"},
    {0x00F0, 0x00FF, "Reserved for Vendors/OEMs"},
    {0x031F, 0x03FF, "Reserved (Property)"},
    {0x0428, 0x0429, "Reserved (Data Field: Location)"},
    {0x042C, 0x042F, "Reserved (Property: Location)"},
    {0x043D, 0x043F, "Reserved (Data Field: Environmental)"},
    {0x0442, 0x044F, "Reserved (Property: Environmental)"},
    {0x0460, 0x046F, "Reserved (Data Field: Motion)"},
    {0x048A, 0x048F, "Reserved (Data Field: Orientation)"},
    {0x0499, 0x049F, "Reserved (Data Field: Mechanical)"},
    {0x04A4, 0x04AF, "Reserved (Property: Mechanical)"},
    {0x04BD, 0x04CF, "Reserved (Data Field: Biometric)"},
    {0x04E4, 0x04EF, "Reserved (Property: Light)"},
    {0x04F3, 0x04F7, "Reserved (Data Field: Scanner)"},
    {0x04FA, 0x04FF, "Reserved (Property: Scanner)"},
    {0x050A, 0x051F, "Reserved (Data Field: Electrical)"},
    {0x052C, 0x052F, "Reserved (Data Field: Time)"},
    {0x0536, 0x053F, "Reserved (Property: Time)"},
    {0x0577, 0x057F, "Reserved (Data Field: Generic)"},
    {0x0583, 0x058F, "Reserved (Property: Generic)"},
    {0x0598, 0x059F, "Reserved (Data Field: Personal Activity)"},
    {0x05A6, 0x05AF, "Reserved (Property: Personal Activity)"},
    {0x05B1, 0x05BF, "Reserved (Data Field: Custom)"},
    {0x05C0, 0x07FF, "Reserved for future use as Sensor Types, Data Fields and Properties"},
    {0x0800, 0x09FF, "Reserved for use as Selection Values"},
    {0x1100, 0x17FF, "Reserved for use as Change Sensitivity Absolute modifier range"},
    {0x2100, 0x27FF, "Reserved for use as Maximum modifier range"},
    {0x3100, 0x37FF, "Reserved for use as Minimum modifier range"},
    {0x4100, 0x47FF, "Reserved for use as Accuracy modifier range"},
    {0x5100, 0x57FF, "Reserved for use as Resolution modifier range"},
    {0x6100, 0x67FF, "Reserved for use as Threshold High modifier range"},
    {0x7100, 0x77FF, "Reserved for use as Threshold Low modifier range"},
    {0x8100, 0x87FF, "Reserved for use as Calibration Offset modifier range"},
    {0x9100, 0x97FF, "Reserved for use as Calibration Multiplier modifier range"},
    {0xA100, 0xA7FF, "Reserved for use as Report Interval modifier range"},
    {0xB100, 0xB7FF, "Reserved for use as Frequency Max modifier range"},
    {0xC100, 0xC7FF, "Reserved for use as Period Max modifier range"},
    {0xD100, 0xD7FF, "Reserved for use as Change Sensitivity Percent modifier range"},
    {0xE100, 0xE7FF, "Reserved for use as Change Sensitivity Percent modifier range"},
    {0xF100, 0xF7FF, "Reserved for use as Vendor Reserved modifier range"},
    /* More generic (and overlapping) ranges in case a better match isn't found above */
    {0x1000, 0xEFFF, "Reserved for use as \"Data Fields with Modifiers\""},
    {0xF000, 0xFFFF, "Reserved for Vendors/OEMs"},
    {0, 0, NULL}
};
static const value_string usb_hid_medical_instrument_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Medical Ultrasound"},
    {0x20, "VCR/Acquisition"},
    {0x21, "Freeze/Thaw"},
    {0x22, "Clip Store"},
    {0x23, "Update"},
    {0x24, "Next"},
    {0x25, "Save"},
    {0x26, "Print"},
    {0x27, "Microphone Enable"},
    {0x40, "Cine"},
    {0x41, "Transmit Power"},
    {0x42, "Volume"},
    {0x43, "Focus"},
    {0x44, "Depth"},
    {0x60, "Soft Step - Primary"},
    {0x61, "Soft Step - Secondary"},
    {0x70, "Depth Gain Compensation"},
    {0x80, "Zoom Select"},
    {0x81, "Zoom Adjust"},
    {0x82, "Spectral Doppler Mode Select"},
    {0x83, "Spectral Doppler Adjust"},
    {0x84, "Color Doppler Mode Select"},
    {0x85, "Color Doppler Adjust"},
    {0x86, "Motion Mode Select"},
    {0x87, "Motion Mode Adjust"},
    {0x88, "2-D Mode Select"},
    {0x89, "2-D Mode Adjust"},
    {0xA0, "Soft Control Select"},
    {0xA1, "Soft Control Adjust"},
    {0, NULL}
};
static const value_string usb_hid_braille_display_usage_page_vals[] = {
    {0x000, "Undefined"},
    {0x001, "Braille Display"},
    {0x002, "Braille Row"},
    {0x003, "8 Dot Braille Cell"},
    {0x004, "6 Dot Braille Cell"},
    {0x005, "Number of Braille Cells"},
    {0x006, "Screen Reader Control"},
    {0x007, "Screen Reader Identifier"},
    {0x0FA, "Router Set 1"},
    {0x0FB, "Router Set 2"},
    {0x0FC, "Router Set 3"},
    {0x100, "Router Key"},
    {0x101, "Row Router Key"},
    {0x200, "Braille Buttons"},
    {0x201, "Braille Keyboard Dot 1"},
    {0x202, "Braille Keyboard Dot 2"},
    {0x203, "Braille Keyboard Dot 3"},
    {0x204, "Braille Keyboard Dot 4"},
    {0x205, "Braille Keyboard Dot 5"},
    {0x206, "Braille Keyboard Dot 6"},
    {0x207, "Braille Keyboard Dot 7"},
    {0x208, "Braille Keyboard Dot 8"},
    {0x209, "Braille Keyboard Space"},
    {0x20A, "Braille Keyboard Left Space"},
    {0x20B, "Braille Keyboard Right Space"},
    {0x20C, "Braille Face Controls"},
    {0x20D, "Braille Left Controls"},
    {0x20E, "Braille Right Controls"},
    {0x20F, "Braille Top Controls"},
    {0x210, "Braille Joystick Center"},
    {0x211, "Braille Joystick Up"},
    {0x212, "Braille Joystick Down"},
    {0x213, "Braille Joystick Left"},
    {0x214, "Braille Joystick Right"},
    {0x215, "Braille D-Pad Center"},
    {0x216, "Braille D-Pad Up"},
    {0x217, "Braille D-Pad Down"},
    {0x218, "Braille D-Pad Left"},
    {0x219, "Braille D-Pad Right"},
    {0x21A, "Braille Pan Left"},
    {0x21B, "Braille Pan Right"},
    {0x21C, "Braille Rocker Up"},
    {0x21D, "Braille Rocker Down"},
    {0x21E, "Braille Rocker Press"},
    {0, NULL}
};
static const value_string usb_hid_lighting_and_illumination_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "LampArray"},
    {0x02, "LampArrayAttributesReport"},
    {0x03, "LampCount"},
    {0x04, "BoundingBoxWidthInMicrometers"},
    {0x05, "BoundingBoxHeightInMicrometers"},
    {0x06, "BoundingBoxDepthInMicrometers"},
    {0x07, "LampArrayKind"},
    {0x08, "MinUpdateIntervalInMicroseconds"},
    {0x20, "LampAttributesRequestReport"},
    {0x21, "LampId"},
    {0x22, "LampAttributesResponseReport"},
    {0x23, "PositionXInMicrometers"},
    {0x24, "PositionYInMicrometers"},
    {0x25, "PositionZInMicrometers"},
    {0x26, "LampPurposes"},
    {0x27, "UpdateLatencyInMicroseconds"},
    {0x28, "RedLevelCount"},
    {0x29, "GreenLevelCount"},
    {0x2A, "BlueLevelCount"},
    {0x2B, "IntensityLevelCount"},
    {0x2C, "IsProgrammable"},
    {0x2D, "InputBinding"},
    {0x50, "LampMultiUpdateReport"},
    {0x51, "RedUpdateChannel"},
    {0x52, "GreenUpdateChannel"},
    {0x53, "BlueUpdateChannel"},
    {0x54, "IntensityUpdateChannel"},
    {0x55, "LampUpdateFlags"},
    {0x60, "LampRangeUpdateReport"},
    {0x61, "LampIdStart"},
    {0x62, "LampIdEnd"},
    {0x70, "LampArrayControlReport"},
    {0x71, "AutonomousMode"},
    {0, NULL}
};
static const value_string usb_hid_monitor_usage_page_vals[] = {
    {0x00, "Reserved"},
    {0x01, "Monitor Control"},
    {0x02, "EDID Information"},
    {0x03, "VDIF Information"},
    {0x04, "VESA Version"},
    {0, NULL}
};
static const value_string usb_hid_vesa_virtual_control_usage_page_vals[] = {
    /* Contiguous Controls */
    {0x10, "Brightness"},
    {0x12, "Contrast"},
    {0x16, "Red Video Gain"},
    {0x18, "Green Video Gain"},
    {0x1A, "Blue Video Gain"},
    {0x1C, "Focus"},
    {0x20, "Horizontal Position"},
    {0x22, "Horizontal Size"},
    {0x24, "Horizontal Pincushion"},
    {0x26, "Horizontal Pincushion Balance"},
    {0x28, "Horizontal Misconvergence"},
    {0x2A, "Horizontal Linearity"},
    {0x2C, "Horizontal Linearity Balance"},
    {0x30, "Vertical Position"},
    {0x32, "Vertical Size"},
    {0x34, "Vertical Pincushion"},
    {0x36, "Vertical Pincushion Balance"},
    {0x38, "Vertical Misconvergence"},
    {0x3A, "Vertical Linearity"},
    {0x3C, "Vertical Linearity Balance"},
    {0x40, "Parallelogram Distortion (Key Balance)"},
    {0x42, "Trapezoidal Distortion (Key)"},
    {0x44, "Tilt (Rotation)"},
    {0x46, "Top Corner Distortion Control"},
    {0x48, "Top Corner Distortion Balance"},
    {0x4A, "Bottom Corner Distortion Control"},
    {0x4C, "Bottom Corner Distortion Balance"},
    {0x56, "Horizontal Moire"},
    {0x58, "Vertical Moire"},
    {0x6C, "Red Video Black Level"},
    {0x6E, "Green Video Black Level"},
    {0x70, "Blue Video Black Level"},
    /* Non-contiguous Controls (Read/Write) */
    {0x5E, "Input Level Select"},
    {0x60, "Input Source Select"},
    {0xCA, "On Screen Display"},
    {0xD4, "StereoMode"},
    /* Non-contiguous Controls (Read-only) */
    {0xA2, "Auto Size Center"},
    {0xA4, "Polarity Horizontal Synchronization"},
    {0xA6, "Polarity Vertical Synchronization"},
    {0xA8, "Synchronization Type"},
    {0xAA, "Screen Orientation"},
    {0xAC, "Horizontal Frequency"},
    {0xAE, "Vertical Frequency"},
    /* Non-contiguous Controls (Write-only) */
    {0x01, "Degauss"},
    {0xB0, "Settings"},
    {0, NULL}
};
static const value_string usb_hid_power_device_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "iName"},
    {0x02, "PresentStatus"},
    {0x03, "ChangedStatus"},
    {0x04, "UPS"},
    {0x05, "PowerSupply"},
    {0x10, "BatterySystem"},
    {0x11, "BatterySystemID"},
    {0x12, "Battery"},
    {0x13, "BatteryID"},
    {0x14, "Charger"},
    {0x15, "ChargerID"},
    {0x16, "PowerConverter"},
    {0x17, "PowerConverterID"},
    {0x18, "OutletSystem"},
    {0x19, "OutletSystemID"},
    {0x1A, "Input"},
    {0x1B, "InputID"},
    {0x1C, "Output"},
    {0x1D, "OutputID"},
    {0x1E, "Flow"},
    {0x1F, "FlowID"},
    {0x20, "Outlet"},
    {0x21, "OutletID"},
    {0x22, "Gang"},
    {0x23, "GangID"},
    {0x24, "PowerSummary"},
    {0x25, "PowerSummaryID"},
    {0x30, "Voltage"},
    {0x31, "Current"},
    {0x32, "Frequency"},
    {0x33, "ApparentPower"},
    {0x34, "ActivePower"},
    {0x35, "PercentLoad"},
    {0x36, "Temperature"},
    {0x37, "Humidity"},
    {0x38, "BadCount"},
    {0x40, "ConfigVoltage"},
    {0x41, "ConfigCurrent"},
    {0x42, "ConfigFrequency"},
    {0x43, "ConfigApparentPower"},
    {0x44, "ConfigActivePower"},
    {0x45, "ConfigPercentLoad"},
    {0x46, "ConfigTemperature"},
    {0x47, "ConfigHumidity"},
    {0x50, "SwitchOnControl"},
    {0x51, "SwitchOffControl"},
    {0x52, "ToggleControl"},
    {0x53, "LowVoltageTransfer"},
    {0x54, "HighVoltageTransfer"},
    {0x55, "DelayBeforeReboot"},
    {0x56, "DelayBeforeStartup"},
    {0x57, "DelayBeforeShutdown"},
    {0x58, "Test"},
    {0x59, "ModuleReset"},
    {0x5A, "AudibleAlarmControl"},
    {0x60, "Present"},
    {0x61, "Good"},
    {0x62, "InternalFailure"},
    {0x63, "VoltageOutOfRange"},
    {0x64, "FrequencyOutOfRange"},
    {0x65, "Overload"},
    {0x66, "OverCharged"},
    {0x67, "OverTemperature"},
    {0x68, "ShutdownRequested"},
    {0x69, "ShutdownImminent"},
    {0x6B, "SwitchOn/Off"},
    {0x6C, "Switchable"},
    {0x6D, "Used"},
    {0x6E, "Boost"},
    {0x6F, "Buck"},
    {0x70, "Initialized"},
    {0x71, "Tested"},
    {0x72, "AwaitingPower"},
    {0x73, "CommunicationLost"},
    {0xFD, "iManufacturer"},
    {0xFE, "iProduct"},
    {0xFF, "iserialNumber"},
    {0, NULL}
};
static const value_string usb_hid_battery_system_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "SMBBatteryMode"},
    {0x02, "SMBBatteryStatus"},
    {0x03, "SMBAlarmWarning"},
    {0x04, "SMBChargerMode"},
    {0x05, "SMBChargerStatus"},
    {0x06, "SMBChargerSpecInfo"},
    {0x07, "SMBSelectorState"},
    {0x08, "SMBSelectorPresets"},
    {0x09, "SMBSelectorInfo"},
    {0x10, "OptionalMfgFunction1"},
    {0x11, "OptionalMfgFunction2"},
    {0x12, "OptionalMfgFunction3"},
    {0x13, "OptionalMfgFunction4"},
    {0x14, "OptionalMfgFunction5"},
    {0x15, "ConnectionToSMBus"},
    {0x16, "OutputConnection"},
    {0x17, "ChargerConnection"},
    {0x18, "BatteryInsertion"},
    {0x19, "Usenext"},
    {0x1A, "OKToUse"},
    {0x1B, "BatterySupported"},
    {0x1C, "SelectorRevision"},
    {0x1D, "ChargingIndicator"},
    {0x28, "ManufacturerAccess"},
    {0x29, "RemainingCapacityLimit"},
    {0x2A, "RemainingTimeLimit"},
    {0x2B, "AtRate"},
    {0x2C, "CapacityMode"},
    {0x2D, "BroadcastToCharger"},
    {0x2E, "PrimaryBattery"},
    {0x2F, "ChargeController"},
    {0x40, "TerminateCharge"},
    {0x41, "TerminateDischarge"},
    {0x42, "BelowRemainingCapacityLimit"},
    {0x43, "RemainingTimeLimitExpired"},
    {0x44, "Charging"},
    {0x45, "Discharging"},
    {0x46, "FullyCharged"},
    {0x47, "FullyDischarged"},
    {0x48, "ConditioningFlag"},
    {0x49, "AtRateOK"},
    {0x4A, "SMBErrorCode"},
    {0x4B, "NeedReplacement"},
    {0x60, "AtRateTimeToFull"},
    {0x61, "AtRateTimeToEmpty"},
    {0x62, "AverageCurrent"},
    {0x63, "Maxerror"},
    {0x64, "RelativeStateOfCharge"},
    {0x65, "AbsoluteStateOfCharge"},
    {0x66, "RemainingCapacity"},
    {0x67, "FullChargeCapacity"},
    {0x68, "RunTimeToEmpty"},
    {0x69, "AverageTimeToEmpty"},
    {0x6A, "AverageTimeToFull"},
    {0x6B, "CycleCount"},
    {0x80, "BattPackModelLevel"},
    {0x81, "InternalChargeController"},
    {0x82, "PrimaryBatterySupport"},
    {0x83, "DesignCapacity"},
    {0x84, "SpecificationInfo"},
    {0x85, "ManufacturerDate"},
    {0x86, "SerialNumber"},
    {0x87, "iManufacturerName"},
    {0x88, "iDevicename"},
    {0x89, "iDeviceChemistery"},
    {0x8A, "ManufacturerData"},
    {0x8B, "Rechargeable"},
    {0x8C, "WarningCapacityLimit"},
    {0x8D, "CapacityGranularity1"},
    {0x8E, "CapacityGranularity2"},
    {0x8F, "iOEMInformation"},
    {0xC0, "InhibitCharge"},
    {0xC1, "EnablePolling"},
    {0xC2, "ResetToZero"},
    {0xD0, "ACPresent"},
    {0xD1, "BatteryPresent"},
    {0xD2, "PowerFail"},
    {0xD3, "AlarmInhibited"},
    {0xD4, "ThermistorUnderRange"},
    {0xD5, "ThermistorHot"},
    {0xD6, "ThermistorCold"},
    {0xD7, "ThermistorOverRange"},
    {0xD8, "VoltageOutOfRange"},
    {0xD9, "CurrentOutOfRange"},
    {0xDA, "CurrentNotRegulated"},
    {0xDB, "VoltageNotRegulated"},
    {0xDC, "MasterMode"},
    {0xF0, "ChargerSelectorSupport"},
    {0xF1, "ChargerSpec"},
    {0xF2, "Level2"},
    {0xF3, "Level3"},
    {0, NULL}
};
static const value_string usb_hid_barcode_scanner_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Bar Code Badge Reader"},
    {0x02, "Bar Code Scanner"},
    {0x03, "Dumb Bar Code Scanner"},
    {0x04, "Cordless Scanner Base"},
    {0x05, "Bar Code Scanner Cradle"},
    {0x10, "Attribute Report"},
    {0x11, "Settings Report"},
    {0x12, "Scanned Data Report"},
    {0x13, "Raw Scanned Data Report"},
    {0x14, "Trigger Report"},
    {0x15, "Status Report"},
    {0x16, "UPC/EAN Control Report"},
    {0x17, "EAN 2/3 Label Control Report"},
    {0x18, "Code 39 Control Report"},
    {0x19, "Interleaved 2 of 5 Control Report"},
    {0x1A, "Standard 2 of 5 Control Report"},
    {0x1B, "MSI Plessey Control Report"},
    {0x1C, "Codabar Control Report"},
    {0x1D, "Code 128 Control Report"},
    {0x1E, "Misc 1D Control Report"},
    {0x1F, "2D Control Report"},
    {0x30, "Aiming/Pointer Mode"},
    {0x31, "Bar Code Present Sensor"},
    {0x32, "Class 1A Laser"},
    {0x33, "Class 2 Laser"},
    {0x34, "Heater Present"},
    {0x35, "Contact Scanner"},
    {0x36, "Electronic Article Surveillance Notification"},
    {0x37, "Constant Electronic Article Surveillance"},
    {0x38, "Error Indication"},
    {0x39, "Fixed Beeper"},
    {0x3A, "Good Decode Indication"},
    {0x3B, "Hands Free Scanning"},
    {0x3C, "Intrinsically Safe"},
    {0x3D, "Klasse Eins Laser"},
    {0x3E, "Long Range Scanner"},
    {0x3F, "Mirror Speed Control"},
    {0x40, "Not On File Indication"},
    {0x41, "Programmable Beeper"},
    {0x42, "Triggerless"},
    {0x43, "Wand"},
    {0x44, "Water Resistant"},
    {0x45, "Multi-Range Scanner"},
    {0x46, "Proximity Sensor"},
    {0x4D, "Fragment Decoding"},
    {0x4E, "Scanner Read Confidence"},
    {0x4F, "Data Prefix"},
    {0x50, "Prefix AIMI"},
    {0x51, "Prefix None"},
    {0x52, "Prefix Proprietary"},
    {0x55, "Active Time"},
    {0x56, "Aiming Laser Pattern"},
    {0x57, "Bar Code Present"},
    {0x58, "Beeper State"},
    {0x59, "Laser On Time"},
    {0x5A, "Laser State"},
    {0x5B, "Lockout Time"},
    {0x5C, "Motor State"},
    {0x5D, "Motor Timeout"},
    {0x5E, "Power On Reset Scanner"},
    {0x5F, "Prevent Read of Barcodes"},
    {0x60, "Initiate Barcode Read"},
    {0x61, "Trigger State"},
    {0x62, "Trigger Mode"},
    {0x63, "Trigger Mode Blinking Laser On"},
    {0x64, "Trigger Mode Continuous Laser On"},
    {0x65, "Trigger Mode Laser on while Pulled"},
    {0x66, "Trigger Mode Laser stays on after Trigger release"},
    {0x6D, "Commit Parameters to NVM"},
    {0x6E, "Parameter Scanning"},
    {0x6F, "Parameters Changed"},
    {0x70, "Set parameter default values"},
    {0x75, "Scanner In Cradle"},
    {0x76, "Scanner In Range"},
    {0x7A, "Aim Duration"},
    {0x7B, "Good Read Lamp Duration"},
    {0x7C, "Good Read Lamp Intensity"},
    {0x7D, "Good Read LED"},
    {0x7E, "Good Read Tone Frequency"},
    {0x7F, "Good Read Tone Length"},
    {0x80, "Good Read Tone Volume"},
    {0x82, "No Read Message"},
    {0x83, "Not on File Volume"},
    {0x84, "Powerup Beep"},
    {0x85, "Sound Error Beep"},
    {0x86, "Sound Good Read Beep"},
    {0x87, "Sound Not On File Beep"},
    {0x88, "Good Read When to Write"},
    {0x89, "GRWTI After Decode"},
    {0x8A, "GRWTI Beep/Lamp after transmit"},
    {0x8B, "GRWTI No Beep/Lamp use at all"},
    {0x91, "Bookland EAN"},
    {0x92, "Convert EAN 8 to 13 Type"},
    {0x93, "Convert UPC A to EAN-13"},
    {0x94, "Convert UPC-E to A"},
    {0x95, "EAN-13"},
    {0x96, "EAN-8"},
    {0x97, "EAN-99 128_Mandatory"},
    {0x98, "EAN-99 P5/128_Optional"},
    {0x9A, "UPC/EAN"},
    {0x9B, "UPC/EAN Coupon Code"},
    {0x9C, "UPC/EAN Periodicals"},
    {0x9D, "UPC-A"},
    {0x9E, "UPC-A with 128 Mandatory"},
    {0x9F, "UPC-A with 128 Optional"},
    {0xA0, "UPC-A with P5 Optional"},
    {0xA1, "UPC-E"},
    {0xA2, "UPC-E1"},
    {0xA9, "Periodical"},
    {0xAA, "Periodical Auto-Discriminate + 2"},
    {0xAB, "Periodical Only Decode with + 2"},
    {0xAC, "Periodical Ignore + 2"},
    {0xAD, "Periodical Auto-Discriminate + 5"},
    {0xAE, "Periodical Only Decode with + 5"},
    {0xAF, "Periodical Ignore + 5"},
    {0xB0, "Check"},
    {0xB1, "Check Disable Price"},
    {0xB2, "Check Enable 4 digit Price"},
    {0xB3, "Check Enable 5 digit Price"},
    {0xB4, "Check Enable European 4 digit Price"},
    {0xB5, "Check Enable European 5 digit Price"},
    {0xB7, "EAN Two Label"},
    {0xB8, "EAN Three Label"},
    {0xB9, "EAN 8 Flag Digit 1"},
    {0xBA, "EAN 8 Flag Digit 2"},
    {0xBB, "EAN 8 Flag Digit 3"},
    {0xBC, "EAN 13 Flag Digit 1"},
    {0xBD, "EAN 13 Flag Digit 2"},
    {0xBE, "EAN 13 Flag Digit 3"},
    {0xBF, "Add EAN 2/3 Label Definition"},
    {0xC0, "Clear all EAN 2/3 Label Definitions"},
    {0xC3, "Codabar"},
    {0xC4, "Code 128"},
    {0xC7, "Code 39"},
    {0xC8, "Code 93 "},
    {0xC9, "Full ASCII Conversion"},
    {0xCA, "Interleaved 2 of 5"},
    {0xCB, "Italian Pharmacy Code"},
    {0xCC, "MSI/Plessey"},
    {0xCD, "Standard 2 of 5 IATA"},
    {0xCE, "Standard 2 of 5"},
    {0xD3, "Transmit Start/Stop"},
    {0xD4, "Tri-Optic"},
    {0xD5, "UCC/EAN-128"},
    {0xD6, "Check Digit"},
    {0xD7, "Check Digit Disable"},
    {0xD8, "Check Digit Enable Interleaved 2 of 5 OPCC"},
    {0xD9, "Check Digit Enable Interleaved 2 of 5 USS"},
    {0xDA, "Check Digit Enable Standard 2 of 5 OPCC"},
    {0xDB, "Check Digit Enable Standard 2 of 5 USS"},
    {0xDC, "Check Digit Enable One MSI Plessey"},
    {0xDD, "Check Digit Enable Two MSI Plessey"},
    {0xDE, "Check Digit Codabar Enable"},
    {0xDF, "Check Digit Code 39 Enable"},
    {0xF0, "Transmit Check Digit"},
    {0xF1, "Disable Check Digit Transmit"},
    {0xF2, "Enable Check Digit Transmit"},
    {0xFB, "Symbology Identifier 1"},
    {0xFC, "Symbology Identifier 2"},
    {0xFD, "Symbology Identifier 3"},
    {0xFE, "Decoded Data"},
    {0xFF, "Decode Data Continued"},
    {0x00, "Bar Space Data"},
    {0x01, "Scanner Data Accuracy"},
    {0x02, "Raw Data Polarity"},
    {0x03, "Polarity Inverted Bar Code"},
    {0x04, "Polarity Normal Bar Code"},
    {0x06, "Minimum Length to Decode"},
    {0x07, "Maximum Length to Decode"},
    {0x08, "First Discrete Length to Decode"},
    {0x09, "Second Discrete Length to Decode"},
    {0x0A, "Data Length Method"},
    {0x0B, "DL Method Read any"},
    {0x0C, "DL Method Check in Range"},
    {0x0D, "DL Method Check for Discrete"},
    {0x10, "Aztec Code"},
    {0x11, "BC412"},
    {0x12, "Channel Code"},
    {0x13, "Code 16"},
    {0x14, "Code 32"},
    {0x15, "Code 49"},
    {0x16, "Code One"},
    {0x17, "Colorcode"},
    {0x18, "Data Matrix"},
    {0x19, "MaxiCode"},
    {0x1A, "MicroPDF"},
    {0x1B, "PDF-417"},
    {0x1C, "PosiCode"},
    {0x1D, "QR Code"},
    {0x1E, "SuperCode"},
    {0x1F, "UltraCode"},
    {0x20, "USD-5 (Slug Code)"},
    {0x21, "VeriCode"},
    {0, NULL}
};
static const value_string usb_hid_weighing_devices_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Weighing Device"},
    {0x20, "Scale Device"},
    {0x21, "Scale Class I Metric"},
    {0x22, "Scale Class I Metric"},
    {0x23, "Scale Class II Metric"},
    {0x24, "Scale Class III Metric"},
    {0x25, "Scale Class IIIL Metric"},
    {0x26, "Scale Class IV Metric"},
    {0x27, "Scale Class III English"},
    {0x28, "Scale Class IIIL English"},
    {0x29, "Scale Class IV English"},
    {0x2A, "Scale Class Generic"},
    {0x30, "Scale Attribute Report"},
    {0x31, "Scale Control Report"},
    {0x32, "Scale Data Report"},
    {0x33, "Scale Status Report"},
    {0x34, "Scale Weight Limit Report"},
    {0x35, "Scale Statistics Report"},
    {0x40, "Data Weight"},
    {0x41, "Data Scaling"},
    {0x50, "Weight Unit"},
    {0x51, "Weight Unit Milligram"},
    {0x52, "Weight Unit Gram"},
    {0x53, "Weight Unit Kilogram"},
    {0x54, "Weight Unit Carats"},
    {0x55, "Weight Unit Taels"},
    {0x56, "Weight Unit Grains"},
    {0x57, "Weight Unit Pennyweights"},
    {0x58, "Weight Unit Metric Ton"},
    {0x59, "Weight Unit Avoir Ton"},
    {0x5A, "Weight Unit Troy Ounce"},
    {0x5B, "Weight Unit Ounce"},
    {0x5C, "Weight Unit Pound"},
    {0x60, "Calibration Count"},
    {0x61, "Re-Zero Count"},
    {0x70, "Scale Status"},
    {0x71, "Scale Status Fault"},
    {0x72, "Scale Status Stable at Center of Zero"},
    {0x73, "Scale Status In Motion"},
    {0x74, "Scale Status Weight Stable"},
    {0x75, "Scale Status Under Zero"},
    {0x76, "Scale Status Over Weight Limit"},
    {0x77, "Scale Status Requires Calibration"},
    {0x78, "Scale Status Requires Re- zeroing"},
    {0x80, "Zero Scale"},
    {0x81, "Enforced Zero Return"},
    {0, NULL}
};
static const value_string usb_hid_magnetic_stripe_reader_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "MSR Device Read-Only"},
    {0x11, "Track 1 Length"},
    {0x12, "Track 2 Length"},
    {0x13, "Track 3 Length"},
    {0x14, "Track JIS Length"},
    {0x20, "Track Data"},
    {0x21, "Track 1 Data"},
    {0x22, "Track 2 Data"},
    {0x23, "Track 3 Data"},
    {0x24, "Track JIS Data"},
    {0, NULL}
};
static const value_string usb_hid_camera_control_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x20, "Camera Auto-focus"},
    {0x21, "Camera Shutter"},
    {0, NULL}
};
static const value_string usb_hid_arcade_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "General Purpose IO Card"},
    {0x02, "Coin Door"},
    {0x03, "Watchdog Timer"},
    {0x30, "General Purpose Analog Input State"},
    {0x31, "General Purpose Digital Input State"},
    {0x32, "General Purpose Optical Input State"},
    {0x33, "General Purpose Digital Output State"},
    {0x34, "Number of Coin Doors"},
    {0x35, "Coin Drawer Drop Count"},
    {0x36, "Coin Drawer Start"},
    {0x37, "Coin Drawer Service"},
    {0x38, "Coin Drawer Tilt"},
    {0x39, "Coin Door Test"},
    {0x3F, "[Undefined]"},
    {0x40, "Coin Door Lockout"},
    {0x41, "Watchdog Timeout"},
    {0x42, "Watchdog Action"},
    {0x43, "Watchdog Reboot"},
    {0x44, "Watchdog Restart"},
    {0x45, "Alarm Input"},
    {0x46, "Coin Door Counter"},
    {0x47, "I/O Direction Mapping"},
    {0x48, "Set I/O Direction"},
    {0x49, "Extended Optical Input State"},
    {0x4A, "Pin Pad Input State"},
    {0x4B, "Pin Pad Status"},
    {0x4C, "Pin Pad Output"},
    {0x4D, "Pin Pad Command"},
    {0, NULL}
};
static const value_string usb_hid_fido_alliance_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "U2F Authenticator Device"},
    {0x20, "Input Report Data"},
    {0x21, "Output Report Data"},
    {0, NULL}
};

static const value_string keycode_vals[] = {
    {0x00, "<ACTION KEY UP>"},
    {0x01, "ErrorRollOver"},
    {0x02, "POSTFail"},
    {0x03, "ErrorUndefined"},

    {0x04, "a"},
    {0x05, "b"},
    {0x06, "c"},
    {0x07, "d"},
    {0x08, "e"},
    {0x09, "f"},
    {0x0A, "g"},
    {0x0B, "h"},
    {0x0C, "i"},
    {0x0D, "j"},
    {0x0E, "k"},
    {0x0F, "l"},
    {0x10, "m"},
    {0x11, "n"},
    {0x12, "o"},
    {0x13, "p"},
    {0x14, "q"},
    {0x15, "r"},
    {0x16, "s"},
    {0x17, "t"},
    {0x18, "u"},
    {0x19, "v"},
    {0x1A, "w"},
    {0x1B, "x"},
    {0x1C, "y"},
    {0x1D, "z"},

    {0x1E, "1"},
    {0x1F, "2"},
    {0x20, "3"},
    {0x21, "4"},
    {0x22, "5"},
    {0x23, "6"},
    {0x24, "7"},
    {0x25, "8"},
    {0x26, "9"},
    {0x27, "0"},

    {0x28, "ENTER"},
    {0x29, "Escape"},
    {0x2A, "Backspace"},
    {0x2B, "Tab"},
    {0x2C, "Spacebar"},

    {0x2D, "-"},
    {0x2E, "="},
    {0x2F, "["},
    {0x30, "]"},
    {0x31, "\\"},
    {0x32, "NonUS #/~"},
    {0x33, ";"},
    {0x34, "'"},
    {0x35, "`"},
    {0x36, ","},
    {0x37, "."},
    {0x38, "/"},
    {0x39, "CapsLock"},
    {0x3A, "F1"},
    {0x3B, "F2"},
    {0x3C, "F3"},
    {0x3D, "F4"},
    {0x3E, "F5"},
    {0x3F, "F6"},
    {0x40, "F7"},
    {0x41, "F8"},
    {0x42, "F9"},
    {0x43, "F10"},
    {0x44, "F11"},
    {0x45, "F12"},
    {0x46, "PrintScreen"},
    {0x47, "ScrollLock"},
    {0x48, "Pause"},
    {0x49, "Insert"},
    {0x4A, "Home"},
    {0x4B, "PageUp"},
    {0x4C, "DeleteForward"},
    {0x4D, "End"},
    {0x4E, "PageDown"},
    {0x4F, "RightArrow"},
    {0x50, "LeftArrow"},
    {0x51, "DownArrow"},
    {0x52, "UpArrow"},
    {0x53, "NumLock"},

    /* Keypad */
    {0x54, "Keypad /"},
    {0x55, "Keypad *"},
    {0x56, "Keypad -"},
    {0x57, "Keypad +"},
    {0x58, "Keypad ENTER"},
    {0x59, "Keypad 1"},
    {0x5A, "Keypad 2"},
    {0x5B, "Keypad 3"},
    {0x5C, "Keypad 4"},
    {0x5D, "Keypad 5"},
    {0x5E, "Keypad 6"},
    {0x5F, "Keypad 7"},
    {0x60, "Keypad 8"},
    {0x61, "Keypad 9"},
    {0x62, "Keypad 0"},
    {0x63, "Keypad ."},

    /* non PC AT */
    {0x64, "NonUS \\/|"},
    {0x65, "Application"},
    {0x66, "Power"},
    {0x67, "Keypad ="},
    {0x68, "F13"},
    {0x69, "F14"},
    {0x6A, "F15"},
    {0x6B, "F16"},
    {0x6C, "F17"},
    {0x6D, "F18"},
    {0x6E, "F19"},
    {0x6F, "F20"},

    {0x70, "F21"},
    {0x71, "F22"},
    {0x72, "F23"},
    {0x73, "F24"},
    {0x74, "Execute"},
    {0x75, "Help"},
    {0x76, "Menu"},
    {0x77, "Select"},
    {0x78, "Stop"},
    {0x79, "Again"},
    {0x7A, "Undo"},
    {0x7B, "Cut"},
    {0x7C, "Copy"},
    {0x7D, "Paste"},
    {0x7E, "Find"},
    {0x7F, "Mute"},

    {0x80, "VolumeUp"},
    {0x81, "VolumeDown"},
    {0x82, "Locking CapsLock"},
    {0x83, "Locking NumLock"},
    {0x84, "Locking ScrollLock"},
    {0x85, "Keypad Comma"},
    {0x86, "Keypad EqualSign"},
    {0x87, "International1"},
    {0x88, "International2"},
    {0x89, "International3"},
    {0x8A, "International4"},
    {0x8B, "International5"},
    {0x8C, "International6"},
    {0x8D, "International7"},
    {0x8E, "International8"},
    {0x8F, "International9"},

    {0x90, "LANG1"},
    {0x91, "LANG2"},
    {0x92, "LANG3"},
    {0x93, "LANG4"},
    {0x94, "LANG5"},
    {0x95, "LANG6"},
    {0x96, "LANG7"},
    {0x97, "LANG8"},
    {0x98, "LANG9"},
    {0x99, "AlternateErase"},
    {0x9A, "SysReq/Attention"},
    {0x9B, "Cancel"},
    {0x9C, "Clear"},
    {0x9D, "Prior"},
    {0x9E, "Return"},
    {0x9F, "Separator"},

    {0xA0, "Out"},
    {0xA1, "Oper"},
    {0xA2, "Clear/Again"},
    {0xA3, "CrSel/Props"},
    {0xA4, "ExSel"},
    /* 0xA5..0xAF - reserved */
    {0xB0, "Keypad 00"},
    {0xB1, "Keypad 000"},
    {0xB2, "ThousandsSeparator"},
    {0xB3, "DecimalSeparator"},
    {0xB4, "CurrencyUnit"},
    {0xB5, "CurrencySubunit"},
    {0xB6, "Keypad ("},
    {0xB7, "Keypad )"},
    {0xB8, "Keypad {"},
    {0xB9, "Keypad }"},
    {0xBA, "Keypad Tab"},
    {0xBB, "Keypad Backspace"},
    {0xBC, "Keypad A"},
    {0xBD, "Keypad B"},
    {0xBE, "Keypad C"},
    {0xBF, "Keypad D"},

    {0xC0, "Keypad E"},
    {0xC1, "Keypad F"},
    {0xC2, "Keypad XOR"},
    {0xC3, "Keypad ^"},
    {0xC4, "Keypad %"},
    {0xC5, "Keypad <"},
    {0xC6, "Keypad >"},
    {0xC7, "Keypad &"},
    {0xC8, "Keypad &&"},
    {0xC9, "Keypad |"},
    {0xCA, "Keypad ||"},
    {0xCB, "Keypad :"},
    {0xCC, "Keypad #"},
    {0xCD, "Keypad Space"},
    {0xCE, "Keypad @"},
    {0xCF, "Keypad !"},

    {0xD0, "Keypad Memory Store"},
    {0xD1, "Keypad Memory Recall"},
    {0xD2, "Keypad Memory Clear"},
    {0xD3, "Keypad Memory Add"},
    {0xD4, "Keypad Memory Subtract"},
    {0xD5, "Keypad Memory Multiply"},
    {0xD6, "Keypad Memory Divide"},
    {0xD7, "Keypad +/-"},
    {0xD8, "Keypad Clear"},
    {0xD9, "Keypad Clear Entry"},
    {0xDA, "Keypad Binary"},
    {0xDB, "Keypad Octal"},
    {0xDC, "Keypad Decimal"},
    {0xDD, "Keypad Hexadecimal"},
    /* 0xDE..0xDF - reserved,  */
    {0xE0, "LeftControl"},
    {0xE1, "LeftShift"},
    {0xE2, "LeftAlt"},
    {0xE3, "LeftGUI"},
    {0xE4, "RightControl"},
    {0xE5, "RightShift"},
    {0xE6, "RightAlt"},
    {0xE7, "RightGUI"},

    {0, NULL}
};
static value_string_ext keycode_vals_ext = VALUE_STRING_EXT_INIT(keycode_vals);

static uint32_t
hid_unpack_value(uint8_t *data, unsigned int idx, unsigned int size)
{
    uint32_t value = 0;

    for(unsigned int i = 1; i <= size; i++)
        value |= data[idx + i] << (8 * (i - 1));

    return value;
}

static bool
hid_unpack_signed(uint8_t *data, unsigned int idx, unsigned int size, int32_t *value)
{
    if (size == 1)
        *value = (int8_t) hid_unpack_value(data, idx, size);
    else if (size == 2)
        *value = (int16_t) hid_unpack_value(data, idx, size);
    else if (size == 4)
        *value = (int32_t) hid_unpack_value(data, idx, size);
    else
        return true;

    return false;
}

static bool
parse_report_descriptor(report_descriptor_t *rdesc)
{
    hid_field_t field;
    uint8_t *data = rdesc->desc_body;
    unsigned int tag, type, size;
    uint8_t prefix;
    uint32_t defined = 0, usage_page = 0, usage = 0, usage_min = 0, usage_max = 0;
    wmem_allocator_t *scope = wmem_file_scope();
    bool first_item = true;

    memset(&field, 0, sizeof(field));
    field.usages = wmem_array_new(scope, sizeof(uint32_t));
    rdesc->fields_in = wmem_array_new(scope, sizeof(hid_field_t));
    rdesc->fields_out = wmem_array_new(scope, sizeof(hid_field_t));

    int i = 0;
    while (i < rdesc->desc_length)
    {
        prefix = data[i];
        tag = (prefix & 0b11110000) >> 4;
        type = (prefix & 0b00001100) >> 2;
        size = prefix & 0b00000011;

        if (size == 3)  /* HID spec: 6.2.2.2 - Short Items */
            size = 4;

        switch (type)
        {
            case USBHID_ITEMTYPE_MAIN:
                switch (tag)
                {
                    case USBHID_MAINITEM_TAG_INPUT:
                        field.properties = hid_unpack_value(data, i, size);

                        if ((defined & HID_REQUIRED_MASK) != HID_REQUIRED_MASK)
                            goto err;

                        /* new field */
                        wmem_array_append_one(rdesc->fields_in, field);

                        field.usages = wmem_array_new(scope, sizeof(uint32_t));
                        first_item = false;

                        /* only keep the global items */
                        defined &= HID_GLOBAL_MASK;
                        break;

                    case USBHID_MAINITEM_TAG_OUTPUT:
                        field.properties = hid_unpack_value(data, i, size);

                        if ((defined & HID_REQUIRED_MASK) != HID_REQUIRED_MASK)
                            goto err;

                        /* new field */
                        wmem_array_append_one(rdesc->fields_out, field);

                        field.usages = wmem_array_new(scope, sizeof(uint32_t));
                        first_item = false;

                        defined &= HID_GLOBAL_MASK;
                        break;

                    case USBHID_MAINITEM_TAG_FEATURE:
                        /*
                        field.properties = hid_unpack_value(data, i, size);
                        TODO
                        */
                        break;

                    case USBHID_MAINITEM_TAG_COLLECTION:
                        /* clear usages */
                        wmem_free(scope, field.usages);
                        field.usages = wmem_array_new(scope, sizeof(uint32_t));
                        break;

                    default:
                        break;
                }
                break;

            case USBHID_ITEMTYPE_GLOBAL:
                switch (tag)
                {
                    case USBHID_GLOBALITEM_TAG_USAGE_PAGE:
                        usage_page = hid_unpack_value(data, i, size);
                        if (usage_page > UINT16_MAX)
                            goto err;
                        defined |= HID_USAGE_PAGE;
                        break;

                    case USBHID_GLOBALITEM_TAG_LOG_MIN:
                        if (hid_unpack_signed(data, i, size, &field.logical_min))
                            goto err;
                        defined |= HID_LOGICAL_MIN;
                        break;

                    case USBHID_GLOBALITEM_TAG_LOG_MAX:
                        if (hid_unpack_signed(data, i, size, &field.logical_max))
                            goto err;
                        defined |= HID_LOGICAL_MAX;
                        break;

                    case USBHID_GLOBALITEM_TAG_REPORT_SIZE:
                        field.report_size = hid_unpack_value(data, i, size);
                        defined |= HID_REPORT_SIZE;
                        break;

                    case USBHID_GLOBALITEM_TAG_REPORT_ID:
                        if (!first_item && !rdesc->uses_report_id)
                            goto err;

                        rdesc->uses_report_id = true;

                        field.report_id = hid_unpack_value(data, i, size);
                        defined |= HID_REPORT_ID;
                        break;

                    case USBHID_GLOBALITEM_TAG_REPORT_COUNT:
                        field.report_count = hid_unpack_value(data, i, size);
                        defined |= HID_REPORT_COUNT;
                        break;

                    case USBHID_GLOBALITEM_TAG_PUSH:
                    case USBHID_GLOBALITEM_TAG_POP:
                        /* TODO */
                        goto err;

                    default:
                        break;
                }
                break;

            case USBHID_ITEMTYPE_LOCAL:
                switch (tag)
                {
                    case USBHID_LOCALITEM_TAG_USAGE:
                        usage = hid_unpack_value(data, i, size);

                        /* Extended usage (size 4) combines both usage page and id */
                        if (size != 4) {
                            if (!(defined & HID_USAGE_PAGE))
                                goto err;
                            usage |= usage_page << 16;
                        }

                        wmem_array_append_one(field.usages, usage);
                        break;

                    case USBHID_LOCALITEM_TAG_USAGE_MIN:
                        usage_min = hid_unpack_value(data, i, size);
                        if (size == 4) {
                            /* Usage max must be extended as well */
                            defined |= HID_EXTENDED_USAGE;
                        } else {
                            if (!(defined & HID_USAGE_PAGE))
                                goto err;
                            usage_min |= usage_page << 16;
                        }
                        defined |= HID_USAGE_MIN;
                        break;

                    case USBHID_LOCALITEM_TAG_USAGE_MAX:
                        if (!(defined & HID_USAGE_MIN))
                            goto err;

                        usage_max = hid_unpack_value(data, i, size);
                        if (defined & HID_EXTENDED_USAGE) {
                            /* Fail if max is not extended usage (HID spec 6.2.2.8) */
                            if (size != 4)
                                goto err;
                        } else if (size == 4) {
                            /* Fail because min wasn't extended, but max is */
                            goto err;
                        } else {
                            if (!(defined & HID_USAGE_PAGE))
                                goto err;
                            usage_max |= usage_page << 16;
                        }

                        /* Usage min and max must be on the same page */
                        if (USAGE_PAGE(usage_min) != USAGE_PAGE(usage_max)) {
                            goto err;
                        }

                        if (usage_min > usage_max) {
                            goto err;
                        }

                        /* min and max are inclusive */
                        wmem_array_grow(field.usages, usage_max - usage_min + 1);
                        for (uint32_t j = usage_min; j <= usage_max; j++) {
                            wmem_array_append_one(field.usages, j);
                        }

                        defined &= ~(HID_USAGE_MIN | HID_EXTENDED_USAGE);
                        break;

                    default: /* TODO */
                        goto err;
                }
                break;

            default: /* reserved */
                goto err;
        }

        i += size + 1;
    }

    return true;

err:
    for (unsigned int j = 0; j < wmem_array_get_count(rdesc->fields_in); j++)
        wmem_free(scope, ((hid_field_t*) wmem_array_index(rdesc->fields_in, j))->usages);

    for (unsigned int j = 0; j < wmem_array_get_count(rdesc->fields_out); j++)
        wmem_free(scope, ((hid_field_t*) wmem_array_index(rdesc->fields_out, j))->usages);

    wmem_free(scope, rdesc->fields_in);
    wmem_free(scope, rdesc->fields_out);
    return false;
}


static bool
is_correct_interface(usb_conv_info_t *info1, usb_conv_info_t *info2)
{
    return (info1->bus_id == info2->bus_id) &&
           (info1->device_address == info2->device_address) &&
           (info1->interfaceNum == info2->interfaceNum);
}

/* Returns the report descriptor */
static report_descriptor_t _U_ *
get_report_descriptor(packet_info *pinfo _U_, usb_conv_info_t *usb_info)
{
    uint32_t bus_id = usb_info->bus_id;
    uint32_t device_address = usb_info->device_address;
    uint32_t interface = usb_info->interfaceNum;
    wmem_tree_key_t key[] = {
        {1, &bus_id},
        {1, &device_address},
        {1, &interface},
        {1, &pinfo->num},
        {0, NULL}
    };

    report_descriptor_t *data = NULL;
    data = (report_descriptor_t*) wmem_tree_lookup32_array_le(report_descriptors, key);
    if (data && is_correct_interface(usb_info, &data->usb_info))
        return data;

    return NULL;
}

/* Inserts the report descriptor */
static void
insert_report_descriptor(packet_info *pinfo, report_descriptor_t *data)
{
    uint32_t bus_id = data->usb_info.bus_id;
    uint32_t device_address = data->usb_info.device_address;
    uint32_t interface = data->usb_info.interfaceNum;
    wmem_tree_key_t key[] = {
        {1, &bus_id},
        {1, &device_address},
        {1, &interface},
        {1, &pinfo->num},
        {0, NULL}
    };

    wmem_tree_insert32_array(report_descriptors, key, data);
}

/* Returns usage page string */
static const char*
get_usage_page_string(uint32_t usage_page)
{
    const char *str;

    str = try_val_to_str(usage_page, usb_hid_item_usage_page_vals);
    if (!str) {
        if ((usage_page & VENDOR_PAGE_HBYTE) == VENDOR_PAGE_HBYTE)
            str = "Vendor";
        else
            str = "Reserved";
    }

    return str;
}

/* Returns usage page item string */
static char*
get_usage_page_item_string(wmem_allocator_t *pool, uint32_t usage_page, uint32_t id)
{
    const char *str = NULL;
    const char *fmt_str = NULL;

    switch (usage_page)
    {
    case GENERIC_DESKTOP_CONTROLS_PAGE:
        str = try_val_to_str(id, usb_hid_generic_desktop_controls_usage_page_vals);
        break;
    case SIMULATION_CONTROLS_PAGE:
        str = try_val_to_str(id, usb_hid_simulation_control_usage_page_vals);
        break;
    case VR_CONTROLS_PAGE:
        str = try_val_to_str(id, usb_hid_vr_controls_usage_page_vals);
        break;
    case SPORT_CONTROLS_PAGE:
        str = try_val_to_str(id, usb_hid_sport_controls_usage_page_vals);
        break;
    case GAME_CONTROLS_PAGE:
        str = try_val_to_str(id, usb_hid_game_controls_usage_page_vals);
        break;
    case GENERIC_DEVICE_CONTROLS_PAGE:
        str = try_val_to_str(id, usb_hid_generic_device_controls_usage_page_vals);
        break;
    case KEYBOARD_KEYPAD_PAGE:
        str = try_val_to_str(id, usb_hid_keyboard_keypad_usage_page_vals);
        break;
    case LED_PAGE:
        str = try_val_to_str(id, usb_hid_led_usage_page_vals);
        break;
    case BUTTON_PAGE:
        str = try_val_to_str(id, usb_hid_button_usage_page_vals);
        if (!str)
            fmt_str = "Button %u";
        break;
    case ORDINAL_PAGE:
        str = try_val_to_str(id, usb_hid_ordinal_usage_page_vals);
        break;
    case TELEPHONY_PAGE:
        str = try_val_to_str(id, usb_hid_telephony_device_usage_page_vals);
        break;
    case CONSUMER_PAGE:
        str = try_val_to_str(id, usb_hid_consumer_usage_page_vals);
        if (!str)
            fmt_str = "Instance %u";
        break;
    case DIGITIZER_PAGE:
        str = try_val_to_str(id, usb_hid_digitizers_usage_page_vals);
        break;
    case HAPTICS_PAGE:
        str = try_val_to_str(id, usb_hid_haptic_usage_page_vals);
        if (id >= 0x2001 && id <= 0x2FFF)
            str = "Vendor Waveforms";
        break;
    case PID_PAGE:
        str = try_val_to_str(id, usb_hid_physical_input_device_usage_page_vals);
        break;
    case UNICODE_PAGE:
        fmt_str = "Character U+%04X";
        break;
    case EYE_AND_HEAD_TRACKER_PAGE:
        str = try_val_to_str(id, usb_hid_eye_and_head_tracker_usage_page_vals);
        break;
    case ALPHANUMERIC_DISPLAY_PAGE:
        str = try_val_to_str(id, usb_hid_alphanumeric_display_usage_page_vals);
        break;
    case SENSOR_PAGE:
        str = try_val_to_str(id, usb_hid_sensor_usage_page_vals);
        if (!str)
            str = try_rval_to_str(id, usb_hid_sensor_usage_page_ranges);
        break;
    case MEDICAL_INSTRUMENTS_PAGE:
        str = try_val_to_str(id, usb_hid_medical_instrument_usage_page_vals);
        break;
    case BRAILLE_DISPLAY_PAGE:
        str = try_val_to_str(id, usb_hid_braille_display_usage_page_vals);
        break;
    case LIGHTING_AND_ILLUMINATION_PAGE:
        str = try_val_to_str(id, usb_hid_lighting_and_illumination_usage_page_vals);
        break;
    case USB_MONITOR_PAGE:
        str = try_val_to_str(id, usb_hid_monitor_usage_page_vals);
        break;
    case USB_ENUMERATED_VALUES_PAGE:
        fmt_str = "ENUM_%u";
        break;
    case VESA_VIRTUAL_CONTROLS_PAGE:
        str = try_val_to_str(id, usb_hid_vesa_virtual_control_usage_page_vals);
        break;
    case POWER_DEVICE_PAGE:
        str = try_val_to_str(id, usb_hid_power_device_usage_page_vals);
        break;
    case BATTERY_SYSTEM_PAGE:
        str = try_val_to_str(id, usb_hid_battery_system_usage_page_vals);
        break;
    case BARCODE_SCANNER_PAGE:
        str = try_val_to_str(id, usb_hid_barcode_scanner_usage_page_vals);
        break;
    case WEIGHING_PAGE:
        str = try_val_to_str(id, usb_hid_weighing_devices_usage_page_vals);
        break;
    case MSR_PAGE:
        str = try_val_to_str(id, usb_hid_magnetic_stripe_reader_usage_page_vals);
        break;
    case CAMERA_CONTROL_PAGE:
        str = try_val_to_str(id, usb_hid_camera_control_usage_page_vals);
        break;
    case ARCADE_PAGE:
        str = try_val_to_str(id, usb_hid_arcade_usage_page_vals);
        break;
    case FIDO_ALLIANCE_PAGE:
        str = try_val_to_str(id, usb_hid_fido_alliance_usage_page_vals);
        break;
    default:
        if ((usage_page & VENDOR_PAGE_HBYTE) == VENDOR_PAGE_HBYTE)
            str = "Vendor";
        break;
    }

    if (fmt_str) {
        return wmem_strdup_printf(pool, fmt_str, id);
    }
    if (!str) {
        str = "Reserved";
    }
    return wmem_strdup_printf(pool, "%s", str);
}

/* Dissector for the data in a HID main report. */
static int
dissect_usb_hid_report_mainitem_data(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, unsigned int bSize, unsigned int bTag)
{
    proto_item *ti = proto_tree_get_parent(tree);
    uint32_t val = 0;

    switch (bTag) {
        case USBHID_MAINITEM_TAG_INPUT:
        case USBHID_MAINITEM_TAG_OUTPUT:
        case USBHID_MAINITEM_TAG_FEATURE:
            proto_tree_add_item(tree, hf_usb_hid_mainitem_bit0, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_mainitem_bit1, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_mainitem_bit2, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_mainitem_bit3, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_mainitem_bit4, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_mainitem_bit5, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_mainitem_bit6, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            if (bTag == USBHID_MAINITEM_TAG_INPUT)
                proto_tree_add_item(tree, hf_usb_hid_mainitem_bit7_input, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_item(tree, hf_usb_hid_mainitem_bit7, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            if (bSize > 1)
                proto_tree_add_item(tree, hf_usb_hid_mainitem_bit8, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            else
                proto_tree_add_boolean_format_value(tree, hf_usb_hid_mainitem_bit8, tvb, offset, 0, false, "Buffered bytes (default, no second byte present)");

            val = tvb_get_uint8(tvb, offset);
            if (val & (1 << 0))
                proto_item_append_text(ti, " (Const,");
            else
                proto_item_append_text(ti, " (Data,");
            if (val & (1 << 1))
                proto_item_append_text(ti, "Var,");
            else
                proto_item_append_text(ti, "Array,");
            if (val & (1 << 2))
                proto_item_append_text(ti, "Rel");
            else
                proto_item_append_text(ti, "Abs");
            if (val & (1 << 3))
                proto_item_append_text(ti, ",Wrap");
            if (val & (1 << 4))
                proto_item_append_text(ti, ",NonLinear");
            if (val & (1 << 5))
                proto_item_append_text(ti, ",NoPref");
            if (val & (1 << 6))
                proto_item_append_text(ti, ",Null");
            if ((bTag == USBHID_MAINITEM_TAG_OUTPUT || bTag == USBHID_MAINITEM_TAG_FEATURE) && val & (1 << 7))
                proto_item_append_text(ti, ",Volatile");
            if (val & (1 << 8))
                proto_item_append_text(ti, ",BuffBytes");
            proto_item_append_text(ti, ")");
            break;
        case USBHID_MAINITEM_TAG_COLLECTION:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_mainitem_colltype, tvb, offset, 1, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (%s)", rval_to_str_const(val, usb_hid_mainitem_colltype_vals, "Unknown"));
            break;
        case USBHID_MAINITEM_TAG_ENDCOLLECTION:
            /* No item data */
            break;
        default:
            proto_tree_add_item(tree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
            proto_item_append_text(ti, " (Unknown)");
            break;
    }
    offset += bSize;
    return offset;
}

/* Dissector for the data in a HID main report. */
static int
dissect_usb_hid_report_globalitem_data(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, unsigned int bSize, unsigned int bTag, struct usb_hid_global_state *global)
{
    const char *str = NULL;
    proto_item *ti = proto_tree_get_parent(tree);
    uint32_t val = 0;
    int32_t val_sig = 0;

    switch (bTag) {
        case USBHID_GLOBALITEM_TAG_USAGE_PAGE:
            switch (bSize) {
                case 1: global->usage_page = tvb_get_uint8(tvb, offset); break;
                case 2: global->usage_page = tvb_get_letohs(tvb, offset); break;
                case 3: global->usage_page = tvb_get_letoh24(tvb, offset); break;
                case 4: global->usage_page = tvb_get_letohl(tvb, offset); break;
                default: global->usage_page = 0; break;
            }
            str = get_usage_page_string(global->usage_page);
            proto_tree_add_uint_format(tree, hf_usb_hid_globalitem_usage, tvb, offset, bSize, global->usage_page, "Usage Page: %s (0x%02x)", str, global->usage_page);
            proto_item_append_text(ti, " (%s)", str);
            break;
        case USBHID_GLOBALITEM_TAG_LOG_MIN:
            proto_tree_add_item_ret_int(tree, hf_usb_hid_globalitem_log_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val_sig);
            proto_item_append_text(ti, " (%d)", val_sig);
            break;
        case USBHID_GLOBALITEM_TAG_LOG_MAX:
            proto_tree_add_item_ret_int(tree, hf_usb_hid_globalitem_log_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val_sig);
            proto_item_append_text(ti, " (%d)", val_sig);
            break;
        case USBHID_GLOBALITEM_TAG_PHY_MIN:
            proto_tree_add_item_ret_int(tree, hf_usb_hid_globalitem_phy_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val_sig);
            proto_item_append_text(ti, " (%d)", val_sig);
            break;
        case USBHID_GLOBALITEM_TAG_PHY_MAX:
            proto_tree_add_item_ret_int(tree, hf_usb_hid_globalitem_phy_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val_sig);
            proto_item_append_text(ti, " (%d)", val_sig);
            break;
        case USBHID_GLOBALITEM_TAG_UNIT_EXP:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_unit_exp, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            if (val >= 7)
                proto_item_append_text(ti, " (%u)", val);
            else
                proto_item_append_text(ti, " (%d)", -(16 - (int) val));
            break;
        case USBHID_GLOBALITEM_TAG_UNIT:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_sys, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_len, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_mass, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_time, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_temp, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_current, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_brightness, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_item_append_text(ti, " (0x%02x)", tvb_get_uint8(tvb, offset));
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_SIZE:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_report_size, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (%u)", val);
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_ID:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_report_id, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_COUNT:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_report_count, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (%u)", val);
            break;
        case USBHID_GLOBALITEM_TAG_PUSH:
            // Push and Pop have no data, but the HID spec 6.2.2.7 doesn't prohibit it.
            if(bSize > 0) {
                proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_push, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
                proto_item_append_text(ti, " (%u)", val);
            }
            break;
        case USBHID_GLOBALITEM_TAG_POP:
            // Push and Pop have no data, but the HID spec 6.2.2.7 doesn't prohibit it.
            if(bSize > 0) {
                proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_pop, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
                proto_item_append_text(ti, " (%u)", val);
            }
            break;
        default:
            proto_tree_add_item(tree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
            proto_item_append_text(ti, " (Unknown)");
            break;
    }
    offset += bSize;
    return offset;
}

/* Dissector for the data in a HID main report. */
static int
dissect_usb_hid_report_localitem_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, unsigned int bSize, unsigned int bTag, struct usb_hid_global_state *global)
{
    uint32_t id = 0xffff;
    proto_item *ti = proto_tree_get_parent(tree);
    char *str = NULL;
    uint32_t val = 0;

    switch (bTag) {
        case USBHID_LOCALITEM_TAG_USAGE:
            if (bSize > 2) {
                /* Full page ID */
                proto_tree_add_item(tree, hf_usb_hid_localitem_usage, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            } else {
                /* Only lower few bits given, need to combine with last global ID */
                if (bSize == 1)
                    id = tvb_get_uint8(tvb, offset);
                else if (bSize == 2)
                    id = tvb_get_ntohs(tvb, offset);
                str = get_usage_page_item_string(pinfo->pool, global->usage_page, id);
                proto_tree_add_uint_format(tree, hf_usb_hid_localitem_usage, tvb, offset, bSize, id, "Usage: %s (0x%02x)", str, id);
                proto_item_append_text(ti, " (%s)", str);
            }
            break;
        case USBHID_LOCALITEM_TAG_USAGE_MIN:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_usage_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_USAGE_MAX:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_usage_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_DESIG_INDEX:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_desig_index, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_DESIG_MIN:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_desig_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_DESIG_MAX:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_desig_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_STRING_INDEX:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_string_index, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_STRING_MIN:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_string_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_STRING_MAX:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_string_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_DELIMITER:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_delimiter, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        default:
            proto_tree_add_item(tree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
            proto_item_append_text(ti, " (Unknown)");
            break;
    }
    offset += bSize;

    return offset;
}

/* Dissector for individual HID report items.  Recursive. */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_usb_hid_report_item(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_conv_info_t *usb_conv_info _U_, const struct usb_hid_global_state *global)
{
    proto_item *subitem;
    proto_tree *tree, *subtree;
    int old_offset;
    unsigned int tmp;
    unsigned int bSize, bType, bTag;
    const value_string *usb_hid_cur_bTag_vals;
    int hf_usb_hid_curitem_bTag;
    struct usb_hid_global_state cur_global;
    memcpy(&cur_global, global, sizeof(struct usb_hid_global_state));

    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        old_offset=offset;

        tmp = tvb_get_uint8(tvb, offset);
        bSize = tmp & USBHID_SIZE_MASK;
        if (bSize == 3) bSize++; /* 3 == four bytes */
        bType = (tmp & USBHID_TYPE_MASK) >> 2;
        bTag = (tmp & USBHID_TAG_MASK) >> 4;

        switch (bType) {
            case USBHID_ITEMTYPE_MAIN:
                hf_usb_hid_curitem_bTag = hf_usb_hid_mainitem_bTag;
                usb_hid_cur_bTag_vals = usb_hid_mainitem_bTag_vals;
                break;
            case USBHID_ITEMTYPE_GLOBAL:
                hf_usb_hid_curitem_bTag = hf_usb_hid_globalitem_bTag;
                usb_hid_cur_bTag_vals = usb_hid_globalitem_bTag_vals;
                break;
            case USBHID_ITEMTYPE_LOCAL:
                hf_usb_hid_curitem_bTag = hf_usb_hid_localitem_bTag;
                usb_hid_cur_bTag_vals = usb_hid_localitem_bTag_vals;
                break;
            default: /* Only USBHID_ITEMTYPE_LONG, but keep compiler happy */
                hf_usb_hid_curitem_bTag = hf_usb_hid_longitem_bTag;
                usb_hid_cur_bTag_vals = usb_hid_longitem_bTag_vals;
                break;
        }

        subtree = proto_tree_add_subtree_format(parent_tree, tvb, offset, bSize + 1, ett_usb_hid_item_header, &subitem, "%s", val_to_str(bTag, usb_hid_cur_bTag_vals, "Unknown/%u tag"));

        tree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_usb_hid_item_header, NULL, "Header");
        proto_tree_add_item(tree, hf_usb_hid_item_bSize, tvb, offset,   1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_hid_item_bType, tvb, offset,   1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_hid_curitem_bTag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if ((bType == 3) && (bTag == 16)) {
            /* Long item */
            bSize = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(subtree, hf_usb_hid_item_bDataSize, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(subtree, hf_usb_hid_item_bLongItemTag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset++;
            proto_tree_add_item(subtree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
            offset += bSize;
        } else {
            /* Short item */
            switch (bType) {
                case USBHID_ITEMTYPE_MAIN:
                    offset = dissect_usb_hid_report_mainitem_data(pinfo, subtree, tvb, offset, bSize, bTag);
                    break;
                case USBHID_ITEMTYPE_GLOBAL:
                    offset = dissect_usb_hid_report_globalitem_data(pinfo, subtree, tvb, offset, bSize, bTag, &cur_global);
                    break;
                case USBHID_ITEMTYPE_LOCAL:
                    offset = dissect_usb_hid_report_localitem_data(pinfo, subtree, tvb, offset, bSize, bTag, &cur_global);
                    break;
                default: /* Only USBHID_ITEMTYPE_LONG, but keep compiler happy */
                    proto_tree_add_item(subtree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
                    offset += bSize;
                    break;
            }
        }

        if (bType == USBHID_ITEMTYPE_MAIN) {
            if (bTag == USBHID_MAINITEM_TAG_COLLECTION) {
                /* Begin collection, nest following elements under us */
                increment_dissection_depth(pinfo);
                offset = dissect_usb_hid_report_item(pinfo, subtree, tvb, offset, usb_conv_info, &cur_global);
                decrement_dissection_depth(pinfo);
                proto_item_set_len(subitem, offset-old_offset);
            } else if (bTag == USBHID_MAINITEM_TAG_ENDCOLLECTION) {
                /* End collection, break out to parent tree item */
                break;
            }
        }
    }
    return offset;
}

/* Dissector for HID "GET DESCRIPTOR" subtype. */
int
dissect_usb_hid_get_report_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_conv_info_t *usb_conv_info)
{
    proto_item *item;
    proto_tree *tree;
    int old_offset=offset;
    struct usb_hid_global_state initial_global;

    memset(&initial_global, 0, sizeof(struct usb_hid_global_state));

    item = proto_tree_add_protocol_format(parent_tree, proto_usb_hid, tvb, offset,
                                          -1, "HID Report");
    tree = proto_item_add_subtree(item, ett_usb_hid_report);
    offset = dissect_usb_hid_report_item(pinfo, tree, tvb, offset, usb_conv_info, &initial_global);

    /* only insert report descriptor the first time we parse it */
    if (!PINFO_FD_VISITED(pinfo) && usb_conv_info) {
        wmem_allocator_t *scope = wmem_file_scope();
        report_descriptor_t *data = wmem_new0(scope, report_descriptor_t);

        data->usb_info = *usb_conv_info;
        data->desc_length = offset - old_offset;
        data->desc_body = (uint8_t*) tvb_memdup(scope, tvb, old_offset, data->desc_length);

        if (parse_report_descriptor(data)) {
            insert_report_descriptor(pinfo, data);
        } else {
            wmem_free(scope, data->desc_body);
            wmem_free(scope, data);
        }
    }

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

/* Dissector for HID GET_REPORT request. See USBHID 1.11, Chapter 7.2.1 Get_Report Request */
static void
dissect_usb_hid_get_report(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item;
    proto_tree *subtree;

    if (!is_request)
        return;

    item = proto_tree_add_item(tree, hf_usb_hid_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_usb_hid_wValue);

    /* Report Type in the high byte, Report ID in the low byte */
    proto_tree_add_item(subtree, hf_usb_hid_report_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(subtree, hf_usb_hid_report_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_usb_hid_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_usb_hid_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    /*offset += 2;*/
}

/* Dissector for HID SET_REPORT request. See USBHID 1.11, Chapter 7.2.2 Set_Report Request */
static void
dissect_usb_hid_set_report(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item;
    proto_tree *subtree;

    if (!is_request)
        return;

    item = proto_tree_add_item(tree, hf_usb_hid_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_usb_hid_wValue);

    proto_tree_add_item(subtree, hf_usb_hid_report_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(subtree, hf_usb_hid_report_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_usb_hid_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_usb_hid_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    /*offset += 2;*/
}


/* Dissector for HID GET_IDLE request. See USBHID 1.11, Chapter 7.2.3 Get_Idle Request */
static void
dissect_usb_hid_get_idle(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item;
    proto_tree *subtree;

    if (!is_request)
        return;

    item = proto_tree_add_item(tree, hf_usb_hid_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_usb_hid_wValue);

    proto_tree_add_item(subtree, hf_usb_hid_report_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(subtree, hf_usb_hid_zero, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_usb_hid_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_usb_hid_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    /*offset += 2;*/
}

/* Dissector for HID SET_IDLE request. See USBHID 1.11, Chapter 7.2.4 Set_Idle Request */
static void
dissect_usb_hid_set_idle(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item;
    proto_tree *subtree;

    if (!is_request)
        return;

    item = proto_tree_add_item(tree, hf_usb_hid_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_usb_hid_wValue);

    /* Duration in the high byte, Report ID in the low byte */
    proto_tree_add_item(subtree, hf_usb_hid_report_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(subtree, hf_usb_hid_duration, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_usb_hid_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_usb_hid_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    /*offset += 2;*/
}

/* Dissector for HID GET_PROTOCOL request. See USBHID 1.11, Chapter 7.2.5 Get_Protocol Request */
static void
dissect_usb_hid_get_protocol(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_conv_info_t *usb_conv_info _U_)
{
    if (!is_request)
        return;

    proto_tree_add_item(tree, hf_usb_hid_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_usb_hid_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_usb_hid_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    /*offset += 2;*/
}

/* Dissector for HID SET_PROTOCOL request. See USBHID 1.11, Chapter 7.2.6 Set_Protocol Request */
static void
dissect_usb_hid_set_protocol(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_conv_info_t *usb_conv_info _U_)
{
    if (!is_request)
        return;

    proto_tree_add_item(tree, hf_usb_hid_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_usb_hid_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_usb_hid_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    /*offset += 2;*/
}


typedef void (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, bool is_request, usb_conv_info_t *usb_conv_info);

typedef struct _usb_setup_dissector_table_t {
    uint8_t request;
    usb_setup_dissector dissector;
} usb_setup_dissector_table_t;


/* USBHID 1.11, Chapter 7.2 Class-Specific Requests */
#define USB_HID_SETUP_GET_REPORT      0x01
#define USB_HID_SETUP_GET_IDLE        0x02
#define USB_HID_SETUP_GET_PROTOCOL    0x03
/* 0x04..0x08: Reserved */
#define USB_HID_SETUP_SET_REPORT      0x09
#define USB_HID_SETUP_SET_IDLE        0x0A
#define USB_HID_SETUP_SET_PROTOCOL    0x0B

static const usb_setup_dissector_table_t setup_dissectors[] = {
    { USB_HID_SETUP_GET_REPORT,   dissect_usb_hid_get_report },
    { USB_HID_SETUP_GET_IDLE,     dissect_usb_hid_get_idle },
    { USB_HID_SETUP_GET_PROTOCOL, dissect_usb_hid_get_protocol },
    { USB_HID_SETUP_SET_REPORT,   dissect_usb_hid_set_report },
    { USB_HID_SETUP_SET_IDLE,     dissect_usb_hid_set_idle },
    { USB_HID_SETUP_SET_PROTOCOL, dissect_usb_hid_set_protocol },
    { 0, NULL }
};

static const value_string setup_request_names_vals[] = {
    { USB_HID_SETUP_GET_REPORT,   "GET_REPORT" },
    { USB_HID_SETUP_GET_IDLE,     "GET_IDLE" },
    { USB_HID_SETUP_GET_PROTOCOL, "GET_PROTOCOL" },
    { USB_HID_SETUP_SET_REPORT,   "SET_REPORT" },
    { USB_HID_SETUP_SET_IDLE,     "SET_IDLE" },
    { USB_HID_SETUP_SET_PROTOCOL, "SET_PROTOCOL" },
    { 0, NULL }
};

static const value_string usb_hid_report_type_vals[] = {
    { 1, "Input" },
    { 2, "Output" },
    { 3, "Feature" },
    { 0, NULL }
};

static int
dissect_usb_hid_boot_keyboard_input_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int       offset = 0;
    bool      shortcut_helper = false;
    unsigned  modifier;
    unsigned  keycode;

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_right_gui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_right_alt, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_right_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_right_ctrl, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_left_gui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_left_alt, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_left_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_left_ctrl, tvb, offset, 1, ENC_BIG_ENDIAN);
    modifier = tvb_get_uint8(tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, " - ");
    if (modifier & 0x80) {
        col_append_str(pinfo->cinfo, COL_INFO, "RIGHT GUI");
        shortcut_helper = true;
    }
    if (modifier & 0x40) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "RIGHT ALT");
        shortcut_helper = true;
    }
    if (modifier & 0x20) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "RIGHT SHIFT");
        shortcut_helper = true;
    }
    if (modifier & 0x10) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "RIGHT CTRL");
        shortcut_helper = true;
    }
    if (modifier & 0x08) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "LEFT GUI");
        shortcut_helper = true;
    }
    if (modifier & 0x04) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "LEFT ALT");
        shortcut_helper = true;
    }
    if (modifier & 0x02) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "LEFT SHIFT");
        shortcut_helper = true;
    }
    if (modifier & 0x01) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "LEFT CTRL");
        shortcut_helper = true;
    }
    offset += 1;

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_uint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = true;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_uint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = true;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_uint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = true;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_uint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = true;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_uint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = true;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_uint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = true;
    }

    if (shortcut_helper == false) {
        col_append_str(pinfo->cinfo, COL_INFO, "<action key up>");
    }

    return offset;
}

static int
dissect_usb_hid_boot_keyboard_output_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int       offset = 0;
    bool      shortcut_helper = false;
    unsigned  leds;

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_constants, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_kana, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_compose, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_scroll_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_caps_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_num_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
    leds = tvb_get_uint8(tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, " - LEDs: ");
    if (leds & 0x01) {
        col_append_str(pinfo->cinfo, COL_INFO, "NumLock");
        shortcut_helper = true;
    }
    if (leds & 0x02) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "CapsLock");
        shortcut_helper = true;
    }
    if (leds & 0x04) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "ScrollLock");
        shortcut_helper = true;
    }
    if (leds & 0x08) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Compose");
        shortcut_helper = true;
    }
    if (leds & 0x10) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Kana");
        shortcut_helper = true;
    }
    if (leds & 0x20) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Constant1");
        shortcut_helper = true;
    }
    if (leds & 0x40) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Constant2");
        shortcut_helper = true;
    }
    if (leds & 0x80) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Constant3");
        /*shortcut_helper = true;*/
    }
    if (!leds) {
        col_append_str(pinfo->cinfo, COL_INFO, "none");
    }

    offset += 1;

    return offset;
}

static int
dissect_usb_hid_boot_mouse_input_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int       offset = 0;
    bool      shortcut_helper = false;
    unsigned  buttons;

    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_8, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_middle, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_right, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_left, tvb, offset, 1, ENC_BIG_ENDIAN);
    buttons = tvb_get_uint8(tvb, offset);
    offset += 1;

    if (buttons) col_append_str(pinfo->cinfo, COL_INFO, " - ");
    if (buttons & 0x01) {
        col_append_str(pinfo->cinfo, COL_INFO, "Button LEFT");
        shortcut_helper = true;
    }
    if (buttons & 0x02) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button RIGHT");
        shortcut_helper = true;
    }
    if (buttons & 0x04) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button MIDDLE");
    }
    if (buttons & 0x08) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 4");
        shortcut_helper = true;
    }
    if (buttons & 0x10) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 5");
        shortcut_helper = true;
    }
    if (buttons & 0x20) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 6");
        shortcut_helper = true;
    }
    if (buttons & 0x40) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 7");
        shortcut_helper = true;
    }
    if (buttons & 0x80) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 8");
        /* Not necessary, this is the last case where it is used
         * shortcut_helper = true;
         */
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_x_displacement, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_y_displacement, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    /* not really in HID Specification */
    if (tvb_reported_length_remaining(tvb, offset)) {
        proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_horizontal_scroll_wheel, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    /* not really in HID Specification */
    if (tvb_reported_length_remaining(tvb, offset)) {
        proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_vertical_scroll_wheel, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (tvb_reported_length_remaining(tvb, offset)) {
        proto_tree_add_item(tree, hf_usbhid_data, tvb, offset, -1, ENC_NA);
        offset += tvb_captured_length_remaining(tvb, offset);
    }

    return offset;
}


/* dissect a "standard" control message that's sent to an interface */
static int
dissect_usb_hid_control_std_intf(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, usb_conv_info_t *usb_conv_info)
{
    int               offset = 0;
    usb_trans_info_t *usb_trans_info;
    uint8_t           req;

    usb_trans_info = usb_conv_info->usb_trans_info;

    /* XXX - can we do some plausibility checks here? */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBHID");

    /* we can't use usb_conv_info->is_request since usb_conv_info
       was replaced with the interface conversation */
    if (usb_trans_info->request_in == pinfo->num) {
        /* the tvb that we see here is the setup packet
           without the request type byte */

        req = tvb_get_uint8(tvb, offset);
        if (req != USB_SETUP_GET_DESCRIPTOR)
            return offset;
        col_clear(pinfo->cinfo, COL_INFO);
        col_append_str(pinfo->cinfo, COL_INFO, "GET DESCRIPTOR Request");
        offset += 1;

        proto_tree_add_item(tree, hf_usb_hid_bDescriptorIndex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        usb_trans_info->u.get_descriptor.usb_index = tvb_get_uint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(tree, hf_usb_hid_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        usb_trans_info->u.get_descriptor.type = tvb_get_uint8(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
                val_to_str_ext(usb_trans_info->u.get_descriptor.type,
                    &hid_descriptor_type_vals_ext, "Unknown type %u"));
        offset += 1;

        proto_tree_add_item(tree, hf_usb_hid_wInterfaceNumber, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_usb_hid_wDescriptorLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }
    else {
        col_clear(pinfo->cinfo, COL_INFO);
        col_append_str(pinfo->cinfo, COL_INFO, "GET DESCRIPTOR Response");
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
                val_to_str_ext(usb_trans_info->u.get_descriptor.type,
                    &hid_descriptor_type_vals_ext, "Unknown type %u"));
        if (usb_trans_info->u.get_descriptor.type == USB_DT_HID_REPORT)
            offset = dissect_usb_hid_get_report_descriptor(pinfo, tree, tvb, offset, usb_conv_info);
    }

    return offset;
}

/* dissect a class-specific control message that's sent to an interface */
static int
dissect_usb_hid_control_class_intf(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, usb_conv_info_t *usb_conv_info)
{
    usb_trans_info_t *usb_trans_info;
    bool is_request;
    int offset = 0;
    usb_setup_dissector dissector = NULL;
    const usb_setup_dissector_table_t *tmp;

    usb_trans_info = usb_conv_info->usb_trans_info;

    is_request = (pinfo->srcport==NO_ENDPOINT);

    /* Check valid values for bmRequestType. See Chapter 7.2 in USBHID 1.11 */
    for (tmp = setup_dissectors; tmp->dissector; tmp++) {
        if (tmp->request == usb_trans_info->setup.request) {
            dissector = tmp->dissector;
            break;
        }
    }
    /* No, we could not find any class specific dissector for this request
     * return 0 and let USB try any of the standard requests.
     */
    if (!dissector)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBHID");

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                 val_to_str(usb_trans_info->setup.request, setup_request_names_vals, "Unknown type %x"),
                 is_request ? "Request" : "Response");

    if (is_request) {
        proto_tree_add_item(tree, hf_usb_hid_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    dissector(pinfo, tree, tvb, offset, is_request, usb_conv_info);
    return tvb_captured_length(tvb);
}

/* unpack a HID logical report field */
static int hid_unpack_logical(tvbuff_t *tvb, int bit_offset, uint32_t size, int32_t min, int32_t *val)
{
    if (size > 32)
        return -1;

    *val = tvb_get_bits32(tvb, bit_offset, size, ENC_LITTLE_ENDIAN);

    if (min < 0)
        *val = ws_sign_ext32(*val, size);

    return 0;
}

static int
dissect_usb_hid_int_dynamic_value_variable(tvbuff_t *tvb, proto_tree *tree, hid_field_t *field,
        int bit_offset, int hf)
{
    int32_t val = 0;

    if (hid_unpack_logical(tvb, bit_offset, field->report_size, field->logical_min, &val))
        return -1;

    proto_tree_add_int_bits_format_value(tree, hf, tvb, bit_offset, field->report_size, val, ENC_LITTLE_ENDIAN, "%d", val);
    return 0;
}

/* dissect the Generic Desktop Controls (0x0001) usage page */
static int
dissect_usb_hid_generic_desktop_controls_page(tvbuff_t *tvb, packet_info _U_ *pinfo,
        proto_tree *tree, hid_field_t *field, unsigned usage, int bit_offset)
{
    int ret = 0;

    DISSECTOR_ASSERT(USAGE_PAGE(usage) == GENERIC_DESKTOP_CONTROLS_PAGE);
    usage = USAGE_ID(usage);
    switch (usage)
    {
        case USBHID_GENERIC_DESKTOP_CONTROLS_X:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_x);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_Y:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_y);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_Z:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_z);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_RX:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_rx);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_RY:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_ry);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_RZ:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_rz);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_SLIDER:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_slider);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_VX:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_vx);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_VY:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_vy);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_VZ:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_vz);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_VBRX:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_vbrx);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_VBRY:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_vbry);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_VBRZ:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_vbrz);
            break;

        case USBHID_GENERIC_DESKTOP_CONTROLS_VNO:
            ret = dissect_usb_hid_int_dynamic_value_variable(tvb, tree, field, bit_offset, hf_usbhid_axis_vno);
            break;

        default:
            ret = -1;
            break;
    }

    return ret;
}

/* dissect the Keyboard/Keypad (0x0007) usage page */
static int
dissect_usb_hid_keyboard_page(tvbuff_t *tvb, packet_info _U_ *pinfo,
        proto_tree *tree, hid_field_t *field, uint32_t usage, int bit_offset)
{
    int32_t val = 0;

    /* the data is a boolean state for the usage (eg. KEY_SHIFT = 1, KEY_CONTROL = 0) */
    if (hid_unpack_logical(tvb, bit_offset, field->report_size, field->logical_min, &val))
        return -1;

    DISSECTOR_ASSERT(USAGE_PAGE(usage) == KEYBOARD_KEYPAD_PAGE);
    usage = USAGE_ID(usage);

    proto_tree_add_boolean_bits_format_value(tree, hf_usbhid_key, tvb, bit_offset, field->report_size, val, ENC_LITTLE_ENDIAN,
        "%s (0x%02x): %s", val_to_str_ext_const(usage, &keycode_vals_ext, "Unknown"), usage, val ? "DOWN" : "UP");
    return 0;
}

/* dissect the Button (0x0009) usage page */
static int
dissect_usb_hid_button_page(tvbuff_t *tvb, packet_info _U_ *pinfo,
        proto_tree *tree, hid_field_t *field, uint32_t usage, int bit_offset)
{
    int32_t val = 0;
    proto_item *ti;

    DISSECTOR_ASSERT(USAGE_PAGE(usage) == BUTTON_PAGE);
    usage = USAGE_ID(usage);

    if (hid_unpack_logical(tvb, bit_offset, field->report_size, field->logical_min, &val))
        return -1;

    ti = proto_tree_add_boolean_bits_format_value(tree, hf_usbhid_button, tvb, bit_offset, field->report_size, val, ENC_LITTLE_ENDIAN, "%u", usage);

    if (usage == 0)
        proto_item_append_text(ti, " (No button pressed)");
    else if (usage == 1)
        proto_item_append_text(ti, " (primary/trigger)");
    else if (usage == 2)
        proto_item_append_text(ti, " (secondary)");
    else if (usage == 3)
        proto_item_append_text(ti, " (tertiary)");

    proto_item_append_text(ti, ": %s", val ? "DOWN" : "UP");
    return 0;
}

static void
dissect_hid_variable(tvbuff_t* tvb, packet_info _U_* pinfo, proto_tree* tree, hid_field_t* field,
                     uint32_t usage, int bit_offset)
{
    int ret = 0;

    /* vendor data (0xff00 - 0xffff) */
    if ((USAGE_PAGE(usage) & 0xff00) == 0xff00) {
        proto_tree_add_bits_item(tree, hf_usbhid_vendor_data, tvb, bit_offset, field->report_size, ENC_LITTLE_ENDIAN);
        return;
    }

    switch (USAGE_PAGE(usage))
    {
    case GENERIC_DESKTOP_CONTROLS_PAGE:
        ret = dissect_usb_hid_generic_desktop_controls_page(tvb, pinfo, tree, field, usage, bit_offset);
        break;

    case KEYBOARD_KEYPAD_PAGE:
        ret = dissect_usb_hid_keyboard_page(tvb, pinfo, tree, field, usage, bit_offset);
        break;

    case BUTTON_PAGE:
        ret = dissect_usb_hid_button_page(tvb, pinfo, tree, field, usage, bit_offset);
        break;

    default:
        ret = -1;
        break;
    }

    if (ret) {
        uint32_t val = 0;
        proto_item *ti =
            proto_tree_add_uint_bits_format_value(tree, hf_usb_hid_localitem_usage, tvb, bit_offset, field->report_size,
                                                  usage, ENC_LITTLE_ENDIAN, "%s", get_usage_page_item_string(pinfo->pool, USAGE_PAGE(usage), USAGE_ID(usage)));
        if (0 == hid_unpack_logical(tvb, bit_offset, field->report_size, field->logical_min, &val))
            proto_item_append_text(ti, ": %d", val);
    }
}

static bool hid_get_usage_from_array(hid_field_t *field, int32_t idx, uint32_t *out)
{
    if ((idx >= field->logical_min) && (idx <= field->logical_max)) {
        idx -= field->logical_min;
        if ((uint32_t)idx < wmem_array_get_count(field->usages)) {
            *out = (*((uint32_t*) wmem_array_index(field->usages, idx)));
            return true;
        }
    }
    return false;
}

static int
dissect_hid_field(tvbuff_t *tvb, packet_info _U_ *pinfo, proto_tree *tree, hid_field_t *field, int bit_offset)
{
    int start_offset = bit_offset;

    if ((field->properties & HID_MAIN_TYPE) == HID_MAIN_ARRAY) {
        proto_item *array_ti;
        proto_tree *array_tree;

        array_ti = proto_tree_add_bits_item(tree, hf_usbhid_array, tvb, bit_offset,
            field->report_size * field->report_count, ENC_LITTLE_ENDIAN);
        array_tree = proto_item_add_subtree(array_ti, ett_usb_hid_array);

        for(unsigned int j = 0; j < field->report_count; j++) {
            uint32_t val = 0;
            bool in_range;
            if (hid_unpack_logical(tvb, bit_offset, field->report_size, field->logical_min, &val)) {
                in_range = false;
            } else {
                in_range = hid_get_usage_from_array(field, val, &val);
            }
            if (in_range) {
                proto_tree_add_boolean_bits_format_value(array_tree, hf_usbhid_array_usage, tvb, bit_offset, field->report_size,
                    val, ENC_LITTLE_ENDIAN, "%s (0x%04x, 0x%04x)", get_usage_page_item_string(pinfo->pool, USAGE_PAGE(val), USAGE_ID(val)),
                    USAGE_PAGE(val), USAGE_ID(val));
            } else {
                proto_tree_add_boolean_bits_format_value(array_tree, hf_usbhid_array_usage, tvb, bit_offset, field->report_size,
                    val, ENC_LITTLE_ENDIAN, "No controls asserted");
            }
            bit_offset += field->report_size;
        }
    } else {
        unsigned int i;
        unsigned int count = wmem_array_get_count(field->usages);
        if (count > field->report_count) {
            count = field->report_count;
        }
        for(i = 0; i < count; i++) {
            uint32_t usage = *((uint32_t*) wmem_array_index(field->usages, i));
            dissect_hid_variable(tvb, pinfo, tree, field, usage, bit_offset);
            bit_offset += field->report_size;
        }
        if (field->report_count > count) {
            int remaining_bits = (field->report_count - count) * field->report_size;
            proto_tree_add_bits_item(tree, hf_usbhid_padding, tvb, bit_offset, remaining_bits, ENC_LITTLE_ENDIAN);
            bit_offset += remaining_bits;
        }
    }

    return bit_offset - start_offset;
}

/* Dissect USB HID data/reports */
static int
dissect_usb_hid_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    unsigned offset = 0, hid_bit_offset;
    proto_item *hid_ti;
    proto_tree *hid_tree;
    wmem_array_t *fields;
    usb_conv_info_t *usb_data = (usb_conv_info_t*) data;
    report_descriptor_t *rdesc = get_report_descriptor(pinfo, usb_data);
    unsigned remaining = tvb_reported_length_remaining(tvb, offset);

    if (remaining) {
        hid_ti = proto_tree_add_item(tree, hf_usbhid_data, tvb, offset, -1, ENC_NA);
        hid_tree = proto_item_add_subtree(hid_ti, ett_usb_hid_data);
        hid_bit_offset = offset * 8;
        offset += remaining;
        uint8_t report_id = tvb_get_bits8(tvb, hid_bit_offset, 8);

        if (rdesc) {
            if (rdesc->uses_report_id) {
                proto_tree_add_item(hid_tree, hf_usbhid_report_id, tvb, hid_bit_offset / 8, 1, ENC_NA);
                hid_bit_offset += 8;
            }

            if (usb_data->direction == P2P_DIR_RECV)
                fields = rdesc->fields_in;
            else
                fields = rdesc->fields_out;

            for(unsigned int i = 0; i < wmem_array_get_count(fields); i++) {
                hid_field_t *field = (hid_field_t*) wmem_array_index(fields, i);
                unsigned int data_size = field->report_size * field->report_count;

                /* skip items with invalid report IDs */
                if (rdesc->uses_report_id && field->report_id != report_id)
                    continue;

                /* if the item has no usages, it is padding - HID spec 6.2.2.9 */
                if (wmem_array_get_count(field->usages) == 0) {
                    proto_tree_add_bits_item(hid_tree, hf_usbhid_padding, tvb, hid_bit_offset, data_size, ENC_LITTLE_ENDIAN);
                    hid_bit_offset += data_size;
                    continue;
                }

                hid_bit_offset += dissect_hid_field(tvb, pinfo, hid_tree, field, hid_bit_offset);
            }
        }
    }

    return offset;
}

/* Dissector for HID class-specific control request as defined in
 * USBHID 1.11, Chapter 7.2.
 * returns the number of bytes consumed */
static int
dissect_usb_hid_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    usb_conv_info_t *usb_conv_info;
    usb_trans_info_t *usb_trans_info;
    uint8_t type, recip;

    usb_conv_info = (usb_conv_info_t *)data;
    if (!usb_conv_info)
        return 0;
    usb_trans_info = usb_conv_info->usb_trans_info;
    if (!usb_trans_info)
        return 0;

    type = USB_TYPE(usb_trans_info->setup.requesttype);
    recip = USB_RECIPIENT(usb_trans_info->setup.requesttype);

    if (recip == RQT_SETUP_RECIPIENT_INTERFACE) {
        if (type == RQT_SETUP_TYPE_STANDARD)
            return dissect_usb_hid_control_std_intf(tvb, pinfo, tree, usb_conv_info);
        else if (type == RQT_SETUP_TYPE_CLASS)
            return dissect_usb_hid_control_class_intf(tvb, pinfo, tree, usb_conv_info);
    }

    return dissect_usb_hid_data(tvb, pinfo, tree, data);
}

/* dissect a descriptor that is specific to the HID class */
static int
dissect_usb_hid_class_descriptors(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, void *data _U_)
{
    uint8_t     type;
    int         offset = 0;
    proto_item *ti;
    proto_tree *desc_tree;
    uint8_t     num_desc;
    unsigned    i;

    type = tvb_get_uint8(tvb, 1);

    /* for now, we only handle the HID descriptor here */
    if (type != USB_DT_HID)
        return 0;

    desc_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_usb_hid_descriptor, &ti, "HID DESCRIPTOR");

    dissect_usb_descriptor_header(desc_tree, tvb, offset, &hid_descriptor_type_vals_ext);
    offset += 2;
    proto_tree_add_item(desc_tree, hf_usb_hid_bcdHID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(desc_tree, hf_usb_hid_bCountryCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    num_desc = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(desc_tree, hf_usb_hid_bNumDescriptors, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    for (i=0;i<num_desc;i++) {
        proto_tree_add_item(desc_tree, hf_usb_hid_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(desc_tree, hf_usb_hid_wDescriptorLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    proto_item_set_len(ti, offset);
    return offset;
}


void
proto_register_usb_hid(void)
{
    static hf_register_info hf[] = {
        { &hf_usb_hid_item_bSize,
            { "bSize", "usbhid.item.bSize", FT_UINT8, BASE_DEC,
                VALS(usb_hid_item_bSize_vals), USBHID_SIZE_MASK, NULL, HFILL }},

        { &hf_usb_hid_item_bType,
            { "bType", "usbhid.item.bType", FT_UINT8, BASE_DEC,
                VALS(usb_hid_item_bType_vals), USBHID_TYPE_MASK, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bTag,
            { "bTag", "usbhid.item.bTag", FT_UINT8, BASE_HEX,
                VALS(usb_hid_mainitem_bTag_vals), USBHID_TAG_MASK, NULL, HFILL }},

        { &hf_usb_hid_globalitem_bTag,
            { "bTag", "usbhid.item.bTag", FT_UINT8, BASE_HEX,
                VALS(usb_hid_globalitem_bTag_vals), USBHID_TAG_MASK, NULL, HFILL }},

        { &hf_usb_hid_localitem_bTag,
            { "bTag", "usbhid.item.bTag", FT_UINT8, BASE_HEX,
                VALS(usb_hid_localitem_bTag_vals), USBHID_TAG_MASK, NULL, HFILL }},

        { &hf_usb_hid_longitem_bTag,
            { "bTag", "usbhid.item.bTag", FT_UINT8, BASE_HEX,
                VALS(usb_hid_longitem_bTag_vals), USBHID_TAG_MASK, NULL, HFILL }},

        { &hf_usb_hid_item_bDataSize,
            { "bDataSize", "usbhid.item.bDataSize", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_item_bLongItemTag,
            { "bTag", "usbhid.item.bLongItemTag", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        /* Main-report item data */

        { &hf_usb_hid_mainitem_bit0,
            { "Data/constant", "usbhid.item.main.readonly", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit0), 1<<0, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit1,
            { "Data type", "usbhid.item.main.variable", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit1), 1<<1, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit2,
            { "Coordinates", "usbhid.item.main.relative", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit2), 1<<2, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit3,
            { "Min/max wraparound", "usbhid.item.main.wrap", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit3), 1<<3, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit4,
            { "Physical relationship to data", "usbhid.item.main.nonlinear", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit4), 1<<4, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit5,
            { "Preferred state", "usbhid.item.main.no_preferred_state", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit5), 1<<5, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit6,
            { "Has null position", "usbhid.item.main.nullstate", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit6), 1<<6, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit7,
            { "(Non)-volatile", "usbhid.item.main.volatile", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit7), 1<<7, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit7_input,
            { "[Reserved]", "usbhid.item.main.reserved", FT_BOOLEAN, 9,
                NULL, 1<<7, NULL, HFILL }},

        { &hf_usb_hid_mainitem_bit8,
            { "Bits or bytes", "usbhid.item.main.buffered_bytes", FT_BOOLEAN, 9,
                TFS(&tfs_mainitem_bit8), 1<<8, NULL, HFILL }},

        { &hf_usb_hid_mainitem_colltype,
            { "Collection type", "usbhid.item.main.colltype", FT_UINT8, BASE_RANGE_STRING|BASE_HEX,
                RVALS(usb_hid_mainitem_colltype_vals), 0, NULL, HFILL }},

        /* Global-report item data */

        { &hf_usb_hid_globalitem_usage,
            { "Usage page", "usbhid.item.global.usage", FT_UINT8, BASE_RANGE_STRING|BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_log_min,
            { "Logical minimum", "usbhid.item.global.log_min", FT_INT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_log_max,
            { "Logical maximum", "usbhid.item.global.log_max", FT_INT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_phy_min,
            { "Physical minimum", "usbhid.item.global.phy_min", FT_INT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_phy_max,
            { "Physical maximum", "usbhid.item.global.phy_max", FT_INT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_unit_exp,
            { "Unit exponent", "usbhid.item.global.unit_exp", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_unit_sys,
            { "System", "usbhid.item.global.unit.system", FT_UINT32, BASE_HEX,
                VALS(usb_hid_globalitem_unit_exp_vals), 0x0000000F, NULL, HFILL }},

        { &hf_usb_hid_globalitem_unit_len,
            { "Length", "usbhid.item.global.unit.length", FT_UINT32, BASE_HEX,
                VALS(usb_hid_globalitem_unit_exp_vals), 0x000000F0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_unit_mass,
            { "Mass", "usbhid.item.global.unit.mass", FT_UINT32, BASE_HEX,
                VALS(usb_hid_globalitem_unit_exp_vals), 0x00000F00, NULL, HFILL }},

        { &hf_usb_hid_globalitem_unit_time,
            { "Time", "usbhid.item.global.unit.time", FT_UINT32, BASE_HEX,
                VALS(usb_hid_globalitem_unit_exp_vals), 0x0000F000, NULL, HFILL }},

        { &hf_usb_hid_globalitem_unit_temp,
            { "Temperature", "usbhid.item.global.unit.temperature", FT_UINT32, BASE_HEX,
                VALS(usb_hid_globalitem_unit_exp_vals), 0x000F0000, NULL, HFILL }},

        { &hf_usb_hid_globalitem_unit_current,
            { "Current", "usbhid.item.global.unit.current", FT_UINT32, BASE_HEX,
                VALS(usb_hid_globalitem_unit_exp_vals), 0x00F00000, NULL, HFILL }},

        { &hf_usb_hid_globalitem_unit_brightness,
            { "Luminous intensity", "usbhid.item.global.unit.brightness", FT_UINT32, BASE_HEX,
                VALS(usb_hid_globalitem_unit_exp_vals), 0x0F000000, NULL, HFILL }},

        { &hf_usb_hid_globalitem_report_size,
            { "Report size", "usbhid.item.global.report_size", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_report_id,
            { "Report ID", "usbhid.item.global.report_id", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_report_count,
            { "Report count", "usbhid.item.global.report_count", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_push,
            { "Push", "usbhid.item.global.push", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_pop,
            { "Pop", "usbhid.item.global.pop", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        /* Local-report item data */

        { &hf_usb_hid_localitem_usage,
            { "Usage", "usbhid.item.local.usage", FT_UINT8, BASE_RANGE_STRING|BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_usage_min,
            { "Usage minimum", "usbhid.item.local.usage_min", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_usage_max,
            { "Usage maximum", "usbhid.item.local.usage_max", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_desig_index,
            { "Designator index", "usbhid.item.local.desig_index", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_desig_min,
            { "Designator minimum", "usbhid.item.local.desig_min", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_desig_max,
            { "Designator maximum", "usbhid.item.local.desig_max", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_string_index,
            { "String index", "usbhid.item.local.string_index", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_string_min,
            { "String minimum", "usbhid.item.local.string_min", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_string_max,
            { "String maximum", "usbhid.item.local.string_max", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_delimiter,
            { "Delimiter", "usbhid.item.local.delimiter", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},


        { &hf_usb_hid_item_unk_data,
            { "Item data", "usbhid.item.data", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL }},

        /* USB HID specific requests */
        { &hf_usb_hid_request,
            { "bRequest", "usbhid.setup.bRequest", FT_UINT8, BASE_HEX,
                VALS(setup_request_names_vals), 0x0, NULL, HFILL }},

        { &hf_usb_hid_value,
            { "wValue", "usbhid.setup.wValue", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_index,
            { "wIndex", "usbhid.setup.wIndex", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_length,
            { "wLength", "usbhid.setup.wLength", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_report_type,
            { "ReportType", "usbhid.setup.ReportType", FT_UINT8, BASE_DEC,
                VALS(usb_hid_report_type_vals), 0x0, NULL, HFILL }},

        { &hf_usb_hid_report_id,
            { "ReportID", "usbhid.setup.ReportID", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_duration,
            { "Duration", "usbhid.setup.Duration", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_zero,
            { "(zero)", "usbhid.setup.zero", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        /* components of the HID descriptor */
        { &hf_usb_hid_bcdHID,
            { "bcdHID", "usbhid.descriptor.hid.bcdHID", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_bCountryCode,
            { "bCountryCode", "usbhid.descriptor.hid.bCountryCode", FT_UINT8, BASE_HEX,
                VALS(hid_country_code_vals), 0x0, NULL, HFILL }},

        { &hf_usb_hid_bNumDescriptors,
            { "bNumDescriptors", "usbhid.descriptor.hid.bNumDescriptors", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_bDescriptorIndex,
            { "bDescriptorIndex", "usbhid.descriptor.hid.bDescriptorIndex", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_bDescriptorType,
            { "bDescriptorType", "usbhid.descriptor.hid.bDescriptorType", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &hid_descriptor_type_vals_ext, 0x00, NULL, HFILL }},

        { &hf_usb_hid_wInterfaceNumber,
            { "wInterfaceNumber", "usbhid.descriptor.hid.wInterfaceNumber", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_wDescriptorLength,
            { "wDescriptorLength", "usbhid.descriptor.hid.wDescriptorLength", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_reserved,
            { "Reserved", "usbhid.boot_report.keyboard.reserved", FT_UINT8, BASE_HEX,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_keycode_1,
            { "Keycode 1", "usbhid.boot_report.keyboard.keycode_1", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &keycode_vals_ext, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_keycode_2,
            { "Keycode 2", "usbhid.boot_report.keyboard.keycode_2", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &keycode_vals_ext, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_keycode_3,
            { "Keycode 3", "usbhid.boot_report.keyboard.keycode_3", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &keycode_vals_ext, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_keycode_4,
            { "Keycode 4", "usbhid.boot_report.keyboard.keycode_4", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &keycode_vals_ext, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_keycode_5,
            { "Keycode 5", "usbhid.boot_report.keyboard.keycode_5", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &keycode_vals_ext, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_keycode_6,
            { "Keycode 6", "usbhid.boot_report.keyboard.keycode_6", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                &keycode_vals_ext, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_modifier_right_gui,
            { "Modifier: RIGHT GUI", "usbhid.boot_report.keyboard.modifier.right_gui", FT_BOOLEAN, 8,
                NULL, 0x80, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_modifier_right_alt,
            { "Modifier: RIGHT ALT", "usbhid.boot_report.keyboard.modifier.right_alt", FT_BOOLEAN, 8,
                NULL, 0x40, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_modifier_right_shift,
            { "Modifier: RIGHT SHIFT", "usbhid.boot_report.keyboard.modifier.right_shift", FT_BOOLEAN, 8,
                NULL, 0x20, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_modifier_right_ctrl,
            { "Modifier: RIGHT CTRL", "usbhid.boot_report.keyboard.modifier.right_ctrl", FT_BOOLEAN, 8,
                NULL, 0x10,NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_modifier_left_gui,
            { "Modifier: LEFT GUI", "usbhid.boot_report.keyboard.modifier.left_gui", FT_BOOLEAN, 8,
                NULL, 0x08, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_modifier_left_alt,
            { "Modifier: LEFT ALT", "usbhid.boot_report.keyboard.modifier.left_alt", FT_BOOLEAN, 8,
                NULL, 0x04, NULL, HFILL }
        },

        { &hf_usbhid_boot_report_keyboard_modifier_left_shift,
            { "Modifier: LEFT SHIFT", "usbhid.boot_report.keyboard.modifier.left_shift", FT_BOOLEAN, 8,
                NULL, 0x02, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_modifier_left_ctrl,
            { "Modifier: LEFT CTRL", "usbhid.boot_report.keyboard.modifier.left_ctrl", FT_BOOLEAN, 8,
                NULL, 0x01, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_leds_constants,
            { "Constants", "usbhid.boot_report.keyboard.leds.constants", FT_UINT8, BASE_HEX,
                NULL, 0xE0, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_leds_kana,
            { "KANA", "usbhid.boot_report.keyboard.leds.kana", FT_BOOLEAN, 8,
                NULL, 0x10, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_leds_compose,
            { "COMPOSE", "usbhid.boot_report.keyboard.leds.compose", FT_BOOLEAN, 8,
                NULL, 0x08, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_leds_scroll_lock,
            { "SCROLL LOCK", "usbhid.boot_report.keyboard.leds.scroll_lock", FT_BOOLEAN, 8,
                NULL, 0x04, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_leds_caps_lock,
            { "CAPS LOCK", "usbhid.boot_report.keyboard.leds.caps_lock", FT_BOOLEAN, 8,
                NULL, 0x02,NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_leds_num_lock,
            { "NUM LOCK",  "usbhid.boot_report.keyboard.leds.num_lock", FT_BOOLEAN, 8,
                NULL, 0x01, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_button_8,
            { "Button 8",  "usbhid.boot_report.mouse.button.8", FT_BOOLEAN, 8,
                NULL, 0x80, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_button_7,
            { "Button 7",  "usbhid.boot_report.mouse.button.7", FT_BOOLEAN, 8,
                NULL, 0x40, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_button_6,
            { "Button 6",  "usbhid.boot_report.mouse.button.6", FT_BOOLEAN, 8,
                NULL, 0x20, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_button_5,
            { "Button 5",  "usbhid.boot_report.mouse.button.5", FT_BOOLEAN, 8,
                NULL, 0x10, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_button_4,
            { "Button 4",  "usbhid.boot_report.mouse.button.4", FT_BOOLEAN, 8,
                NULL, 0x08, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_button_middle,
            { "Button Middle", "usbhid.boot_report.mouse.button.middle", FT_BOOLEAN, 8,
                NULL, 0x04, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_button_right,
            { "Button Right",  "usbhid.boot_report.mouse.button.right", FT_BOOLEAN, 8,
                NULL, 0x02, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_button_left,
            { "Button Left",   "usbhid.boot_report.mouse.button.left", FT_BOOLEAN, 8,
                NULL, 0x01, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_x_displacement,
            { "X Displacement", "usbhid.boot_report.mouse.x_displacement", FT_INT8, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_y_displacement,
            { "Y Displacement", "usbhid.boot_report.mouse.y_displacement", FT_INT8, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_horizontal_scroll_wheel,
            { "Horizontal Scroll Wheel", "usbhid.boot_report.mouse.scroll_wheel.horizontal", FT_INT8, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_boot_report_mouse_vertical_scroll_wheel,
            { "Vertical Scroll Wheel", "usbhid.boot_report.mouse.scroll_wheel.vertical", FT_INT8, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_data,
            { "HID Data", "usbhid.data", FT_BYTES, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_unknown_data,
            { "Unknown", "usbhid.data.unknown", FT_BYTES, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_vendor_data,
            { "Vendor Data", "usbhid.data.vendor", FT_BYTES, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_report_id,
            { "Report ID", "usbhid.data.report_id", FT_UINT8, BASE_HEX,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_padding,
            { "Padding", "usbhid.data.padding", FT_BYTES, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_x,
            { "X Axis", "usbhid.data.axis.x", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_y,
            { "Y Axis", "usbhid.data.axis.y", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_z,
            { "Z Axis", "usbhid.data.axis.z", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_rx,
            { "Rx Axis", "usbhid.data.axis.rx", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_ry,
            { "Ry Axis", "usbhid.data.axis.ry", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_rz,
            { "Rz Axis", "usbhid.data.axis.rz", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_slider,
            { "Slider Axis", "usbhid.data.axis.slider", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_vx,
            { "Vx Axis", "usbhid.data.axis.vx", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_vy,
            { "Vy Axis", "usbhid.data.axis.vy", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_vz,
            { "Vz Axis", "usbhid.data.axis.vz", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_vbrx,
            { "Vbrx Axis", "usbhid.data.axis.vbrx", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_vbry,
            { "Vbry Axis", "usbhid.data.axis.vbry", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_vbrz,
            { "Vbrz Axis", "usbhid.data.axis.vbrz", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_axis_vno,
            { "Vno Axis", "usbhid.data.axis.vno", FT_INT32, BASE_DEC,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_button,
            { "Button", "usbhid.data.button", FT_BOOLEAN, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_key,
            { "Key", "usbhid.data.key.variable", FT_BOOLEAN, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_array,
            { "Array", "usbhid.data.array", FT_BYTES, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},

        { &hf_usbhid_array_usage,
            { "Usage", "usbhid.data.array.usage", FT_BOOLEAN, BASE_NONE,
            NULL, 0x00, NULL, HFILL }},
    };

    static int *usb_hid_subtrees[] = {
        &ett_usb_hid_report,
        &ett_usb_hid_item_header,
        &ett_usb_hid_wValue,
        &ett_usb_hid_descriptor,
        &ett_usb_hid_data,
        &ett_usb_hid_unknown_data,
        &ett_usb_hid_array
    };

    report_descriptors = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_usb_hid = proto_register_protocol("USB HID", "USBHID", "usbhid");
    proto_register_field_array(proto_usb_hid, hf, array_length(hf));
    proto_register_subtree_array(usb_hid_subtrees, array_length(usb_hid_subtrees));

    /*usb_hid_boot_keyboard_input_report_handle  =*/ register_dissector("usbhid.boot_report.keyboard.input",  dissect_usb_hid_boot_keyboard_input_report,  proto_usb_hid);
    /*usb_hid_boot_keyboard_output_report_handle =*/ register_dissector("usbhid.boot_report.keyboard.output", dissect_usb_hid_boot_keyboard_output_report, proto_usb_hid);
    /*usb_hid_boot_mouse_input_report_handle     =*/ register_dissector("usbhid.boot_report.mouse.input",     dissect_usb_hid_boot_mouse_input_report,     proto_usb_hid);
    usb_hid_control_handle                         = register_dissector("usbhid.control", dissect_usb_hid_control, proto_usb_hid);
    usb_hid_interrupt_handle                       = register_dissector("usbhid.data", dissect_usb_hid_data, proto_usb_hid);
    usb_hid_descr_handle                           = register_dissector("usbhid.class_descriptors", dissect_usb_hid_class_descriptors, proto_usb_hid);
}

void
proto_reg_handoff_usb_hid(void)
{
    dissector_add_uint("usb.control", IF_CLASS_HID, usb_hid_control_handle);
    dissector_add_for_decode_as("usb.device", usb_hid_control_handle);
    dissector_add_uint("usb.interrupt", IF_CLASS_HID, usb_hid_interrupt_handle);
    dissector_add_uint("usb.descriptor", IF_CLASS_HID, usb_hid_descr_handle);
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
