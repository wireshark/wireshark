/* packet-usb-hid.c
 *
 * USB HID dissector
 * By Adam Nielsen <a.nielsen@shikadi.net> 2009
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"


#include <epan/packet.h>
#include "packet-usb.h"
#include "packet-usb-hid.h"
#include "packet-btsdp.h"


void proto_register_usb_hid(void);
void proto_reg_handoff_usb_hid(void);

/* protocols and header fields */
static int proto_usb_hid = -1;
static int hf_usb_hid_item_bSize = -1;
static int hf_usb_hid_item_bType = -1;
static int hf_usb_hid_mainitem_bTag = -1;
static int hf_usb_hid_globalitem_bTag = -1;
static int hf_usb_hid_localitem_bTag = -1;
static int hf_usb_hid_longitem_bTag = -1;
static int hf_usb_hid_item_bDataSize = -1;
static int hf_usb_hid_item_bLongItemTag = -1;
static int hf_usb_hid_item_unk_data = -1;

static int hf_usb_hid_mainitem_bit0 = -1;
static int hf_usb_hid_mainitem_bit1 = -1;
static int hf_usb_hid_mainitem_bit2 = -1;
static int hf_usb_hid_mainitem_bit3 = -1;
static int hf_usb_hid_mainitem_bit4 = -1;
static int hf_usb_hid_mainitem_bit5 = -1;
static int hf_usb_hid_mainitem_bit6 = -1;
static int hf_usb_hid_mainitem_bit7 = -1;
static int hf_usb_hid_mainitem_bit7_input = -1;
static int hf_usb_hid_mainitem_bit8 = -1;
static int hf_usb_hid_mainitem_colltype = -1;

static int hf_usb_hid_globalitem_usage = -1;
static int hf_usb_hid_globalitem_log_min = -1;
static int hf_usb_hid_globalitem_log_max = -1;
static int hf_usb_hid_globalitem_phy_min = -1;
static int hf_usb_hid_globalitem_phy_max = -1;
static int hf_usb_hid_globalitem_unit_exp = -1;
static int hf_usb_hid_globalitem_unit_sys = -1;
static int hf_usb_hid_globalitem_unit_len = -1;
static int hf_usb_hid_globalitem_unit_mass = -1;
static int hf_usb_hid_globalitem_unit_time = -1;
static int hf_usb_hid_globalitem_unit_temp = -1;
static int hf_usb_hid_globalitem_unit_current = -1;
static int hf_usb_hid_globalitem_unit_brightness = -1;
static int hf_usb_hid_globalitem_report_size = -1;
static int hf_usb_hid_globalitem_report_id = -1;
static int hf_usb_hid_globalitem_report_count = -1;
static int hf_usb_hid_globalitem_push = -1;
static int hf_usb_hid_globalitem_pop = -1;

static int hf_usb_hid_localitem_usage = -1;
static int hf_usb_hid_localitem_usage_min = -1;
/* static int hf_usb_hid_localitem_usage_max = -1; */
static int hf_usb_hid_localitem_desig_index = -1;
static int hf_usb_hid_localitem_desig_min = -1;
static int hf_usb_hid_localitem_desig_max = -1;
static int hf_usb_hid_localitem_string_index = -1;
static int hf_usb_hid_localitem_string_min = -1;
static int hf_usb_hid_localitem_string_max = -1;
static int hf_usb_hid_localitem_delimiter = -1;

static gint ett_usb_hid_report = -1;
static gint ett_usb_hid_item_header = -1;
static gint ett_usb_hid_wValue = -1;
static gint ett_usb_hid_descriptor = -1;

static int hf_usb_hid_request = -1;
static int hf_usb_hid_value = -1;
static int hf_usb_hid_index = -1;
static int hf_usb_hid_length = -1;
static int hf_usb_hid_report_type = -1;
static int hf_usb_hid_report_id = -1;
static int hf_usb_hid_duration = -1;
static int hf_usb_hid_zero = -1;

static int hf_usb_hid_bcdHID = -1;
static int hf_usb_hid_bCountryCode = -1;
static int hf_usb_hid_bNumDescriptors = -1;
static int hf_usb_hid_bDescriptorIndex = -1;
static int hf_usb_hid_bDescriptorType = -1;
static int hf_usb_hid_wInterfaceNumber = -1;
static int hf_usb_hid_wDescriptorLength = -1;

static int hf_usbhid_boot_report_keyboard_modifier_right_gui = -1;
static int hf_usbhid_boot_report_keyboard_modifier_right_alt = -1;
static int hf_usbhid_boot_report_keyboard_modifier_right_shift = -1;
static int hf_usbhid_boot_report_keyboard_modifier_right_ctrl = -1;
static int hf_usbhid_boot_report_keyboard_modifier_left_gui = -1;
static int hf_usbhid_boot_report_keyboard_modifier_left_alt = -1;
static int hf_usbhid_boot_report_keyboard_modifier_left_shift = -1;
static int hf_usbhid_boot_report_keyboard_modifier_left_ctrl = -1;
static int hf_usbhid_boot_report_keyboard_reserved = -1;
static int hf_usbhid_boot_report_keyboard_keycode_1 = -1;
static int hf_usbhid_boot_report_keyboard_keycode_2 = -1;
static int hf_usbhid_boot_report_keyboard_keycode_3 = -1;
static int hf_usbhid_boot_report_keyboard_keycode_4 = -1;
static int hf_usbhid_boot_report_keyboard_keycode_5 = -1;
static int hf_usbhid_boot_report_keyboard_keycode_6 = -1;
static int hf_usbhid_boot_report_keyboard_leds_constants = -1;
static int hf_usbhid_boot_report_keyboard_leds_kana = -1;
static int hf_usbhid_boot_report_keyboard_leds_compose = -1;
static int hf_usbhid_boot_report_keyboard_leds_scroll_lock = -1;
static int hf_usbhid_boot_report_keyboard_leds_caps_lock = -1;
static int hf_usbhid_boot_report_keyboard_leds_num_lock = -1;
static int hf_usbhid_boot_report_mouse_button_8 = -1;
static int hf_usbhid_boot_report_mouse_button_7 = -1;
static int hf_usbhid_boot_report_mouse_button_6 = -1;
static int hf_usbhid_boot_report_mouse_button_5 = -1;
static int hf_usbhid_boot_report_mouse_button_4 = -1;
static int hf_usbhid_boot_report_mouse_button_middle = -1;
static int hf_usbhid_boot_report_mouse_button_right = -1;
static int hf_usbhid_boot_report_mouse_button_left = -1;
static int hf_usbhid_boot_report_mouse_x_displacement = -1;
static int hf_usbhid_boot_report_mouse_y_displacement = -1;
static int hf_usbhid_boot_report_mouse_horizontal_scroll_wheel = -1;
static int hf_usbhid_boot_report_mouse_vertical_scroll_wheel = -1;
static int hf_usbhid_data = -1;

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


/* HID class specific descriptor types */
#define USB_DT_HID        0x21
#define USB_DT_HID_REPORT 0x22
static const value_string hid_descriptor_type_vals[] = {
    {USB_DT_HID, "HID"},
    {USB_DT_HID_REPORT, "HID Report"},
    {0,NULL}
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
    {USBHID_MAINITEM_TAG_ENDCOLLECTION, "End collection"},
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
    {USBHID_GLOBALITEM_TAG_USAGE_PAGE,   "Usage"},
    {USBHID_GLOBALITEM_TAG_LOG_MIN,      "Logical minimum"},
    {USBHID_GLOBALITEM_TAG_LOG_MAX,      "Logical maximum"},
    {USBHID_GLOBALITEM_TAG_PHY_MIN,      "Physical minimum"},
    {USBHID_GLOBALITEM_TAG_PHY_MAX,      "Physical maximum"},
    {USBHID_GLOBALITEM_TAG_UNIT_EXP,     "Unit exponent"},
    {USBHID_GLOBALITEM_TAG_UNIT,         "Units"},
    {USBHID_GLOBALITEM_TAG_REPORT_SIZE,  "Report size"},
    {USBHID_GLOBALITEM_TAG_REPORT_ID,    "Report ID"},
    {USBHID_GLOBALITEM_TAG_REPORT_COUNT, "Report count"},
    {USBHID_GLOBALITEM_TAG_PUSH,         "Push"},
    {USBHID_GLOBALITEM_TAG_POP,          "Pop"},
    {12, "[Reserved]"},
    {13, "[Reserved]"},
    {14, "[Reserved]"},
    {15, "[Reserved]"},
    {0, NULL}
};
#define USBHID_LOCALITEM_TAG_USAGE_PAGE     0
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
    {USBHID_LOCALITEM_TAG_USAGE_PAGE,   "Usage"},
    {USBHID_LOCALITEM_TAG_USAGE_MIN,    "Usage minimum"},
    {USBHID_LOCALITEM_TAG_USAGE_MAX,    "Usage maximum"},
    {USBHID_LOCALITEM_TAG_DESIG_INDEX,  "Designator index"},
    {USBHID_LOCALITEM_TAG_DESIG_MIN,    "Designator minimum"},
    {USBHID_LOCALITEM_TAG_DESIG_MAX,    "Designator maximum"},
    {USBHID_LOCALITEM_TAG_STRING_INDEX, "String index"},
    {USBHID_LOCALITEM_TAG_STRING_MIN,   "String minimum"},
    {USBHID_LOCALITEM_TAG_STRING_MAX,   "String maximum"},
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
static const range_string usb_hid_item_usage_page_vals[] = {
    {0x00, 0x00, "Undefined"},
    {0x01, 0x01, "Generic desktop controls"},
    {0x02, 0x02, "Simulation controls"},
    {0x03, 0x03, "VR controls"},
    {0x04, 0x04, "Sport controls"},
    {0x05, 0x05, "Game controls"},
    {0x06, 0x06, "Generic device controls"},
    {0x07, 0x07, "Keyboard/keypad"},
    {0x08, 0x08, "LEDs"},
    {0x09, 0x09, "Button"},
    {0x0A, 0x0A, "Ordinal"},
    {0x0B, 0x0B, "Telephony"},
    {0x0C, 0x0C, "Consumer"},
    {0x0D, 0x0D, "Digitizer"},
    {0x0E, 0x0E, "[Reserved]"},
    {0x0F, 0x0F, "Physical Interface Device (PID) page"},
    {0x10, 0x10, "Unicode"},
    {0x11, 0x13, "[Reserved]"},
    {0x14, 0x14, "Alphanumeric display"},
    {0x15, 0x3F, "[Reserved]"},
    {0x40, 0x40, "Medical instruments"},
    {0x41, 0x7F, "[Reserved]"},
    {0x80, 0x83, "Monitor page"},
    {0x84, 0x87, "Power page"},
    {0x88, 0x8B, "[Reserved]"},
    {0x8C, 0x8C, "Bar code scanner page"},
    {0x8D, 0x8D, "Scale page"},
    {0x8E, 0x8E, "Magnetic Stripe Reading (MSR) devices"},
    {0x8F, 0x8F, "[Reserved Point of Sale page]"},
    {0x90, 0x90, "Camera control page"},
    {0x91, 0x91, "Arcade page"},
    {0x92, 0xFEFF, "[Reserved]"},
    {0xFF00, 0xFFFF, "[Vendor-defined]"},
    {0, 0, NULL}
};
static const range_string usb_hid_item_usage_vals[] = {
    {0x000000, 0x00FFFF, "Undefined"},

    // Generic desktop controls
    {0x010000, 0x010000, "Undefined"},
    {0x010001, 0x010001, "Pointer"},
    {0x010002, 0x010002, "Mouse"},
    {0x010003, 0x010003, "Reserved"},
    {0x010004, 0x010004, "Joystick"},
    {0x010005, 0x010005, "Game Pad"},
    {0x010006, 0x010006, "Keyboard"},
    {0x010007, 0x010007, "Keypad"},
    {0x010008, 0x010008, "Multi-axis Controller"},
    {0x010009, 0x010009, "Tablet PC System Controls"},
    {0x01000A, 0x01002F, "Reserved"},
    {0x010030, 0x010030, "X"},
    {0x010031, 0x010031, "Y"},
    {0x010032, 0x010032, "Z"},
    {0x010033, 0x010033, "Rx"},
    {0x010034, 0x010034, "Ry"},
    {0x010035, 0x010035, "Rz"},
    {0x010036, 0x010036, "Slider"},
    {0x010037, 0x010037, "Dial"},
    {0x010038, 0x010038, "Wheel"},
    {0x010039, 0x010039, "Hat switch"},
    {0x01003A, 0x01003A, "Counted Buffer"},
    {0x01003B, 0x01003B, "Byte Count"},
    {0x01003C, 0x01003C, "Motion Wakeup"},
    {0x01003D, 0x01003D, "Start"},
    {0x01003E, 0x01003E, "Select"},
    {0x01003F, 0x01003F, "Reserved"},
    {0x010040, 0x010040, "Vx"},
    {0x010041, 0x010041, "Vy"},
    {0x010042, 0x010042, "Vz"},
    {0x010043, 0x010043, "Vbrx"},
    {0x010044, 0x010044, "Vbry"},
    {0x010045, 0x010045, "Vbrz"},
    {0x010046, 0x010046, "Vno"},
    {0x010047, 0x010047, "Feature Notification"},
    {0x010048, 0x010048, "Resolution Multiplier"},
    {0x010049, 0x01007F, "Reserved"},
    {0x010080, 0x010080, "System Control"},
    {0x010081, 0x010081, "System Power Down"},
    {0x010082, 0x010082, "System Sleep"},
    {0x010083, 0x010083, "System Wake Up"},
    {0x010084, 0x010084, "System Context Menu"},
    {0x010085, 0x010085, "System Main Menu"},
    {0x010086, 0x010086, "System App Menu"},
    {0x010087, 0x010087, "System Menu Help"},
    {0x010088, 0x010088, "System Menu Exit"},
    {0x010089, 0x010089, "System Menu Select"},
    {0x01008A, 0x01008A, "System Menu Right"},
    {0x01008B, 0x01008B, "System Menu Left"},
    {0x01008C, 0x01008C, "System Menu Up"},
    {0x01008D, 0x01008D, "System Menu Down"},
    {0x01008E, 0x01008E, "System Cold Restart"},
    {0x01008F, 0x01008F, "System Warm Restart"},
    {0x010090, 0x010090, "D-pad Up"},
    {0x010091, 0x010091, "D-pad Down"},
    {0x010092, 0x010092, "D-pad Right"},
    {0x010093, 0x010093, "D-pad Left"},
    {0x010094, 0x01009F, "Reserved"},
    {0x0100A0, 0x0100A0, "System Dock"},
    {0x0100A1, 0x0100A1, "System Undock"},
    {0x0100A2, 0x0100A2, "System Setup"},
    {0x0100A3, 0x0100A3, "System Break"},
    {0x0100A4, 0x0100A4, "System Debugger Break"},
    {0x0100A5, 0x0100A5, "Application Break"},
    {0x0100A6, 0x0100A6, "Application Debugger Break"},
    {0x0100A7, 0x0100A7, "System Speaker Mute"},
    {0x0100A8, 0x0100A8, "System Hibernate"},
    {0x0100A9, 0x0100AF, "Reserved"},
    {0x0100B0, 0x0100B0, "System Display Invert"},
    {0x0100B1, 0x0100B1, "System Display Internal"},
    {0x0100B2, 0x0100B2, "System Display External"},
    {0x0100B3, 0x0100B3, "System Display Both"},
    {0x0100B4, 0x0100B4, "System Display Dual"},
    {0x0100B5, 0x0100B5, "System Display Toggle Int/Ext"},
    {0x0100B6, 0x0100B6, "System Display Swap Primary/Secondary"},
    {0x0100B7, 0x0100B7, "System Display LCD Autoscale"},
    {0x0100B8, 0x01FFFF, "Reserved"},

    // Simulation controls
    {0x020000, 0x020000, "Undefined"},
    {0x020001, 0x020001, "Flight Simulation Device"},
    {0x020002, 0x020002, "Automobile Simulation Device"},
    {0x020003, 0x020003, "Tank Simulation Device"},
    {0x020004, 0x020004, "Spaceship Simulation Device"},
    {0x020005, 0x020005, "Submarine Simulation Device"},
    {0x020006, 0x020006, "Sailing Simulation Device"},
    {0x020007, 0x020007, "Motorcycle Simulation Device"},
    {0x020008, 0x020008, "Sports Simulation Device"},
    {0x020009, 0x020009, "Airplane Simulation Device"},
    {0x02000A, 0x02000A, "Helicopter Simulation Device"},
    {0x02000B, 0x02000B, "Magic Carpet Simulation Device"},
    {0x02000C, 0x02000C, "Bicycle Simulation Device"},
    {0x02000D, 0x02001F, "Reserved"},
    {0x020020, 0x020020, "Flight Control Stick"},
    {0x020021, 0x020021, "Flight Stick"},
    {0x020022, 0x020022, "Cyclic Control"},
    {0x020023, 0x020023, "Cyclic Trim"},
    {0x020024, 0x020024, "Flight Yoke"},
    {0x020025, 0x020025, "Track Control"},
    {0x020026, 0x0200AF, "Reserved"},
    {0x0200B0, 0x0200B0, "Aileron"},
    {0x0200B1, 0x0200B1, "Aileron Trim"},
    {0x0200B2, 0x0200B2, "Anti-Torque Control"},
    {0x0200B3, 0x0200B3, "Autopilot Enable"},
    {0x0200B4, 0x0200B4, "Chaff Release"},
    {0x0200B5, 0x0200B5, "Collective Control"},
    {0x0200B6, 0x0200B6, "Dive Brake"},
    {0x0200B7, 0x0200B7, "Electronic Countermeasures"},
    {0x0200B8, 0x0200B8, "Elevator"},
    {0x0200B9, 0x0200B9, "Elevator Trim"},
    {0x0200BA, 0x0200BA, "Rudder"},
    {0x0200BB, 0x0200BB, "Throttle"},
    {0x0200BC, 0x0200BC, "Flight Communications"},
    {0x0200BD, 0x0200BD, "Flare Release"},
    {0x0200BE, 0x0200BE, "Landing Gear"},
    {0x0200BF, 0x0200BF, "Toe Brake"},
    {0x0200C0, 0x0200C0, "Trigger"},
    {0x0200C1, 0x0200C1, "Weapons Arm"},
    {0x0200C2, 0x0200C2, "Weapons Select"},
    {0x0200C3, 0x0200C3, "Wing Flaps"},
    {0x0200C4, 0x0200C4, "Accelerator"},
    {0x0200C5, 0x0200C5, "Brake"},
    {0x0200C6, 0x0200C6, "Clutch"},
    {0x0200C7, 0x0200C7, "Shifter"},
    {0x0200C8, 0x0200C8, "Steering"},
    {0x0200C9, 0x0200C9, "Turret Direction"},
    {0x0200CA, 0x0200CA, "Barrel Elevation"},
    {0x0200CB, 0x0200CB, "Dive Plane"},
    {0x0200CC, 0x0200CC, "Ballast"},
    {0x0200CD, 0x0200CD, "Bicycle Crank"},
    {0x0200CE, 0x0200CE, "Handle Bars"},
    {0x0200CF, 0x0200CF, "Front Brake"},
    {0x0200D0, 0x0200D0, "Rear Brake"},
    {0x0200D1, 0x02FFFF, "Reserved"},

    // VR controls
    {0x030000, 0x030000, "Unidentified"},
    {0x030001, 0x030001, "Belt"},
    {0x030002, 0x030002, "Body Suit"},
    {0x030003, 0x030003, "Flexor"},
    {0x030004, 0x030004, "Glove"},
    {0x030005, 0x030005, "Head Tracker"},
    {0x030006, 0x030006, "Head Mounted Display"},
    {0x030007, 0x030007, "Hand Tracker"},
    {0x030008, 0x030008, "Oculometer"},
    {0x030009, 0x030009, "Vest"},
    {0x03000A, 0x03000A, "Animatronic Device"},
    {0x03000B, 0x03001F, "Reserved"},
    {0x030020, 0x030020, "Stereo Enable"},
    {0x030021, 0x030021, "Display Enable"},
    {0x030022, 0x03FFFF, "Reserved"},

    // Sport controls
    {0x040000, 0x040000, "Unidentified"},
    {0x040001, 0x040001, "Baseball Bat"},
    {0x040002, 0x040002, "Golf Club"},
    {0x040003, 0x040003, "Rowing Machine"},
    {0x040004, 0x040004, "Treadmill"},
    {0x040005, 0x04002F, "Reserved"},
    {0x040030, 0x040030, "Oar"},
    {0x040031, 0x040031, "Slope"},
    {0x040032, 0x040032, "Rate"},
    {0x040033, 0x040033, "Stick Speed"},
    {0x040034, 0x040034, "Stick Face Angle"},
    {0x040035, 0x040035, "Stick Heel/Toe"},
    {0x040036, 0x040036, "Stick Follow Through"},
    {0x040037, 0x040037, "Stick Tempo"},
    {0x040038, 0x040038, "Stick Type"},
    {0x040039, 0x040039, "Stick Height"},
    {0x04003A, 0x04004F, "Reserved"},
    {0x040050, 0x040050, "Putter"},
    {0x040051, 0x040051, "1 Iron"},
    {0x040052, 0x040052, "2 Iron"},
    {0x040053, 0x040053, "3 Iron"},
    {0x040054, 0x040054, "4 Iron"},
    {0x040055, 0x040055, "5 Iron"},
    {0x040056, 0x040056, "6 Iron"},
    {0x040057, 0x040057, "7 Iron"},
    {0x040058, 0x040058, "8 Iron"},
    {0x040059, 0x040059, "9 Iron"},
    {0x04005A, 0x04005A, "10 Iron"},
    {0x04005B, 0x04005B, "11 Iron"},
    {0x04005C, 0x04005C, "Sand Wedge"},
    {0x04005D, 0x04005D, "Loft Wedge"},
    {0x04005E, 0x04005E, "Power Wedge"},
    {0x04005F, 0x04005F, "1 Wood"},
    {0x040060, 0x040060, "3 Wood"},
    {0x040061, 0x040061, "5 Wood"},
    {0x040062, 0x040062, "7 Wood"},
    {0x040063, 0x040063, "9 Wood"},
    {0x040064, 0x04FFFF, "Reserved"},

    // Game controls
    {0x050000, 0x050000, "Undefined"},
    {0x050001, 0x050001, "3D Game Controller"},
    {0x050002, 0x050002, "Pinball Device"},
    {0x050003, 0x050003, "Gun Device"},
    {0x050004, 0x05001F, "Reserved"},
    {0x050020, 0x050020, "Point of View"},
    {0x050021, 0x050021, "Turn Right/Left"},
    {0x050022, 0x050022, "Pitch Forward/Backward"},
    {0x050023, 0x050023, "Roll Right/Left"},
    {0x050024, 0x050024, "Move Right/Left"},
    {0x050025, 0x050025, "Move Forward/Backward"},
    {0x050026, 0x050026, "Move Up/Down"},
    {0x050027, 0x050027, "Lean Right/Left"},
    {0x050028, 0x050028, "Lean Forward/Backward"},
    {0x050029, 0x050029, "Height of POV"},
    {0x05002A, 0x05002A, "Flipper"},
    {0x05002B, 0x05002B, "Secondary Flipper"},
    {0x05002C, 0x05002C, "Bump"},
    {0x05002D, 0x05002D, "New Game"},
    {0x05002E, 0x05002E, "Shoot Ball"},
    {0x05002F, 0x05002F, "Player"},
    {0x050030, 0x050030, "Gun Bolt"},
    {0x050031, 0x050031, "Gun Clip"},
    {0x050032, 0x050032, "Gun Selector"},
    {0x050033, 0x050033, "Gun Single Shot"},
    {0x050034, 0x050034, "Gun Burst"},
    {0x050035, 0x050035, "Gun Automatic"},
    {0x050036, 0x050036, "Gun Safety"},
    {0x050037, 0x050037, "Gamepad Fire/Jump"},
    {0x050038, 0x050038, "[Undefined]"},
    {0x050039, 0x050039, "Gamepad Trigger"},
    {0x05003A, 0x05FFFF, "Reserved"},

    // Generic device controls
    {0x060000, 0x060000, "Unidentified"},
    {0x060001, 0x06001F, "Reserved"},
    {0x060020, 0x060020, "Battery Strength"},
    {0x060021, 0x060021, "Wireless Channel"},
    {0x060022, 0x060022, "Wireless ID"},
    {0x060023, 0x060023, "Discover Wireless Control"},
    {0x060024, 0x060024, "Security Code Character Entered"},
    {0x060025, 0x060025, "Security Code Character Erased"},
    {0x060026, 0x060026, "Security Code Cleared"},
    {0x060027, 0x06FFFF, "Reserved"},

    // Keyboard/keypad
    {0x070000, 0x070000, "Reserved (no event indicated)"},
    {0x070001, 0x070001, "Keyboard ErrorRollOver"},
    {0x070002, 0x070002, "Keyboard POSTFail"},
    {0x070003, 0x070003, "Keyboard ErrorUndefined"},
    {0x070004, 0x070004, "Keyboard a and A"},
    {0x070005, 0x070005, "Keyboard b and B"},
    {0x070006, 0x070006, "Keyboard c and C"},
    {0x070007, 0x070007, "Keyboard d and D"},
    {0x070008, 0x070008, "Keyboard e and E"},
    {0x070009, 0x070009, "Keyboard f and F"},
    {0x07000A, 0x07000A, "Keyboard g and G"},
    {0x07000B, 0x07000B, "Keyboard h and H"},
    {0x07000C, 0x07000C, "Keyboard i and I"},
    {0x07000D, 0x07000D, "Keyboard j and J"},
    {0x07000E, 0x07000E, "Keyboard k and K"},
    {0x07000F, 0x07000F, "Keyboard l and L"},
    {0x070010, 0x070010, "Keyboard m and M"},
    {0x070011, 0x070011, "Keyboard n and N"},
    {0x070012, 0x070012, "Keyboard o and O"},
    {0x070013, 0x070013, "Keyboard p and P"},
    {0x070014, 0x070014, "Keyboard q and Q"},
    {0x070015, 0x070015, "Keyboard r and R"},
    {0x070016, 0x070016, "Keyboard s and S"},
    {0x070017, 0x070017, "Keyboard t and T"},
    {0x070018, 0x070018, "Keyboard u and U"},
    {0x070019, 0x070019, "Keyboard v and V"},
    {0x07001A, 0x07001A, "Keyboard w and W"},
    {0x07001B, 0x07001B, "Keyboard x and X"},
    {0x07001C, 0x07001C, "Keyboard y and Y"},
    {0x07001D, 0x07001D, "Keyboard z and Z"},
    {0x07001E, 0x07001E, "Keyboard 1 and !"},
    {0x07001F, 0x07001F, "Keyboard 2 and @"},
    {0x070020, 0x070020, "Keyboard 3 and #"},
    {0x070021, 0x070021, "Keyboard 4 and $"},
    {0x070022, 0x070022, "Keyboard 5 and %"},
    {0x070023, 0x070023, "Keyboard 6 and ^"},
    {0x070024, 0x070024, "Keyboard 7 and &"},
    {0x070025, 0x070025, "Keyboard 8 and *"},
    {0x070026, 0x070026, "Keyboard 9 and ("},
    {0x070027, 0x070027, "Keyboard 0 and )"},
    {0x070028, 0x070028, "Keyboard Return (ENTER)"},
    {0x070029, 0x070029, "Keyboard ESCAPE"},
    {0x07002A, 0x07002A, "Keyboard DELETE (Backspace)"},
    {0x07002B, 0x07002B, "Keyboard Tab"},
    {0x07002C, 0x07002C, "Keyboard Spacebar"},
    {0x07002D, 0x07002D, "Keyboard - and (underscore)"},
    {0x07002E, 0x07002E, "Keyboard = and +"},
    {0x07002F, 0x07002F, "Keyboard [ and {"},
    {0x070030, 0x070030, "Keyboard ] and }"},
    {0x070031, 0x070031, "Keyboard \\ and |"},
    {0x070032, 0x070032, "Keyboard Non-US # and ~"},
    {0x070033, 0x070033, "Keyboard ; and :"},
    {0x070034, 0x070034, "Keyboard ' and \""},
    {0x070035, 0x070035, "Keyboard Grave Accent and Tilde"},
    {0x070036, 0x070036, "Keyboard , and <"},
    {0x070037, 0x070037, "Keyboard . and >"},
    {0x070038, 0x070038, "Keyboard / and ?"},
    {0x070039, 0x070039, "Keyboard Caps Lock"},
    {0x07003A, 0x07003A, "Keyboard F1"},
    {0x07003B, 0x07003B, "Keyboard F2"},
    {0x07003C, 0x07003C, "Keyboard F3"},
    {0x07003D, 0x07003D, "Keyboard F4"},
    {0x07003E, 0x07003E, "Keyboard F5"},
    {0x07003F, 0x07003F, "Keyboard F6"},
    {0x070040, 0x070040, "Keyboard F7"},
    {0x070041, 0x070041, "Keyboard F8"},
    {0x070042, 0x070042, "Keyboard F9"},
    {0x070043, 0x070043, "Keyboard F11"},
    {0x070044, 0x070044, "Keyboard F12"},
    {0x070045, 0x070045, "Keyboard F13"},
    {0x070046, 0x070046, "Keyboard PrintScreen"},
    {0x070047, 0x070047, "Keyboard Scroll Lock"},
    {0x070048, 0x070048, "Keyboard Pause"},
    {0x070049, 0x070049, "Keyboard Insert"},
    {0x07004A, 0x07004A, "Keyboard Home"},
    {0x07004B, 0x07004B, "Keyboard PageUp"},
    {0x07004C, 0x07004C, "Keyboard Delete Forward"},
    {0x07004D, 0x07004D, "Keyboard End"},
    {0x07004E, 0x07004E, "Keyboard PageDown"},
    {0x07004F, 0x07004F, "Keyboard RightArrow"},
    {0x070050, 0x070050, "Keyboard LeftArrow"},
    {0x070051, 0x070051, "Keyboard DownArrow"},
    {0x070052, 0x070052, "Keyboard UpArrow"},
    {0x070053, 0x070053, "Keypad Num Lock and Clear"},
    {0x070054, 0x070054, "Keypad /"},
    {0x070055, 0x070055, "Keypad *"},
    {0x070056, 0x070056, "Keypad -"},
    {0x070057, 0x070057, "Keypad +"},
    {0x070058, 0x070058, "Keypad ENTER"},
    {0x070059, 0x070059, "Keypad 1 and End"},
    {0x07005A, 0x07005A, "Keypad 2 and Down Arrow"},
    {0x07005B, 0x07005B, "Keypad 3 and PageDn"},
    {0x07005C, 0x07005C, "Keypad 4 and Left Arrow"},
    {0x07005D, 0x07005D, "Keypad 5"},
    {0x07005E, 0x07005E, "Keypad 6 and Right Arrow"},
    {0x07005F, 0x07005F, "Keypad 7 and Home"},
    {0x070060, 0x070060, "Keypad 8 and Up Arrow"},
    {0x070061, 0x070061, "Keypad 9 and PageUp"},
    {0x070062, 0x070062, "Keypad 0 and Insert"},
    {0x070063, 0x070063, "Keypad . and Delete"},
    {0x070064, 0x070064, "Keyboard Non-US \\ and |"},
    {0x070065, 0x070065, "Keyboard Application"},
    {0x070066, 0x070066, "Keyboard Power"},
    {0x070067, 0x070067, "Keypad ="},
    {0x070068, 0x070068, "Keyboard F13"},
    {0x070069, 0x070069, "Keyboard F14"},
    {0x07006A, 0x07006A, "Keyboard F15"},
    {0x07006B, 0x07006B, "Keyboard F16"},
    {0x07006C, 0x07006C, "Keyboard F17"},
    {0x07006D, 0x07006D, "Keyboard F18"},
    {0x07006E, 0x07006E, "Keyboard F19"},
    {0x07006F, 0x07006F, "Keyboard F20"},
    {0x070070, 0x070070, "Keyboard F21"},
    {0x070071, 0x070071, "Keyboard F22"},
    {0x070072, 0x070072, "Keyboard F23"},
    {0x070073, 0x070073, "Keyboard F24"},
    {0x070074, 0x070074, "Keyboard Execute"},
    {0x070075, 0x070075, "Keyboard Help"},
    {0x070076, 0x070076, "Keyboard Menu"},
    {0x070077, 0x070077, "Keyboard Select"},
    {0x070078, 0x070078, "Keyboard Stop"},
    {0x070079, 0x070079, "Keyboard Again"},
    {0x07007A, 0x07007A, "Keyboard Undo"},
    {0x07007B, 0x07007B, "Keyboard Cut"},
    {0x07007C, 0x07007C, "Keyboard Copy"},
    {0x07007D, 0x07007D, "Keyboard Paste"},
    {0x07007E, 0x07007E, "Keyboard Find"},
    {0x07007F, 0x07007F, "Keyboard Mute"},
    {0x070080, 0x070080, "Keyboard Volume Up"},
    {0x070081, 0x070081, "Keyboard Volume Down"},
    {0x070082, 0x070082, "Keyboard Locking Caps Lock"},
    {0x070083, 0x070083, "Keyboard Locking Num Lock"},
    {0x070084, 0x070084, "Keyboard Locking Scroll Lock"},
    {0x070085, 0x070085, "Keypad Comma"},
    {0x070086, 0x070086, "Keypad Equal Sign"},
    {0x070087, 0x070087, "Keyboard International1"},
    {0x070088, 0x070088, "Keyboard International2"},
    {0x070089, 0x070089, "Keyboard International3"},
    {0x07008A, 0x07008A, "Keyboard International4"},
    {0x07008B, 0x07008B, "Keyboard International5"},
    {0x07008C, 0x07008C, "Keyboard International6"},
    {0x07008D, 0x07008D, "Keyboard International7"},
    {0x07008E, 0x07008E, "Keyboard International8"},
    {0x07008F, 0x07008F, "Keyboard International9"},
    {0x070090, 0x070090, "Keyboard LANG1"},
    {0x070091, 0x070091, "Keyboard LANG2"},
    {0x070092, 0x070092, "Keyboard LANG3"},
    {0x070093, 0x070093, "Keyboard LANG4"},
    {0x070094, 0x070094, "Keyboard LANG5"},
    {0x070095, 0x070095, "Keyboard LANG6"},
    {0x070096, 0x070096, "Keyboard LANG7"},
    {0x070097, 0x070097, "Keyboard LANG8"},
    {0x070098, 0x070098, "Keyboard LANG9"},
    {0x070099, 0x070099, "Keyboard Alternate Erase"},
    {0x07009A, 0x07009A, "Keyboard SysReq/Attention"},
    {0x07009B, 0x07009B, "Keyboard Cancel"},
    {0x07009C, 0x07009C, "Keyboard Clear"},
    {0x07009D, 0x07009D, "Keyboard Prior"},
    {0x07009E, 0x07009E, "Keyboard Return"},
    {0x07009F, 0x07009F, "Keyboard Separator"},
    {0x0700A0, 0x0700A0, "Keyboard Out"},
    {0x0700A1, 0x0700A1, "Keyboard Oper"},
    {0x0700A2, 0x0700A2, "Keyboard Clear/Again"},
    {0x0700A3, 0x0700A3, "Keyboard CrSel/Props"},
    {0x0700A4, 0x0700A4, "Keyboard ExSel"},
    {0x0700A5, 0x0700AF, "Reserved"},
    {0x0700B0, 0x0700B0, "Keypad 00"},
    {0x0700B1, 0x0700B1, "Keypad 000"},
    {0x0700B2, 0x0700B2, "Thousands Separator"},
    {0x0700B3, 0x0700B3, "Decimal Separator"},
    {0x0700B4, 0x0700B4, "Currency Unit"},
    {0x0700B5, 0x0700B5, "Currency Sub-unit"},
    {0x0700B6, 0x0700B6, "Keypad ("},
    {0x0700B7, 0x0700B7, "Keypad )"},
    {0x0700B8, 0x0700B8, "Keypad {"},
    {0x0700B9, 0x0700B9, "Keypad }"},
    {0x0700BA, 0x0700BA, "Keypad Tab"},
    {0x0700BB, 0x0700BB, "Keypad Backspace"},
    {0x0700BC, 0x0700BC, "Keypad A"},
    {0x0700BD, 0x0700BD, "Keypad B"},
    {0x0700BE, 0x0700BE, "Keypad C"},
    {0x0700BF, 0x0700BF, "Keypad D"},
    {0x0700C0, 0x0700C0, "Keypad E"},
    {0x0700C1, 0x0700C1, "Keypad F"},
    {0x0700C2, 0x0700C2, "Keypad XOR"},
    {0x0700C3, 0x0700C3, "Keypad ^"},
    {0x0700C4, 0x0700C4, "Keypad %"},
    {0x0700C5, 0x0700C5, "Keypad <"},
    {0x0700C6, 0x0700C6, "Keypad >"},
    {0x0700C7, 0x0700C7, "Keypad &"},
    {0x0700C8, 0x0700C8, "Keypad &&"},
    {0x0700C9, 0x0700C9, "Keypad |"},
    {0x0700CA, 0x0700CA, "Keypad ||"},
    {0x0700CB, 0x0700CB, "Keypad :"},
    {0x0700CC, 0x0700CC, "Keypad #"},
    {0x0700CD, 0x0700CD, "Keypad Space"},
    {0x0700CE, 0x0700CE, "Keypad @"},
    {0x0700CF, 0x0700CF, "Keypad !"},
    {0x0700D0, 0x0700D0, "Keypad Memory Store"},
    {0x0700D1, 0x0700D1, "Keypad Memory Recall"},
    {0x0700D2, 0x0700D2, "Keypad Memory Clear"},
    {0x0700D3, 0x0700D3, "Keypad Memory Add"},
    {0x0700D4, 0x0700D4, "Keypad Memory Subtract"},
    {0x0700D5, 0x0700D5, "Keypad Memory Multiply"},
    {0x0700D6, 0x0700D6, "Keypad Memory Divide"},
    {0x0700D7, 0x0700D7, "Keypad +/-"},
    {0x0700D8, 0x0700D8, "Keypad Clear"},
    {0x0700D9, 0x0700D9, "Keypad Clear Entry"},
    {0x0700DA, 0x0700DA, "Keypad Binary"},
    {0x0700DB, 0x0700DB, "Keypad Octal"},
    {0x0700DC, 0x0700DC, "Keypad Decimal"},
    {0x0700DD, 0x0700DD, "Keypad Hexadecimal"},
    {0x0700DE, 0x0700DF, "Reserved"},
    {0x0700E0, 0x0700E0, "Keyboard LeftControl"},
    {0x0700E1, 0x0700E1, "Keyboard LeftShift"},
    {0x0700E2, 0x0700E2, "Keyboard LeftAlt"},
    {0x0700E3, 0x0700E3, "Keyboard Left GUI"},
    {0x0700E4, 0x0700E4, "Keyboard RightControl"},
    {0x0700E5, 0x0700E5, "Keyboard RightShift"},
    {0x0700E6, 0x0700E6, "Keyboard RightAlt"},
    {0x0700E7, 0x0700E7, "Keyboard Right GUI"},
    {0x0700E8, 0x07FFFF, "Reserved"},

    // LEDs
    {0x080000, 0x080000, "Undefined"},
    {0x080001, 0x080001, "Num Lock"},
    {0x080002, 0x080002, "Caps Lock"},
    {0x080003, 0x080003, "Scroll Lock"},
    {0x080004, 0x080004, "Compose"},
    {0x080005, 0x080005, "Kana"},
    {0x080006, 0x080006, "Power"},
    {0x080007, 0x080007, "Shift"},
    {0x080008, 0x080008, "Do Not Disturb"},
    {0x080009, 0x080009, "Mute"},
    {0x08000A, 0x08000A, "Tone Enable"},
    {0x08000B, 0x08000B, "High Cut Filter"},
    {0x08000C, 0x08000C, "Low Cut Filter"},
    {0x08000D, 0x08000D, "Equalizer Enable"},
    {0x08000E, 0x08000E, "Sound Field On"},
    {0x08000F, 0x08000F, "Surround On"},
    {0x080010, 0x080010, "Repeat"},
    {0x080011, 0x080011, "Stereo"},
    {0x080012, 0x080012, "Sampling Rate Detect"},
    {0x080013, 0x080013, "Spinning"},
    {0x080014, 0x080014, "CAV"},
    {0x080015, 0x080015, "CLV"},
    {0x080016, 0x080016, "Recording Format Detect"},
    {0x080017, 0x080017, "Off-Hook"},
    {0x080018, 0x080018, "Ring"},
    {0x080019, 0x080019, "Message Waiting"},
    {0x08001A, 0x08001A, "Data Mode"},
    {0x08001B, 0x08001B, "Battery Operation"},
    {0x08001C, 0x08001C, "Battery OK"},
    {0x08001D, 0x08001D, "Battery Low"},
    {0x08001E, 0x08001E, "Speaker"},
    {0x08001F, 0x08001F, "Head Set"},
    {0x080020, 0x080020, "Hold"},
    {0x080021, 0x080021, "Microphone"},
    {0x080022, 0x080022, "Coverage"},
    {0x080023, 0x080023, "Night Mode"},
    {0x080024, 0x080024, "Send Calls"},
    {0x080025, 0x080025, "Call Pickup"},
    {0x080026, 0x080026, "Conference"},
    {0x080027, 0x080027, "Stand-by"},
    {0x080028, 0x080028, "Camera On"},
    {0x080029, 0x080029, "Camera Off"},
    {0x08002A, 0x08002A, "On-Line"},
    {0x08002B, 0x08002B, "Off-Line"},
    {0x08002C, 0x08002C, "Busy"},
    {0x08002D, 0x08002D, "Ready"},
    {0x08002E, 0x08002E, "Paper-Out"},
    {0x08002F, 0x08002F, "Paper-Jam"},
    {0x080030, 0x080030, "Remote"},
    {0x080031, 0x080031, "Forward"},
    {0x080032, 0x080032, "Reverse"},
    {0x080033, 0x080033, "Stop"},
    {0x080034, 0x080034, "Rewind"},
    {0x080035, 0x080035, "Fast Forward"},
    {0x080036, 0x080036, "Play"},
    {0x080037, 0x080037, "Pause"},
    {0x080038, 0x080038, "Record"},
    {0x080039, 0x080039, "Error"},
    {0x08003A, 0x08003A, "Usage Selected Indicator"},
    {0x08003B, 0x08003B, "Usage In Use Indicator"},
    {0x08003C, 0x08003C, "Usage Multi Mode Indicator"},
    {0x08003D, 0x08003D, "Indicator On"},
    {0x08003E, 0x08003E, "Indicator Flash"},
    {0x08003F, 0x08003F, "Indicator Slow Blink"},
    {0x080040, 0x080040, "Indicator Fast Blink"},
    {0x080041, 0x080041, "Indicator Off"},
    {0x080042, 0x080042, "Flash On Time"},
    {0x080043, 0x080043, "Slow Blink On Time"},
    {0x080044, 0x080044, "Slow Blink Off Time"},
    {0x080045, 0x080045, "Fast Blink On Time"},
    {0x080046, 0x080046, "Fast Blink Off Time"},
    {0x080047, 0x080047, "Usage Indicator Color"},
    {0x080048, 0x080048, "Indicator Red"},
    {0x080049, 0x080049, "Indicator Green"},
    {0x08004A, 0x08004A, "Indicator Amber"},
    {0x08004B, 0x08004B, "Generic Indicator"},
    {0x08004C, 0x08004C, "System Suspend"},
    {0x08004D, 0x08004D, "External Power Connected"},
    {0x08004E, 0x08FFFF, "Reserved"},

    // Button
    {0x090000, 0x090000, "No button pressed"},
    {0x090001, 0x09FFFF, "Button #"},

    // Ordinal
    {0x0A0000, 0x0A0000, "Reserved"},
    {0x0A0001, 0x0AFFFF, "Instance #"},

    // Telephony
    {0x0B0000, 0x0B0000, "Unassigned"},
    {0x0B0001, 0x0B0001, "Phone"},
    {0x0B0002, 0x0B0002, "Answering Machine"},
    {0x0B0003, 0x0B0003, "Message Controls"},
    {0x0B0004, 0x0B0004, "Handset"},
    {0x0B0005, 0x0B0005, "Headset"},
    {0x0B0006, 0x0B0006, "Telephony Key Pad"},
    {0x0B0007, 0x0B0007, "Programmable Button"},
    {0x0B0008, 0x0B001F, "Reserved"},
    {0x0B0020, 0x0B0020, "Hook Switch"},
    {0x0B0021, 0x0B0021, "Flash"},
    {0x0B0022, 0x0B0022, "Feature"},
    {0x0B0023, 0x0B0023, "Hold"},
    {0x0B0024, 0x0B0024, "Redial"},
    {0x0B0025, 0x0B0025, "Transfer"},
    {0x0B0026, 0x0B0026, "Drop"},
    {0x0B0027, 0x0B0027, "Park"},
    {0x0B0028, 0x0B0028, "Forward Calls"},
    {0x0B0029, 0x0B0029, "Alternate Function"},
    {0x0B002A, 0x0B002A, "Line"},
    {0x0B002B, 0x0B002B, "Speaker Phone"},
    {0x0B002C, 0x0B002C, "Conference"},
    {0x0B002D, 0x0B002D, "Ring Enable"},
    {0x0B002E, 0x0B002E, "Ring Select"},
    {0x0B002F, 0x0B002F, "Phone Mute"},
    {0x0B0030, 0x0B0030, "Caller ID"},
    {0x0B0031, 0x0B0031, "Send"},
    {0x0B0032, 0x0B004F, "Reserved"},
    {0x0B0050, 0x0B0050, "Speed Dial"},
    {0x0B0051, 0x0B0051, "Store Number"},
    {0x0B0052, 0x0B0052, "Recall Number"},
    {0x0B0053, 0x0B0053, "Phone Directory"},
    {0x0B0054, 0x0B006F, "Reserved"},
    {0x0B0070, 0x0B0070, "Voice Mail"},
    {0x0B0071, 0x0B0071, "Screen Calls"},
    {0x0B0072, 0x0B0072, "Do Not Disturb"},
    {0x0B0073, 0x0B0073, "Message"},
    {0x0B0074, 0x0B0074, "Answer On/Off"},
    {0x0B0075, 0x0B008F, "Reserved"},
    {0x0B0090, 0x0B0090, "Inside Dial Tone"},
    {0x0B0091, 0x0B0091, "Outside Dial Tone"},
    {0x0B0092, 0x0B0092, "Inside Ring Tone"},
    {0x0B0093, 0x0B0093, "Outside Ring Tone"},
    {0x0B0094, 0x0B0094, "Priority Ring Tone"},
    {0x0B0095, 0x0B0095, "Inside Ringback"},
    {0x0B0096, 0x0B0096, "Priority Ringback"},
    {0x0B0097, 0x0B0097, "Line Busy Tone"},
    {0x0B0098, 0x0B0098, "Reorder Tone"},
    {0x0B0099, 0x0B0099, "Call Waiting Tone"},
    {0x0B009A, 0x0B009A, "Confirmation Tone 1"},
    {0x0B009B, 0x0B009B, "Confirmation Tone 2"},
    {0x0B009C, 0x0B009C, "Tones Off"},
    {0x0B009D, 0x0B009D, "Outside Ringback"},
    {0x0B009E, 0x0B009E, "Ringer"},
    {0x0B009F, 0x0B00AF, "Reserved"},
    {0x0B00B0, 0x0B00B0, "Phone Key 0"},
    {0x0B00B1, 0x0B00B1, "Phone Key 1"},
    {0x0B00B2, 0x0B00B2, "Phone Key 2"},
    {0x0B00B3, 0x0B00B3, "Phone Key 3"},
    {0x0B00B4, 0x0B00B4, "Phone Key 4"},
    {0x0B00B5, 0x0B00B5, "Phone Key 5"},
    {0x0B00B6, 0x0B00B6, "Phone Key 6"},
    {0x0B00B7, 0x0B00B7, "Phone Key 7"},
    {0x0B00B8, 0x0B00B8, "Phone Key 8"},
    {0x0B00B9, 0x0B00B9, "Phone Key 9"},
    {0x0B00BA, 0x0B00BA, "Phone Key Star"},
    {0x0B00BB, 0x0B00BB, "Phone Key Pound"},
    {0x0B00BC, 0x0B00BC, "Phone Key A"},
    {0x0B00BD, 0x0B00BD, "Phone Key B"},
    {0x0B00BE, 0x0B00BE, "Phone Key C"},
    {0x0B00BF, 0x0B00BF, "Phone Key D"},
    {0x0B00C0, 0x0BFFFF, "Reserved"},

    // Consumer
    {0x0C0000, 0x0C0000, "Unassigned"},
    {0x0C0001, 0x0C0001, "Consumer Control"},
    {0x0C0002, 0x0C0002, "Numeric Key Pad"},
    {0x0C0003, 0x0C0003, "Programmable Buttons"},
    {0x0C0004, 0x0C0004, "Microphone"},
    {0x0C0005, 0x0C0005, "Headphone"},
    {0x0C0006, 0x0C0006, "Graphic Equalizer"},
    {0x0C0007, 0x0C001F, "Reserved"},
    {0x0C0020, 0x0C0020, "+10"},
    {0x0C0021, 0x0C0021, "+100"},
    {0x0C0022, 0x0C0022, "AM/PM"},
    {0x0C0023, 0x0C002F, "Reserved"},
    {0x0C0030, 0x0C0030, "Power"},
    {0x0C0031, 0x0C0031, "Reset"},
    {0x0C0032, 0x0C0032, "Sleep"},
    {0x0C0033, 0x0C0033, "Sleep After"},
    {0x0C0034, 0x0C0034, "Sleep Mode"},
    {0x0C0035, 0x0C0035, "Illumination"},
    {0x0C0036, 0x0C0036, "Function Buttons"},
    {0x0C0037, 0x0C003F, "Reserved"},
    {0x0C0040, 0x0C0040, "Menu"},
    {0x0C0041, 0x0C0041, "Menu Pick"},
    {0x0C0042, 0x0C0042, "Menu Up"},
    {0x0C0043, 0x0C0043, "Menu Down"},
    {0x0C0044, 0x0C0044, "Menu Left"},
    {0x0C0045, 0x0C0045, "Menu Right"},
    {0x0C0046, 0x0C0046, "Menu Escape"},
    {0x0C0047, 0x0C0047, "Menu Value Increase"},
    {0x0C0048, 0x0C0048, "Menu Value Decrease"},
    {0x0C0049, 0x0C005F, "Reserved"},
    {0x0C0060, 0x0C0060, "Data On Screen"},
    {0x0C0061, 0x0C0061, "Closed Caption"},
    {0x0C0062, 0x0C0062, "Closed Caption Select"},
    {0x0C0063, 0x0C0063, "VCR/TV"},
    {0x0C0064, 0x0C0064, "Broadcast Mode"},
    {0x0C0065, 0x0C0065, "Snapshot"},
    {0x0C0066, 0x0C0066, "Still"},
    {0x0C0067, 0x0C007F, "Reserved"},
    {0x0C0080, 0x0C0080, "Selection"},
    {0x0C0081, 0x0C0081, "Assign Selection"},
    {0x0C0082, 0x0C0082, "Mode Step"},
    {0x0C0083, 0x0C0083, "Recall Last"},
    {0x0C0084, 0x0C0084, "Enter Channel"},
    {0x0C0085, 0x0C0085, "Order Movie"},
    {0x0C0086, 0x0C0086, "Channel"},
    {0x0C0087, 0x0C0087, "Media Selection"},
    {0x0C0088, 0x0C0088, "Media Select Computer"},
    {0x0C0089, 0x0C0089, "Media Select TV"},
    {0x0C008A, 0x0C008A, "Media Select WWW"},
    {0x0C008B, 0x0C008B, "Media Select DVD"},
    {0x0C008C, 0x0C008C, "Media Select Telephone"},
    {0x0C008D, 0x0C008D, "Media Select Program Guide"},
    {0x0C008E, 0x0C008E, "Media Select Video Phone"},
    {0x0C008F, 0x0C008F, "Media Select Games"},
    {0x0C0090, 0x0C0090, "Media Select Messages"},
    {0x0C0091, 0x0C0091, "Media Select CD "},
    {0x0C0092, 0x0C0092, "Media Select VCR"},
    {0x0C0093, 0x0C0093, "Media Select Tuner"},
    {0x0C0094, 0x0C0094, "Quit"},
    {0x0C0095, 0x0C0095, "Help"},
    {0x0C0096, 0x0C0096, "Media Select Tape"},
    {0x0C0097, 0x0C0097, "Media Select Cable"},
    {0x0C0098, 0x0C0098, "Media Select Satellite"},
    {0x0C0099, 0x0C0099, "Media Select Security"},
    {0x0C009A, 0x0C009A, "Media Select Home"},
    {0x0C009B, 0x0C009B, "Media Select Call"},
    {0x0C009C, 0x0C009C, "Channel Increment"},
    {0x0C009D, 0x0C009D, "Channel Decrement"},
    {0x0C009E, 0x0C009E, "Media Select SAP"},
    {0x0C009F, 0x0C009F, "Reserved"},
    {0x0C00A0, 0x0C00A0, "VCR Plus"},
    {0x0C00A1, 0x0C00A1, "Once"},
    {0x0C00A2, 0x0C00A2, "Daily"},
    {0x0C00A3, 0x0C00A3, "Weekly"},
    {0x0C00A4, 0x0C00A4, "Monthly"},
    {0x0C00A5, 0x0C00AF, "Reserved"},
    {0x0C00B0, 0x0C00B0, "Play"},
    {0x0C00B1, 0x0C00B1, "Pause"},
    {0x0C00B2, 0x0C00B2, "Record"},
    {0x0C00B3, 0x0C00B3, "Fast Forward"},
    {0x0C00B4, 0x0C00B4, "Rewind"},
    {0x0C00B5, 0x0C00B5, "Scan Next Track"},
    {0x0C00B6, 0x0C00B6, "Scan Previous Track"},
    {0x0C00B7, 0x0C00B7, "Stop"},
    {0x0C00B8, 0x0C00B8, "Eject"},
    {0x0C00B9, 0x0C00B9, "Random Play"},
    {0x0C00BA, 0x0C00BA, "Select Disc"},
    {0x0C00BB, 0x0C00BB, "Enter Disc"},
    {0x0C00BC, 0x0C00BC, "Repeat"},
    {0x0C00BD, 0x0C00BD, "Tracking"},
    {0x0C00BE, 0x0C00BE, "Track Normal"},
    {0x0C00BF, 0x0C00BF, "Slow Tracking"},
    {0x0C00C0, 0x0C00C0, "Frame Forward"},
    {0x0C00C1, 0x0C00C1, "Frame Back"},
    {0x0C00C2, 0x0C00C2, "Mark"},
    {0x0C00C3, 0x0C00C3, "Clear Mark"},
    {0x0C00C4, 0x0C00C4, "Repeat From Mark"},
    {0x0C00C5, 0x0C00C5, "Return To Mark"},
    {0x0C00C6, 0x0C00C6, "Search Mark Forward"},
    {0x0C00C7, 0x0C00C7, "Search Mark Backwards"},
    {0x0C00C8, 0x0C00C8, "Counter Reset"},
    {0x0C00C9, 0x0C00C9, "Show Counter"},
    {0x0C00CA, 0x0C00CA, "Tracking Increment"},
    {0x0C00CB, 0x0C00CB, "Tracking Decrement"},
    {0x0C00CC, 0x0C00CC, "Stop/Eject"},
    {0x0C00CD, 0x0C00CD, "Play/Pause"},
    {0x0C00CE, 0x0C00CE, "Play/Skip"},
    {0x0C00CF, 0x0C00DF, "Reserved"},
    {0x0C00E0, 0x0C00E0, "Volume"},
    {0x0C00E1, 0x0C00E1, "Balance"},
    {0x0C00E2, 0x0C00E2, "Mute"},
    {0x0C00E3, 0x0C00E3, "Bass"},
    {0x0C00E4, 0x0C00E4, "Treble"},
    {0x0C00E5, 0x0C00E5, "Bass Boost"},
    {0x0C00E6, 0x0C00E6, "Surround Mode"},
    {0x0C00E7, 0x0C00E7, "Loudness"},
    {0x0C00E8, 0x0C00E8, "MPX"},
    {0x0C00E9, 0x0C00E9, "Volume Increment"},
    {0x0C00EA, 0x0C00EA, "Volume Decrement"},
    {0x0C00EB, 0x0C00EF, "Reserved"},
    {0x0C00F0, 0x0C00F0, "Speed Select"},
    {0x0C00F1, 0x0C00F1, "Playback Speed"},
    {0x0C00F2, 0x0C00F2, "Standard Play"},
    {0x0C00F3, 0x0C00F3, "Long Play"},
    {0x0C00F4, 0x0C00F4, "Extended Play"},
    {0x0C00F5, 0x0C00F5, "Slow"},
    {0x0C00F6, 0x0C00FF, "Reserved"},
    {0x0C0100, 0x0C0100, "Fan Enable"},
    {0x0C0101, 0x0C0101, "Fan Speed"},
    {0x0C0102, 0x0C0102, "Light Enable"},
    {0x0C0103, 0x0C0103, "Light Illumination Level"},
    {0x0C0104, 0x0C0104, "Climate Control Enable"},
    {0x0C0105, 0x0C0105, "Room Temperature"},
    {0x0C0106, 0x0C0106, "Security Enable"},
    {0x0C0107, 0x0C0107, "Fire Alarm"},
    {0x0C0108, 0x0C0108, "Police Alarm"},
    {0x0C0109, 0x0C0109, "Proximity"},
    {0x0C010A, 0x0C010A, "Motion"},
    {0x0C010B, 0x0C010B, "Duress Alarm"},
    {0x0C010C, 0x0C010C, "Holdup Alarm"},
    {0x0C010D, 0x0C010D, "Medical Alarm"},
    {0x0C010E, 0x0C014F, "Reserved"},
    {0x0C0150, 0x0C0150, "Balance Right"},
    {0x0C0151, 0x0C0151, "Balance Left"},
    {0x0C0152, 0x0C0152, "Bass Increment"},
    {0x0C0153, 0x0C0153, "Bass Decrement"},
    {0x0C0154, 0x0C0154, "Treble Increment"},
    {0x0C0155, 0x0C0155, "Treble Decrement"},
    {0x0C0156, 0x0C015F, "Reserved"},
    {0x0C0160, 0x0C0160, "Speaker System"},
    {0x0C0161, 0x0C0161, "Channel Left"},
    {0x0C0162, 0x0C0162, "Channel Right"},
    {0x0C0163, 0x0C0163, "Channel Center"},
    {0x0C0164, 0x0C0164, "Channel Front"},
    {0x0C0165, 0x0C0165, "Channel Center Front"},
    {0x0C0166, 0x0C0166, "Channel Side"},
    {0x0C0167, 0x0C0167, "Channel Surround"},
    {0x0C0168, 0x0C0168, "Channel Low Frequency Enhancement"},
    {0x0C0169, 0x0C0169, "Channel Top"},
    {0x0C016A, 0x0C016A, "Channel Unknown"},
    {0x0C016B, 0x0C016F, "Reserved"},
    {0x0C0170, 0x0C0170, "Sub-channel"},
    {0x0C0171, 0x0C0171, "Sub-channel Increment"},
    {0x0C0172, 0x0C0172, "Sub-channel Decrement"},
    {0x0C0173, 0x0C0173, "Alternate Audio Increment"},
    {0x0C0174, 0x0C0174, "Alternate Audio Decrement"},
    {0x0C0175, 0x0C017F, "Reserved"},
    {0x0C0180, 0x0C0180, "Application Launch Buttons"},
    {0x0C0181, 0x0C0181, "AL Launch Button Configuration Tool"},
    {0x0C0182, 0x0C0182, "AL Programmable Button Configuration"},
    {0x0C0183, 0x0C0183, "AL Consumer Control Configuration"},
    {0x0C0184, 0x0C0184, "AL Word Processor"},
    {0x0C0185, 0x0C0185, "AL Text Editor"},
    {0x0C0186, 0x0C0186, "AL Spreadsheet"},
    {0x0C0187, 0x0C0187, "AL Graphics Editor"},
    {0x0C0188, 0x0C0188, "AL Presentation App"},
    {0x0C0189, 0x0C0189, "AL Database App"},
    {0x0C018A, 0x0C018A, "AL Email Reader"},
    {0x0C018B, 0x0C018B, "AL Newsreader"},
    {0x0C018C, 0x0C018C, "AL Voicemail"},
    {0x0C018D, 0x0C018D, "AL Contacts/Address Book"},
    {0x0C018E, 0x0C018E, "AL Calendar/Schedule"},
    {0x0C018F, 0x0C018F, "AL Task/Project Manager"},
    {0x0C0190, 0x0C0190, "AL Log/Journal/Timecard"},
    {0x0C0191, 0x0C0191, "AL Checkbook/Finance"},
    {0x0C0192, 0x0C0192, "AL Calculator"},
    {0x0C0193, 0x0C0193, "AL A/V Capture/Playback"},
    {0x0C0194, 0x0C0194, "AL Local Machine Browser"},
    {0x0C0195, 0x0C0195, "AL LAN/WAN Browser"},
    {0x0C0196, 0x0C0196, "AL Internet Browser"},
    {0x0C0197, 0x0C0197, "AL Remote Networking/ISP Connect"},
    {0x0C0198, 0x0C0198, "AL Network Conference"},
    {0x0C0199, 0x0C0199, "AL Network Chat"},
    {0x0C019A, 0x0C019A, "AL Telephony/Dialer"},
    {0x0C019B, 0x0C019B, "AL Logon"},
    {0x0C019C, 0x0C019C, "AL Logoff"},
    {0x0C019D, 0x0C019D, "AL Logon/Logoff"},
    {0x0C019E, 0x0C019E, "AL Terminal Lock/Screensaver"},
    {0x0C019F, 0x0C019F, "AL Control Panel"},
    {0x0C01A0, 0x0C01A0, "AL Command Line Processor/Run"},
    {0x0C01A1, 0x0C01A1, "AL Process/Task Manager"},
    {0x0C01A2, 0x0C01A2, "AL Select Task/Application"},
    {0x0C01A3, 0x0C01A3, "AL Next Task/Application"},
    {0x0C01A4, 0x0C01A4, "AL Previous Task/Application"},
    {0x0C01A5, 0x0C01A5, "AL Preemptive Halt Task/Application"},
    {0x0C01A6, 0x0C01A6, "AL Integrated Help Center"},
    {0x0C01A7, 0x0C01A7, "AL Documents"},
    {0x0C01A8, 0x0C01A8, "AL Thesaurus"},
    {0x0C01A9, 0x0C01A9, "AL Dictionary"},
    {0x0C01AA, 0x0C01AA, "AL Desktop"},
    {0x0C01AB, 0x0C01AB, "AL Spell Check"},
    {0x0C01AC, 0x0C01AC, "AL Grammar Check"},
    {0x0C01AD, 0x0C01AD, "AL Wireless Status"},
    {0x0C01AE, 0x0C01AE, "AL Keyboard Layout"},
    {0x0C01AF, 0x0C01AF, "AL Virus Protection"},
    {0x0C01B0, 0x0C01B0, "AL Encryption"},
    {0x0C01B1, 0x0C01B1, "AL Screen Saver"},
    {0x0C01B2, 0x0C01B2, "AL Alarms"},
    {0x0C01B3, 0x0C01B3, "AL Clock"},
    {0x0C01B4, 0x0C01B4, "AL File Browser"},
    {0x0C01B5, 0x0C01B5, "AL Power Status"},
    {0x0C01B6, 0x0C01B6, "AL Image Browser"},
    {0x0C01B7, 0x0C01B7, "AL Audio Browser"},
    {0x0C01B8, 0x0C01B8, "AL Movie Browser"},
    {0x0C01B9, 0x0C01B9, "AL Digital Rights Manager"},
    {0x0C01BA, 0x0C01BA, "AL Digital Wallet"},
    {0x0C01BB, 0x0C01BB, "Reserved"},
    {0x0C01BC, 0x0C01BC, "AL Instant Messaging"},
    {0x0C01BD, 0x0C01BD, "AL OEM Features/ Tips/Tutorial Browser"},
    {0x0C01BE, 0x0C01BE, "AL OEM Help"},
    {0x0C01BF, 0x0C01BF, "AL Online Community"},
    {0x0C01C0, 0x0C01C0, "AL Entertainment Content Browser"},
    {0x0C01C1, 0x0C01C1, "AL Online Shopping Browser"},
    {0x0C01C2, 0x0C01C2, "AL SmartCard Information/Help"},
    {0x0C01C3, 0x0C01C3, "AL Market Monitor/Finance Browser"},
    {0x0C01C4, 0x0C01C4, "AL Customized Corporate News Browser"},
    {0x0C01C5, 0x0C01C5, "AL Online Activity Browser"},
    {0x0C01C6, 0x0C01C6, "AL Research/Search Browser"},
    {0x0C01C7, 0x0C01C7, "AL Audio Player"},
    {0x0C01C8, 0x0C01FF, "Reserved"},
    {0x0C0200, 0x0C0200, "Generic GUI Application Controls"},
    {0x0C0201, 0x0C0201, "AC New"},
    {0x0C0202, 0x0C0202, "AC Open"},
    {0x0C0203, 0x0C0203, "AC Close"},
    {0x0C0204, 0x0C0204, "AC Exit"},
    {0x0C0205, 0x0C0205, "AC Maximize"},
    {0x0C0206, 0x0C0206, "AC Minimize"},
    {0x0C0207, 0x0C0207, "AC Save"},
    {0x0C0208, 0x0C0208, "AC Print"},
    {0x0C0209, 0x0C0209, "AC Properties"},
    {0x0C020A, 0x0C0219, "[Undefined]"},
    {0x0C021A, 0x0C021A, "AC Undo"},
    {0x0C021B, 0x0C021B, "AC Copy"},
    {0x0C021C, 0x0C021C, "AC Cut"},
    {0x0C021D, 0x0C021D, "AC Paste"},
    {0x0C021E, 0x0C021E, "AC Select All"},
    {0x0C021F, 0x0C021F, "AC Find"},
    {0x0C0220, 0x0C0220, "AC Find and Replace"},
    {0x0C0221, 0x0C0221, "AC Search"},
    {0x0C0222, 0x0C0222, "AC Go To"},
    {0x0C0223, 0x0C0223, "AC Home"},
    {0x0C0224, 0x0C0224, "AC Back"},
    {0x0C0225, 0x0C0225, "AC Forward"},
    {0x0C0226, 0x0C0226, "AC Stop"},
    {0x0C0227, 0x0C0227, "AC Refresh"},
    {0x0C0228, 0x0C0228, "AC Previous Link"},
    {0x0C0229, 0x0C0229, "AC Next Link"},
    {0x0C022A, 0x0C022A, "AC Bookmarks"},
    {0x0C022B, 0x0C022B, "AC History"},
    {0x0C022C, 0x0C022C, "AC Subscriptions"},
    {0x0C022D, 0x0C022D, "AC Zoom In"},
    {0x0C022E, 0x0C022E, "AC Zoom Out"},
    {0x0C022F, 0x0C022F, "AC Zoom"},
    {0x0C0230, 0x0C0230, "AC Full Screen View"},
    {0x0C0231, 0x0C0231, "AC Normal View"},
    {0x0C0232, 0x0C0232, "AC View Toggle"},
    {0x0C0233, 0x0C0233, "AC Scroll Up"},
    {0x0C0234, 0x0C0234, "AC Scroll Down"},
    {0x0C0235, 0x0C0235, "AC Scroll"},
    {0x0C0236, 0x0C0236, "AC Pan Left"},
    {0x0C0237, 0x0C0237, "AC Pan Right"},
    {0x0C0238, 0x0C0238, "AC Pan"},
    {0x0C0239, 0x0C0239, "AC New Window"},
    {0x0C023A, 0x0C023A, "AC Tile Horizontally"},
    {0x0C023B, 0x0C023B, "AC Tile Vertically"},
    {0x0C023C, 0x0C023C, "AC Format"},
    {0x0C023D, 0x0C023D, "AC Edit"},
    {0x0C023E, 0x0C023E, "AC Bold"},
    {0x0C023F, 0x0C023F, "AC Italics"},
    {0x0C0240, 0x0C0240, "AC Underline"},
    {0x0C0241, 0x0C0241, "AC Strikethrough"},
    {0x0C0242, 0x0C0242, "AC Subscript"},
    {0x0C0243, 0x0C0243, "AC Superscript"},
    {0x0C0244, 0x0C0244, "AC All Caps"},
    {0x0C0245, 0x0C0245, "AC Rotate"},
    {0x0C0246, 0x0C0246, "AC Resize"},
    {0x0C0247, 0x0C0247, "AC Flip horizontal"},
    {0x0C0248, 0x0C0248, "AC Flip Vertical"},
    {0x0C0249, 0x0C0249, "AC Mirror Horizontal"},
    {0x0C024A, 0x0C024A, "AC Mirror Vertical"},
    {0x0C024B, 0x0C024B, "AC Font Select"},
    {0x0C024C, 0x0C024C, "AC Font Color"},
    {0x0C024D, 0x0C024D, "AC Font Size"},
    {0x0C024E, 0x0C024E, "AC Justify Left"},
    {0x0C024F, 0x0C024F, "AC Justify Center H"},
    {0x0C0250, 0x0C0250, "AC Justify Right"},
    {0x0C0251, 0x0C0251, "AC Justify Block H"},
    {0x0C0252, 0x0C0252, "AC Justify Top"},
    {0x0C0253, 0x0C0253, "AC Justify Center V"},
    {0x0C0254, 0x0C0254, "AC Justify Bottom"},
    {0x0C0255, 0x0C0255, "AC Justify Block V"},
    {0x0C0256, 0x0C0256, "AC Indent Decrease"},
    {0x0C0257, 0x0C0257, "AC Indent Increase"},
    {0x0C0258, 0x0C0258, "AC Numbered List"},
    {0x0C0259, 0x0C0259, "AC Restart Numbering"},
    {0x0C025A, 0x0C025A, "AC Bulleted List"},
    {0x0C025B, 0x0C025B, "AC Promote"},
    {0x0C025C, 0x0C025C, "AC Demote"},
    {0x0C025D, 0x0C025D, "AC Yes"},
    {0x0C025E, 0x0C025E, "AC No"},
    {0x0C025F, 0x0C025F, "AC Cancel"},
    {0x0C0260, 0x0C0260, "AC Catalog"},
    {0x0C0261, 0x0C0261, "AC Buy/Checkout"},
    {0x0C0262, 0x0C0262, "AC Add to Cart"},
    {0x0C0263, 0x0C0263, "AC Expand"},
    {0x0C0264, 0x0C0264, "AC Expand All"},
    {0x0C0265, 0x0C0265, "AC Collapse"},
    {0x0C0266, 0x0C0266, "AC Collapse All"},
    {0x0C0267, 0x0C0267, "AC Print Preview"},
    {0x0C0268, 0x0C0268, "AC Paste Special"},
    {0x0C0269, 0x0C0269, "AC Insert Mode"},
    {0x0C026A, 0x0C026A, "AC Delete"},
    {0x0C026B, 0x0C026B, "AC Lock"},
    {0x0C026C, 0x0C026C, "AC Unlock"},
    {0x0C026D, 0x0C026D, "AC Protect"},
    {0x0C026E, 0x0C026E, "AC Unprotect"},
    {0x0C026F, 0x0C026F, "AC Attach Comment"},
    {0x0C0270, 0x0C0270, "AC Delete Comment"},
    {0x0C0271, 0x0C0271, "AC View Comment"},
    {0x0C0272, 0x0C0272, "AC Select Word"},
    {0x0C0273, 0x0C0273, "AC Select Sentence"},
    {0x0C0274, 0x0C0274, "AC Select Paragraph"},
    {0x0C0275, 0x0C0275, "AC Select Column"},
    {0x0C0276, 0x0C0276, "AC Select Row"},
    {0x0C0277, 0x0C0277, "AC Select Table"},
    {0x0C0278, 0x0C0278, "AC Select Object"},
    {0x0C0279, 0x0C0279, "AC Redo/Repeat"},
    {0x0C027A, 0x0C027A, "AC Sort"},
    {0x0C027B, 0x0C027B, "AC Sort Ascending"},
    {0x0C027C, 0x0C027C, "AC Sort Descending"},
    {0x0C027D, 0x0C027D, "AC Filter"},
    {0x0C027E, 0x0C027E, "AC Set Clock"},
    {0x0C027F, 0x0C027F, "AC View Clock"},
    {0x0C0280, 0x0C0280, "AC Select Time Zone"},
    {0x0C0281, 0x0C0281, "AC Edit Time Zones"},
    {0x0C0282, 0x0C0282, "AC Set Alarm"},
    {0x0C0283, 0x0C0283, "AC Clear Alarm"},
    {0x0C0284, 0x0C0284, "AC Snooze Alarm"},
    {0x0C0285, 0x0C0285, "AC Reset Alarm"},
    {0x0C0286, 0x0C0286, "AC Synchronize"},
    {0x0C0287, 0x0C0287, "AC Send/Receive"},
    {0x0C0288, 0x0C0288, "AC Send To"},
    {0x0C0289, 0x0C0289, "AC Reply"},
    {0x0C028A, 0x0C028A, "AC Reply All"},
    {0x0C028B, 0x0C028B, "AC Forward Msg"},
    {0x0C028C, 0x0C028C, "AC Send"},
    {0x0C028D, 0x0C028D, "AC Attach File"},
    {0x0C028E, 0x0C028E, "AC Upload"},
    {0x0C028F, 0x0C028F, "AC Download (Save Target As)"},
    {0x0C0290, 0x0C0290, "AC Set Borders"},
    {0x0C0291, 0x0C0291, "AC Insert Row"},
    {0x0C0292, 0x0C0292, "AC Insert Column"},
    {0x0C0293, 0x0C0293, "AC Insert File"},
    {0x0C0294, 0x0C0294, "AC Insert Picture"},
    {0x0C0295, 0x0C0295, "AC Insert Object"},
    {0x0C0296, 0x0C0296, "AC Insert Symbol"},
    {0x0C0297, 0x0C0297, "AC Save and Close"},
    {0x0C0298, 0x0C0298, "AC Rename"},
    {0x0C0299, 0x0C0299, "AC Merge"},
    {0x0C029A, 0x0C029A, "AC Split"},
    {0x0C029B, 0x0C029B, "AC Disribute Horizontally"},
    {0x0C029C, 0x0C029C, "AC Distribute Vertically"},
    {0x0C029D, 0x0CFFFF, "Reserved"},

    // Digitizer
    {0x0D0000, 0x0D0000, "Undefined"},
    {0x0D0001, 0x0D0001, "Digitizer"},
    {0x0D0002, 0x0D0002, "Pen"},
    {0x0D0003, 0x0D0003, "Light Pen"},
    {0x0D0004, 0x0D0004, "Touch Screen"},
    {0x0D0005, 0x0D0005, "Touch Pad"},
    {0x0D0006, 0x0D0006, "White Board"},
    {0x0D0007, 0x0D0007, "Coordinate Measuring Machine"},
    {0x0D0008, 0x0D0008, "3D Digitizer"},
    {0x0D0009, 0x0D0009, "Stereo Plotter"},
    {0x0D000A, 0x0D000A, "Articulated Arm"},
    {0x0D000B, 0x0D000B, "Armature"},
    {0x0D000C, 0x0D000C, "Multiple Point Digitizer"},
    {0x0D000D, 0x0D000D, "Free Space Wand"},
    {0x0D000E, 0x0D001F, "Reserved"},
    {0x0D0020, 0x0D0020, "Stylus"},
    {0x0D0021, 0x0D0021, "Puck"},
    {0x0D0022, 0x0D0022, "Finger"},
    {0x0D0023, 0x0D002F, "Reserved"},
    {0x0D0030, 0x0D0030, "Tip Pressure"},
    {0x0D0031, 0x0D0031, "Barrel Pressure"},
    {0x0D0032, 0x0D0032, "In Range"},
    {0x0D0033, 0x0D0033, "Touch"},
    {0x0D0034, 0x0D0034, "Untouch"},
    {0x0D0035, 0x0D0035, "Tap"},
    {0x0D0036, 0x0D0036, "Quality"},
    {0x0D0037, 0x0D0037, "Data Valid"},
    {0x0D0038, 0x0D0038, "Transducer Index"},
    {0x0D0039, 0x0D0039, "Tablet Function Keys"},
    {0x0D003A, 0x0D003A, "Program Change Keys"},
    {0x0D003B, 0x0D003B, "Battery Strength"},
    {0x0D003C, 0x0D003C, "Invert"},
    {0x0D003D, 0x0D003D, "X Tilt"},
    {0x0D003E, 0x0D003E, "Y Tilt"},
    {0x0D003F, 0x0D003F, "Azimuth"},
    {0x0D0040, 0x0D0040, "Altitude"},
    {0x0D0041, 0x0D0041, "Twist"},
    {0x0D0042, 0x0D0042, "Tip Switch"},
    {0x0D0043, 0x0D0043, "Secondary Tip Switch"},
    {0x0D0044, 0x0D0044, "Barrel Switch"},
    {0x0D0045, 0x0D0045, "Eraser"},
    {0x0D0046, 0x0D0046, "Tablet Pick"},
    {0x0D0047, 0x0DFFFF, "Reserved"},

    {0x0E0000, 0x0EFFFF, "[Reserved]"},

    // Physical Interface Device (PID) page
    {0x0F0000, 0x0F0000, "Undefined"},
    {0x0F0001, 0x0F0001, "Physical Interface Device"},
    {0x0F0002, 0x0F001F, "Reserved"},
    {0x0F0020, 0x0F0020, "Normal"},
    {0x0F0021, 0x0F0021, "Set Effect Report"},
    {0x0F0022, 0x0F0022, "Effect Block Index"},
    {0x0F0023, 0x0F0023, "Parameter Block Offset"},
    {0x0F0024, 0x0F0024, "ROM Flag"},
    {0x0F0025, 0x0F0025, "Effect Type"},
    {0x0F0026, 0x0F0026, "ET Constant Force"},
    {0x0F0027, 0x0F0027, "ET Ramp"},
    {0x0F0028, 0x0F0028, "ET Custom Force Data"},
    {0x0F0029, 0x0F002F, "Reserved"},
    {0x0F0030, 0x0F0030, "ET Square"},
    {0x0F0031, 0x0F0031, "ET Sine"},
    {0x0F0032, 0x0F0032, "ET Triangle"},
    {0x0F0033, 0x0F0033, "ET Sawtooth Up"},
    {0x0F0034, 0x0F0034, "ET Sawtooth Down"},
    {0x0F0035, 0x0F003F, "Reserved"},
    {0x0F0040, 0x0F0040, "ET Spring"},
    {0x0F0041, 0x0F0041, "ET Damper"},
    {0x0F0042, 0x0F0042, "ET Inertia"},
    {0x0F0043, 0x0F0043, "ET Friction"},
    {0x0F0044, 0x0F004F, "Reserved"},
    {0x0F0050, 0x0F0050, "Duration"},
    {0x0F0051, 0x0F0051, "Sample Period"},
    {0x0F0052, 0x0F0052, "Gain"},
    {0x0F0053, 0x0F0053, "Trigger Button"},
    {0x0F0054, 0x0F0054, "Trigger Repeat Interval"},
    {0x0F0055, 0x0F0055, "Axes Enable"},
    {0x0F0056, 0x0F0056, "Direction Enable"},
    {0x0F0057, 0x0F0057, "Direction"},
    {0x0F0058, 0x0F0058, "Type Specific Block Offset"},
    {0x0F0059, 0x0F0059, "Block Type"},
    {0x0F005A, 0x0F005A, "Set Envelope Report"},
    {0x0F005B, 0x0F005B, "Attack Level"},
    {0x0F005C, 0x0F005C, "Attack Time"},
    {0x0F005D, 0x0F005D, "Fade Level"},
    {0x0F005E, 0x0F005E, "Fade Time"},
    {0x0F005F, 0x0F005F, "Set Condition Report"},
    {0x0F0060, 0x0F0060, "CP Offset"},
    {0x0F0061, 0x0F0061, "Positive Coefficient"},
    {0x0F0062, 0x0F0062, "Negative Coefficient"},
    {0x0F0063, 0x0F0063, "Positive Saturation"},
    {0x0F0064, 0x0F0064, "Negative Saturation"},
    {0x0F0065, 0x0F0065, "Dead Band"},
    {0x0F0066, 0x0F0066, "Download Force Sample"},
    {0x0F0067, 0x0F0067, "Isoch Custom Force Enable"},
    {0x0F0068, 0x0F0068, "Custom Force Data Report"},
    {0x0F0069, 0x0F0069, "Custom Force Data"},
    {0x0F006A, 0x0F006A, "Custom Force Vendor Defined Data"},
    {0x0F006B, 0x0F006B, "Set Custom Force Report"},
    {0x0F006C, 0x0F006C, "Custom Force Data Offset"},
    {0x0F006D, 0x0F006D, "Sample Count"},
    {0x0F006E, 0x0F006E, "Set Periodic Report"},
    {0x0F006F, 0x0F006F, "Offset"},
    {0x0F0070, 0x0F0070, "Magnitude"},
    {0x0F0071, 0x0F0071, "Phase"},
    {0x0F0072, 0x0F0072, "Period"},
    {0x0F0073, 0x0F0073, "Set Constant Force Report"},
    {0x0F0074, 0x0F0074, "Set Ramp Force Report"},
    {0x0F0075, 0x0F0075, "Ramp Start"},
    {0x0F0076, 0x0F0076, "Ramp End"},
    {0x0F0077, 0x0F0077, "Effect Operation Report"},
    {0x0F0078, 0x0F0078, "Effect Operation"},
    {0x0F0079, 0x0F0079, "Op Effect Start"},
    {0x0F007A, 0x0F007A, "Op Effect Start Solo"},
    {0x0F007B, 0x0F007B, "Op Effect Stop"},
    {0x0F007C, 0x0F007C, "Loop Count"},
    {0x0F007D, 0x0F007D, "Device Gain Report"},
    {0x0F007E, 0x0F007E, "Device Gain"},
    {0x0F007F, 0x0F007F, "PID Pool Report"},
    {0x0F0080, 0x0F0080, "RAM Pool Size"},
    {0x0F0081, 0x0F0081, "ROM Pool Size"},
    {0x0F0082, 0x0F0082, "ROM Effect Block Count"},
    {0x0F0083, 0x0F0083, "Simultaneous Effects Max"},
    {0x0F0084, 0x0F0084, "Pool Alignment"},
    {0x0F0085, 0x0F0085, "PID Pool Move Report"},
    {0x0F0086, 0x0F0086, "Move Source"},
    {0x0F0087, 0x0F0087, "Move Destination"},
    {0x0F0088, 0x0F0088, "Move Length"},
    {0x0F0089, 0x0F0089, "PID Block Load Report"},
    {0x0F008A, 0x0F008A, "Reserved"},
    {0x0F008B, 0x0F008B, "Block Load Status"},
    {0x0F008C, 0x0F008C, "Block Load Success"},
    {0x0F008D, 0x0F008D, "Block Load Full"},
    {0x0F008E, 0x0F008E, "Block Load Error"},
    {0x0F008F, 0x0F008F, "Block Handle"},
    {0x0F0090, 0x0F0090, "PID Block Free Report"},
    {0x0F0091, 0x0F0091, "Type Specific Block Handle"},
    {0x0F0092, 0x0F0092, "PID State Report"},
    {0x0F0093, 0x0F0093, "Reserved"},
    {0x0F0094, 0x0F0094, "Effect Playing"},
    {0x0F0095, 0x0F0095, "PID Device Control Report"},
    {0x0F0096, 0x0F0096, "PID Device Control"},
    {0x0F0097, 0x0F0097, "DC Enable Actuators"},
    {0x0F0098, 0x0F0098, "DC Disable Actuators"},
    {0x0F0099, 0x0F0099, "DC Stop All Effects"},
    {0x0F009A, 0x0F009A, "DC Device Reset"},
    {0x0F009B, 0x0F009B, "DC Device Pause"},
    {0x0F009C, 0x0F009C, "DC Device Continue"},
    {0x0F009D, 0x0F009D, "Reserved"},
    {0x0F009E, 0x0F009E, "Reserved"},
    {0x0F009F, 0x0F009F, "Device Paused"},
    {0x0F00A0, 0x0F00A0, "Actuators Enabled"},
    {0x0F00A1, 0x0F00A3, "Reserved"},
    {0x0F00A4, 0x0F00A4, "Safety Switch"},
    {0x0F00A5, 0x0F00A5, "Actuator Override Switch"},
    {0x0F00A6, 0x0F00A6, "Actuator Power"},
    {0x0F00A7, 0x0F00A7, "Start Delay"},
    {0x0F00A8, 0x0F00A8, "Parameter Block Size"},
    {0x0F00A9, 0x0F00A9, "Device Managed Pool"},
    {0x0F00AA, 0x0F00AA, "Shared Parameter Blocks"},
    {0x0F00AB, 0x0F00AB, "Create New Effect Report"},
    {0x0F00AC, 0x0F00AC, "RAM Pool Available"},
    {0x0F00AD, 0x0FFFFF, "Reserved"},

    {0x100000, 0x10FFFF, "Unicode Page"},
    {0x110000, 0x13FFFF, "[Reserved]"},

    // Alphanumeric display
    {0x140000, 0x140000, "Undefined"},
    {0x140001, 0x140001, "Alphanumeric Display"},
    {0x140002, 0x140002, "Bitmapped Display"},
    {0x140003, 0x14001F, "Reserved"},
    {0x140020, 0x140020, "Display Attributes Report"},
    {0x140021, 0x140021, "ASCII Character Set"},
    {0x140022, 0x140022, "Data Read Back"},
    {0x140023, 0x140023, "Font Read Back"},
    {0x140024, 0x140024, "Display Control Report"},
    {0x140025, 0x140025, "Clear Display"},
    {0x140026, 0x140026, "Display Enable"},
    {0x140027, 0x140027, "Screen Saver Delay"},
    {0x140028, 0x140028, "Screen Saver Enable"},
    {0x140029, 0x140029, "Vertical Scroll"},
    {0x14002A, 0x14002A, "Horizontal Scroll"},
    {0x14002B, 0x14002B, "Character Report"},
    {0x14002C, 0x14002C, "Display Data"},
    {0x14002D, 0x14002D, "Display Status"},
    {0x14002E, 0x14002E, "Stat Not Ready"},
    {0x14002F, 0x14002F, "Stat Ready"},
    {0x140030, 0x140030, "Err Not a loadable character"},
    {0x140031, 0x140031, "Err Font data cannot be read"},
    {0x140032, 0x140032, "Cursor Position Report"},
    {0x140033, 0x140033, "Row"},
    {0x140034, 0x140034, "Column"},
    {0x140035, 0x140035, "Rows"},
    {0x140036, 0x140036, "Columns"},
    {0x140037, 0x140037, "Cursor Pixel Positioning"},
    {0x140038, 0x140038, "Cursor Mode"},
    {0x140039, 0x140039, "Cursor Enable"},
    {0x14003A, 0x14003A, "Cursor Blink"},
    {0x14003B, 0x14003B, "Font Report"},
    {0x14003C, 0x14003C, "Font Data"},
    {0x14003D, 0x14003D, "Character Width"},
    {0x14003E, 0x14003E, "Character Height"},
    {0x14003F, 0x14003F, "Character Spacing Horizontal"},
    {0x140040, 0x140040, "Character Spacing Vertical"},
    {0x140041, 0x140041, "Unicode Character Set"},
    {0x140042, 0x140042, "Font 7-Segment"},
    {0x140043, 0x140043, "7-Segment Direct Map"},
    {0x140044, 0x140044, "Font 14-Segment"},
    {0x140045, 0x140045, "14-Segment Direct Map"},
    {0x140046, 0x140046, "Display Brightness"},
    {0x140047, 0x140047, "Display Contrast"},
    {0x140048, 0x140048, "Character Attribute"},
    {0x140049, 0x140049, "Attribute Readback"},
    {0x14004A, 0x14004A, "Attribute Data"},
    {0x14004B, 0x14004B, "Char Attr Enhance"},
    {0x14004C, 0x14004C, "Char Attr Underline"},
    {0x14004D, 0x14004D, "Char Attr Blink"},
    {0x14004E, 0x14007F, "Reserved"},
    {0x140080, 0x140080, "Bitmap Size X"},
    {0x140081, 0x140081, "Bitmap Size Y"},
    {0x140082, 0x140082, "Reserved"},
    {0x140083, 0x140083, "Bit Depth Format"},
    {0x140084, 0x140084, "Display Orientation"},
    {0x140085, 0x140085, "Palette Report"},
    {0x140086, 0x140086, "Palette Data Size"},
    {0x140087, 0x140087, "Palette Data Offset"},
    {0x140088, 0x140088, "Palette Data"},
    {0x140089, 0x140089, "[Undefined]"},
    {0x14008A, 0x14008A, "Blit Report"},
    {0x14008B, 0x14008B, "Blit Rectangle X1"},
    {0x14008C, 0x14008C, "Blit Rectangle Y1"},
    {0x14008D, 0x14008D, "Blit Rectangle X2"},
    {0x14008E, 0x14008E, "Blit Rectangle Y2"},
    {0x14008F, 0x14008F, "Blit Data"},
    {0x140090, 0x140090, "Soft Button"},
    {0x140091, 0x140091, "Soft Button ID"},
    {0x140092, 0x140092, "Soft Button Side"},
    {0x140093, 0x140093, "Soft Button Offset 1"},
    {0x140094, 0x140094, "Soft Button Offset 2"},
    {0x140095, 0x140095, "Soft Button Report"},
    {0x140096, 0x14FFFF, "Reserved"},

    {0x150000, 0x3FFFFF, "[Reserved]"},

    // Medical instruments
    {0x400000, 0x400000, "Undefined"},
    {0x400001, 0x400001, "Medical Ultrasound"},
    {0x400002, 0x40001F, "Reserved"},
    {0x400020, 0x400020, "VCR/Acquisition"},
    {0x400021, 0x400021, "Freeze/Thaw"},
    {0x400022, 0x400022, "Clip Store"},
    {0x400023, 0x400023, "Update"},
    {0x400024, 0x400024, "Next"},
    {0x400025, 0x400025, "Save"},
    {0x400026, 0x400026, "Print"},
    {0x400027, 0x400027, "Microphone Enable"},
    {0x400028, 0x40003F, "Reserved"},
    {0x400040, 0x400040, "Cine"},
    {0x400041, 0x400041, "Transmit Power"},
    {0x400042, 0x400042, "Volume"},
    {0x400043, 0x400043, "Focus"},
    {0x400044, 0x400044, "Depth"},
    {0x400045, 0x40005F, "Reserved"},
    {0x400060, 0x400060, "Soft Step - Primary"},
    {0x400061, 0x400061, "Soft Step - Secondary"},
    {0x400062, 0x40006F, "Reserved"},
    {0x400070, 0x400070, "Depth Gain Compensation"},
    {0x400071, 0x40007F, "Reserved"},
    {0x400080, 0x400080, "Zoom Select"},
    {0x400081, 0x400081, "Zoom Adjust"},
    {0x400082, 0x400082, "Spectral Doppler Mode Select"},
    {0x400083, 0x400083, "Spectral Doppler Adjust"},
    {0x400084, 0x400084, "Color Doppler Mode Select"},
    {0x400085, 0x400085, "Color Doppler Adjust"},
    {0x400086, 0x400086, "Motion Mode Select"},
    {0x400087, 0x400087, "Motion Mode Adjust"},
    {0x400088, 0x400088, "2-D Mode Select"},
    {0x400089, 0x400089, "2-D Mode Adjust"},
    {0x40008A, 0x40009F, "Reserved"},
    {0x4000A0, 0x4000A0, "Soft Control Select"},
    {0x4000A1, 0x4000A1, "Soft Control Adjust"},
    {0x4000A2, 0x40FFFF, "Reserved"},

    {0x410000, 0x7FFFFF, "[Reserved]"},

    // Monitor page
    // USB Monitor Usage Page
    {0x800000, 0x800000, "Reserved"},
    {0x800001, 0x800001, "Monitor Control"},
    {0x800002, 0x800002, "EDID Information"},
    {0x800003, 0x800003, "VDIF Information"},
    {0x800004, 0x800004, "VESA Version"},
    {0x800005, 0x80FFFF, "[Undefined]"},
    // Monitor Enumerated Values [Usage Page]
    {0x810000, 0x81FFFF, "ENUM_#"},
    // VESA Virtual Control Usage Page
    {0x820000, 0x820000, "Reserved"},
    {0x820001, 0x820001, "Degauss"},
    {0x820002, 0x82000F, "Reserved"},
    {0x820010, 0x820010, "Brightness"},
    {0x820011, 0x820011, "Reserved"},
    {0x820012, 0x820012, "Contrast"},
    {0x820013, 0x820015, "Reserved"},
    {0x820016, 0x820016, "Red Video Gain"},
    {0x820017, 0x820017, "Reserved"},
    {0x820018, 0x820018, "Green Video Gain"},
    {0x820019, 0x820019, "Reserved"},
    {0x82001A, 0x82001A, "Blue Video Gain"},
    {0x82001B, 0x82001B, "Reserved"},
    {0x82001C, 0x82001C, "Focus"},
    {0x82001D, 0x82001F, "Reserved"},
    {0x820020, 0x820020, "Horizontal Position"},
    {0x820021, 0x820021, "Reserved"},
    {0x820022, 0x820022, "Horizontal Size"},
    {0x820023, 0x820023, "Reserved"},
    {0x820024, 0x820024, "Horizontal Pincushion"},
    {0x820025, 0x820025, "Reserved"},
    {0x820026, 0x820026, "Horizontal Pincushion Balance"},
    {0x820027, 0x820027, "Reserved"},
    {0x820028, 0x820028, "Horizontal Misconvergence"},
    {0x820029, 0x820029, "Reserved"},
    {0x82002A, 0x82002A, "Horizontal Linearity"},
    {0x82002B, 0x82002B, "Reserved"},
    {0x82002C, 0x82002C, "Horizontal Linearity Balance"},
    {0x82002D, 0x82002F, "Reserved"},
    {0x820030, 0x820030, "Vertical Position"},
    {0x820031, 0x820031, "Reserved"},
    {0x820032, 0x820032, "Vertical Size"},
    {0x820033, 0x820033, "Reserved"},
    {0x820034, 0x820034, "Vertical Pincushion"},
    {0x820035, 0x820035, "Reserved"},
    {0x820036, 0x820036, "Vertical Pincushion Balance"},
    {0x820037, 0x820037, "Reserved"},
    {0x820038, 0x820038, "Vertical Misconvergence"},
    {0x820039, 0x820039, "Reserved"},
    {0x82003A, 0x82003A, "Vertical Linearity"},
    {0x82003B, 0x82003B, "Reserved"},
    {0x82003C, 0x82003C, "Vertical Linearity Balance"},
    {0x82003D, 0x82003F, "Reserved"},
    {0x820040, 0x820040, "Parallelogram Distortion (Key Balance)"},
    {0x820041, 0x820041, "Reserved"},
    {0x820042, 0x820042, "Trapezoidal Distortion (Key)"},
    {0x820043, 0x820043, "Reserved"},
    {0x820044, 0x820044, "Tilt (Rotation)"},
    {0x820045, 0x820045, "Reserved"},
    {0x820046, 0x820046, "Top Corner Distortion Control"},
    {0x820047, 0x820047, "Reserved"},
    {0x820048, 0x820048, "Top Corner Distortion Balance"},
    {0x820049, 0x820049, "Reserved"},
    {0x82004A, 0x82004A, "Bottom Corner Distortion Control"},
    {0x82004B, 0x82004B, "Reserved"},
    {0x82004C, 0x82004C, "Bottom Corner Distortion Balance"},
    {0x82004D, 0x820055, "Reserved"},
    {0x820056, 0x820056, "Horizontal Moire"},
    {0x820057, 0x820057, "Reserved"},
    {0x820058, 0x820058, "Vertical Moire"},
    {0x820059, 0x82005D, "Reserved"},
    {0x82005E, 0x82005E, "Input Level Select"},
    {0x82005F, 0x82005F, "Reserved"},
    {0x820060, 0x820060, "Input Source Select"},
    {0x820061, 0x82006B, "Reserved"},
    {0x82006C, 0x82006C, "Red Video Black Level"},
    {0x82006D, 0x82006D, "Reserved"},
    {0x82006E, 0x82006E, "Green Video Black Level"},
    {0x82006F, 0x82006F, "Reserved"},
    {0x820070, 0x820070, "Blue Video Black Level"},
    {0x820071, 0x8200A1, "Reserved"},
    {0x8200A2, 0x8200A2, "Auto Size Center"},
    {0x8200A3, 0x8200A3, "Reserved"},
    {0x8200A4, 0x8200A4, "Polarity Horizontal Synchronization"},
    {0x8200A5, 0x8200A5, "Reserved"},
    {0x8200A6, 0x8200A6, "Polarity Vertical Synchronization"},
    {0x8200A7, 0x8200A7, "Reserved"},
    {0x8200A8, 0x8200A8, "Synchronization Type"},
    {0x8200A9, 0x8200A9, "Reserved"},
    {0x8200AA, 0x8200AA, "Screen Orientation"},
    {0x8200AB, 0x8200AB, "Reserved"},
    {0x8200AC, 0x8200AC, "Horizontal Frequency"},
    {0x8200AD, 0x8200AD, "Reserved"},
    {0x8200AE, 0x8200AE, "Vertical Frequency"},
    {0x8200AF, 0x8200AF, "Reserved"},
    {0x8200B0, 0x8200B0, "Settings"},
    {0x8200B1, 0x8200C9, "Reserved"},
    {0x8200CA, 0x8200CA, "On Screen Display"},
    {0x8200CB, 0x8200D3, "Reserved"},
    {0x8200D4, 0x8200D4, "StereoMode"},
    {0x8200D5, 0x82FFFF, "Reserved"},
    // Monitor page Reserved
    {0x830000, 0x83FFFF, "Reserved"},

    // Power page
    // Power Device Page
    {0x840000, 0x840000, "Undefined"},
    {0x840001, 0x840001, "iName"},
    {0x840002, 0x840002, "PresentStatus"},
    {0x840003, 0x840003, "ChangedStatus"},
    {0x840004, 0x840004, "UPS"},
    {0x840005, 0x840005, "PowerSupply"},
    {0x840006, 0x84000F, "Reserved"},
    {0x840010, 0x840010, "BatterySystem"},
    {0x840011, 0x840011, "BatterySystemID"},
    {0x840012, 0x840012, "Battery"},
    {0x840013, 0x840013, "BatteryID"},
    {0x840014, 0x840014, "Charger"},
    {0x840015, 0x840015, "ChargerID"},
    {0x840016, 0x840016, "PowerConverter"},
    {0x840017, 0x840017, "PowerConverterID"},
    {0x840018, 0x840018, "OutletSystem"},
    {0x840019, 0x840019, "OutletSystemID"},
    {0x84001A, 0x84001A, "Input"},
    {0x84001B, 0x84001B, "InputID"},
    {0x84001C, 0x84001C, "Output"},
    {0x84001D, 0x84001D, "OutputID"},
    {0x84001E, 0x84001E, "Flow"},
    {0x84001F, 0x84001F, "FlowID"},
    {0x840020, 0x840020, "Outlet"},
    {0x840021, 0x840021, "OutletID"},
    {0x840022, 0x840022, "Gang"},
    {0x840023, 0x840023, "GangID"},
    {0x840024, 0x840024, "PowerSummary"},
    {0x840025, 0x840025, "PowerSummaryID"},
    {0x840026, 0x84002F, "Reserved"},
    {0x840030, 0x840030, "Voltage"},
    {0x840031, 0x840031, "Current"},
    {0x840032, 0x840032, "Frequency"},
    {0x840033, 0x840033, "ApparentPower"},
    {0x840034, 0x840034, "ActivePower"},
    {0x840035, 0x840035, "PercentLoad"},
    {0x840036, 0x840036, "Temperature"},
    {0x840037, 0x840037, "Humidity"},
    {0x840038, 0x840038, "BadCount"},
    {0x840039, 0x84003F, "Reserved"},
    {0x840040, 0x840040, "ConfigVoltage"},
    {0x840041, 0x840041, "ConfigCurrent"},
    {0x840042, 0x840042, "ConfigFrequency"},
    {0x840043, 0x840043, "ConfigApparentPower"},
    {0x840044, 0x840044, "ConfigActivePower"},
    {0x840045, 0x840045, "ConfigPercentLoad"},
    {0x840046, 0x840046, "ConfigTemperature"},
    {0x840047, 0x840047, "ConfigHumidity"},
    {0x840048, 0x84004F, "Reserved"},
    {0x840050, 0x840050, "SwitchOnControl"},
    {0x840051, 0x840051, "SwitchOffControl"},
    {0x840052, 0x840052, "ToggleControl"},
    {0x840053, 0x840053, "LowVoltageTransfer"},
    {0x840054, 0x840054, "HighVoltageTransfer"},
    {0x840055, 0x840055, "DelayBeforeReboot"},
    {0x840056, 0x840056, "DelayBeforeStartup"},
    {0x840057, 0x840057, "DelayBeforeShutdown"},
    {0x840058, 0x840058, "Test"},
    {0x840059, 0x840059, "ModuleReset"},
    {0x84005A, 0x84005A, "AudibleAlarmControl"},
    {0x84005B, 0x84005F, "Reserved"},
    {0x840060, 0x840060, "Present"},
    {0x840061, 0x840061, "Good"},
    {0x840062, 0x840062, "InternalFailure"},
    {0x840063, 0x840063, "VoltageOutOfRange"},
    {0x840064, 0x840064, "FrequencyOutOfRange"},
    {0x840065, 0x840065, "Overload"},
    {0x840066, 0x840066, "OverCharged"},
    {0x840067, 0x840067, "OverTemperature"},
    {0x840068, 0x840068, "ShutdownRequested"},
    {0x840069, 0x840069, "ShutdownImminent"},
    {0x84006A, 0x84006A, "Reserved"},
    {0x84006B, 0x84006B, "SwitchOn/Off"},
    {0x84006C, 0x84006C, "Switchable"},
    {0x84006D, 0x84006D, "Used"},
    {0x84006E, 0x84006E, "Boost"},
    {0x84006F, 0x84006F, "Buck"},
    {0x840070, 0x840070, "Initialized"},
    {0x840071, 0x840071, "Tested"},
    {0x840072, 0x840072, "AwaitingPower"},
    {0x840073, 0x840073, "CommunicationLost"},
    {0x840074, 0x8400FC, "Reserved"},
    {0x8400FD, 0x8400FD, "iManufacturer"},
    {0x8400FE, 0x8400FE, "iProduct"},
    {0x8400FF, 0x8400FF, "iserialNumber"},
    {0x840100, 0x84FEFF, "Reserved"},
    {0x84FF00, 0x84FFFF, "Vendor-specific"},
    // Battery System Page
    {0x850000, 0x850000, "Undefined"},
    {0x850001, 0x850001, "SMBBatteryMode"},
    {0x850002, 0x850002, "SMBBatteryStatus"},
    {0x850003, 0x850003, "SMBAlarmWarning"},
    {0x850004, 0x850004, "SMBChargerMode"},
    {0x850005, 0x850005, "SMBChargerStatus"},
    {0x850006, 0x850006, "SMBChargerSpecInfo"},
    {0x850007, 0x850007, "SMBSelectorState"},
    {0x850008, 0x850008, "SMBSelectorPresets"},
    {0x850009, 0x850009, "SMBSelectorInfo"},
    {0x85000A, 0x85000F, "Reserved"},
    {0x850010, 0x850010, "OptionalMfgFunction1"},
    {0x850011, 0x850011, "OptionalMfgFunction2"},
    {0x850012, 0x850012, "OptionalMfgFunction3"},
    {0x850013, 0x850013, "OptionalMfgFunction4"},
    {0x850014, 0x850014, "OptionalMfgFunction5"},
    {0x850015, 0x850015, "ConnectionToSMBus"},
    {0x850016, 0x850016, "OutputConnection"},
    {0x850017, 0x850017, "ChargerConnection"},
    {0x850018, 0x850018, "BatteryInsertion"},
    {0x850019, 0x850019, "Usenext"},
    {0x85001A, 0x85001A, "OKToUse"},
    {0x85001B, 0x85001B, "BatterySupported"},
    {0x85001C, 0x85001C, "SelectorRevision"},
    {0x85001D, 0x85001D, "ChargingIndicator"},
    {0x85001E, 0x850027, "Reserved"},
    {0x850028, 0x850028, "ManufacturerAccess"},
    {0x850029, 0x850029, "RemainingCapacityLimit"},
    {0x85002A, 0x85002A, "RemainingTimeLimit"},
    {0x85002B, 0x85002B, "AtRate"},
    {0x85002C, 0x85002C, "CapacityMode"},
    {0x85002D, 0x85002D, "BroadcastToCharger"},
    {0x85002E, 0x85002E, "PrimaryBattery"},
    {0x85002F, 0x85002F, "ChargeController"},
    {0x850030, 0x85003F, "Reserved"},
    {0x850040, 0x850040, "TerminateCharge"},
    {0x850041, 0x850041, "TerminateDischarge"},
    {0x850042, 0x850042, "BelowRemainingCapacityLimit"},
    {0x850043, 0x850043, "RemainingTimeLimitExpired"},
    {0x850044, 0x850044, "Charging"},
    {0x850045, 0x850045, "Discharging"},
    {0x850046, 0x850046, "FullyCharged"},
    {0x850047, 0x850047, "FullyDischarged"},
    {0x850048, 0x850048, "ConditioningFlag"},
    {0x850049, 0x850049, "AtRateOK"},
    {0x85004A, 0x85004A, "SMBErrorCode"},
    {0x85004B, 0x85004B, "NeedReplacement"},
    {0x85004C, 0x85005F, "Reserved"},
    {0x850060, 0x850060, "AtRateTimeToFull"},
    {0x850061, 0x850061, "AtRateTimeToEmpty"},
    {0x850062, 0x850062, "AverageCurrent"},
    {0x850063, 0x850063, "Maxerror"},
    {0x850064, 0x850064, "RelativeStateOfCharge"},
    {0x850065, 0x850065, "AbsoluteStateOfCharge"},
    {0x850066, 0x850066, "RemainingCapacity"},
    {0x850067, 0x850067, "FullChargeCapacity"},
    {0x850068, 0x850068, "RunTimeToEmpty"},
    {0x850069, 0x850069, "AverageTimeToEmpty"},
    {0x85006A, 0x85006A, "AverageTimeToFull"},
    {0x85006B, 0x85006B, "CycleCount"},
    {0x85006C, 0x85007F, "Reserved"},
    {0x850080, 0x850080, "BattPackModelLevel"},
    {0x850081, 0x850081, "InternalChargeController"},
    {0x850082, 0x850082, "PrimaryBatterySupport"},
    {0x850083, 0x850083, "DesignCapacity"},
    {0x850084, 0x850084, "SpecificationInfo"},
    {0x850085, 0x850085, "ManufacturerDate"},
    {0x850086, 0x850086, "SerialNumber"},
    {0x850087, 0x850087, "iManufacturerName"},
    {0x850088, 0x850088, "iDevicename"},
    {0x850089, 0x850089, "iDeviceChemistery"},
    {0x85008A, 0x85008A, "ManufacturerData"},
    {0x85008B, 0x85008B, "Rechargable"},
    {0x85008C, 0x85008C, "WarningCapacityLimit"},
    {0x85008D, 0x85008D, "CapacityGranularity1"},
    {0x85008E, 0x85008E, "CapacityGranularity2"},
    {0x85008F, 0x85008F, "iOEMInformation"},
    {0x850090, 0x8500BF, "Reserved"},
    {0x8500C0, 0x8500C0, "InhibitCharge"},
    {0x8500C1, 0x8500C1, "EnablePolling"},
    {0x8500C2, 0x8500C2, "ResetToZero"},
    {0x8500C3, 0x8500CF, "Reserved"},
    {0x8500D0, 0x8500D0, "ACPresent"},
    {0x8500D1, 0x8500D1, "BatteryPresent"},
    {0x8500D2, 0x8500D2, "PowerFail"},
    {0x8500D3, 0x8500D3, "AlarmInhibited"},
    {0x8500D4, 0x8500D4, "ThermistorUnderRange"},
    {0x8500D5, 0x8500D5, "ThermistorHot"},
    {0x8500D6, 0x8500D6, "ThermistorCold"},
    {0x8500D7, 0x8500D7, "ThermistorOverRange"},
    {0x8500D8, 0x8500D8, "VoltageOutOfRange"},
    {0x8500D9, 0x8500D9, "CurrentOutOfRange"},
    {0x8500DA, 0x8500DA, "CurrentNotRegulated"},
    {0x8500DB, 0x8500DB, "VoltageNotRegulated"},
    {0x8500DC, 0x8500DC, "MasterMode"},
    {0x8500DD, 0x8500EF, "Reserved"},
    {0x8500F0, 0x8500F0, "ChargerSelectorSupport"},
    {0x8500F1, 0x8500F1, "ChargerSpec"},
    {0x8500F2, 0x8500F2, "Level2"},
    {0x8500F3, 0x8500F3, "Level3"},
    {0x8500F4, 0x8500FF, "Reserved"},
    {0x850100, 0x85FEFF, "Reserved"},
    {0x85FF00, 0x85FFFF, "Vendor-specific"},
    // Power page reserved
    {0x860000, 0x87FFFF, "Reserved"},

    {0x880000, 0x8BFFFF, "[Reserved]"},

    // Bar code scanner page
    {0x8C0000, 0x8C0000, "Undefined"},
    {0x8C0001, 0x8C0001, "Bar Code Badge Reader"},
    {0x8C0002, 0x8C0002, "Bar Code Scanner"},
    {0x8C0003, 0x8C0003, "Dumb Bar Code Scanner"},
    {0x8C0004, 0x8C0004, "Cordless Scanner Base"},
    {0x8C0005, 0x8C0005, "Bar Code Scanner Cradle"},
    {0x8C0006, 0x8C000F, "Reserved"},
    {0x8C0010, 0x8C0010, "Attribute Report"},
    {0x8C0011, 0x8C0011, "Settings Report"},
    {0x8C0012, 0x8C0012, "Scanned Data Report"},
    {0x8C0013, 0x8C0013, "Raw Scanned Data Report"},
    {0x8C0014, 0x8C0014, "Trigger Report"},
    {0x8C0015, 0x8C0015, "Status Report"},
    {0x8C0016, 0x8C0016, "UPC/EAN Control Report"},
    {0x8C0017, 0x8C0017, "EAN 2/3 Label Control Report"},
    {0x8C0018, 0x8C0018, "Code 39 Control Report"},
    {0x8C0019, 0x8C0019, "Interleaved 2 of 5 Control Report"},
    {0x8C001A, 0x8C001A, "Standard 2 of 5 Control Report"},
    {0x8C001B, 0x8C001B, "MSI Plessey Control Report"},
    {0x8C001C, 0x8C001C, "Codabar Control Report"},
    {0x8C001D, 0x8C001D, "Code 128 Control Report"},
    {0x8C001E, 0x8C001E, "Misc 1D Control Report"},
    {0x8C001F, 0x8C001F, "2D Control Report"},
    {0x8C0020, 0x8C002F, "Reserved"},
    {0x8C0030, 0x8C0030, "Aiming/Pointer Mode"},
    {0x8C0031, 0x8C0031, "Bar Code Present Sensor"},
    {0x8C0032, 0x8C0032, "Class 1A Laser"},
    {0x8C0033, 0x8C0033, "Class 2 Laser"},
    {0x8C0034, 0x8C0034, "Heater Present"},
    {0x8C0035, 0x8C0035, "Contact Scanner"},
    {0x8C0036, 0x8C0036, "Electronic Article Surveillance Notification"},
    {0x8C0037, 0x8C0037, "Constant Electronic Article Surveillance"},
    {0x8C0038, 0x8C0038, "Error Indication"},
    {0x8C0039, 0x8C0039, "Fixed Beeper"},
    {0x8C003A, 0x8C003A, "Good Decode Indication"},
    {0x8C003B, 0x8C003B, "Hands Free Scanning"},
    {0x8C003C, 0x8C003C, "Intrinsically Safe"},
    {0x8C003D, 0x8C003D, "Klasse Eins Laser"},
    {0x8C003E, 0x8C003E, "Long Range Scanner"},
    {0x8C003F, 0x8C003F, "Mirror Speed Control"},
    {0x8C0040, 0x8C0040, "Not On File Indication"},
    {0x8C0041, 0x8C0041, "Programmable Beeper"},
    {0x8C0042, 0x8C0042, "Triggerless"},
    {0x8C0043, 0x8C0043, "Wand"},
    {0x8C0044, 0x8C0044, "Water Resistant"},
    {0x8C0045, 0x8C0045, "Multi-Range Scanner"},
    {0x8C0046, 0x8C0046, "Proximity Sensor"},
    {0x8C0047, 0x8C004C, "Reserved"},
    {0x8C004D, 0x8C004D, "Fragment Decoding"},
    {0x8C004E, 0x8C004E, "Scanner Read Confidence"},
    {0x8C004F, 0x8C004F, "Data Prefix"},
    {0x8C0050, 0x8C0050, "Prefix AIMI"},
    {0x8C0051, 0x8C0051, "Prefix None"},
    {0x8C0052, 0x8C0052, "Prefix Proprietary"},
    {0x8C0053, 0x8C0054, "Reserved"},
    {0x8C0055, 0x8C0055, "Active Time"},
    {0x8C0056, 0x8C0056, "Aiming Laser Pattern"},
    {0x8C0057, 0x8C0057, "Bar Code Present"},
    {0x8C0058, 0x8C0058, "Beeper State"},
    {0x8C0059, 0x8C0059, "Laser On Time"},
    {0x8C005A, 0x8C005A, "Laser State"},
    {0x8C005B, 0x8C005B, "Lockout Time"},
    {0x8C005C, 0x8C005C, "Motor State"},
    {0x8C005D, 0x8C005D, "Motor Timeout"},
    {0x8C005E, 0x8C005E, "Power On Reset Scanner"},
    {0x8C005F, 0x8C005F, "Prevent Read of Barcodes"},
    {0x8C0060, 0x8C0060, "Initiate Barcode Read"},
    {0x8C0061, 0x8C0061, "Trigger State"},
    {0x8C0062, 0x8C0062, "Trigger Mode"},
    {0x8C0063, 0x8C0063, "Trigger Mode Blinking Laser On"},
    {0x8C0064, 0x8C0064, "Trigger Mode Continuous Laser On"},
    {0x8C0065, 0x8C0065, "Trigger Mode Laser on while Pulled"},
    {0x8C0066, 0x8C0066, "Trigger Mode Laser stays on after Trigger release"},
    {0x8C0067, 0x8C006C, "Reserved"},
    {0x8C006D, 0x8C006D, "Commit Parameters to NVM"},
    {0x8C006E, 0x8C006E, "Parameter Scanning"},
    {0x8C006F, 0x8C006F, "Parameters Changed"},
    {0x8C0070, 0x8C0070, "Set parameter default values"},
    {0x8C0071, 0x8C0074, "Reserved"},
    {0x8C0075, 0x8C0075, "Scanner In Cradle"},
    {0x8C0076, 0x8C0076, "Scanner In Range"},
    {0x8C0077, 0x8C0079, "Reserved"},
    {0x8C007A, 0x8C007A, "Aim Duration"},
    {0x8C007B, 0x8C007B, "Good Read Lamp Duration"},
    {0x8C007C, 0x8C007C, "Good Read Lamp Intensity"},
    {0x8C007D, 0x8C007D, "Good Read LED"},
    {0x8C007E, 0x8C007E, "Good Read Tone Frequency"},
    {0x8C007F, 0x8C007F, "Good Read Tone Length"},
    {0x8C0080, 0x8C0080, "Good Read Tone Volume"},
    {0x8C0081, 0x8C0081, "Reserved"},
    {0x8C0082, 0x8C0082, "No Read Message"},
    {0x8C0083, 0x8C0083, "Not on File Volume"},
    {0x8C0084, 0x8C0084, "Powerup Beep"},
    {0x8C0085, 0x8C0085, "Sound Error Beep"},
    {0x8C0086, 0x8C0086, "Sound Good Read Beep"},
    {0x8C0087, 0x8C0087, "Sound Not On File Beep"},
    {0x8C0088, 0x8C0088, "Good Read When to Write"},
    {0x8C0089, 0x8C0089, "GRWTI After Decode"},
    {0x8C008A, 0x8C008A, "GRWTI Beep/Lamp after transmit"},
    {0x8C008B, 0x8C008B, "GRWTI No Beep/Lamp use at all"},
    {0x8C008C, 0x8C0090, "Reserved"},
    {0x8C0091, 0x8C0091, "Bookland EAN"},
    {0x8C0092, 0x8C0092, "Convert EAN 8 to 13 Type"},
    {0x8C0093, 0x8C0093, "Convert UPC A to EAN-13"},
    {0x8C0094, 0x8C0094, "Convert UPC-E to A"},
    {0x8C0095, 0x8C0095, "EAN-13"},
    {0x8C0096, 0x8C0096, "EAN-8"},
    {0x8C0097, 0x8C0097, "EAN-99 128_Mandatory"},
    {0x8C0098, 0x8C0098, "EAN-99 P5/128_Optional"},
    {0x8C0099, 0x8C0099, "Reserved"},
    {0x8C009A, 0x8C009A, "UPC/EAN"},
    {0x8C009B, 0x8C009B, "UPC/EAN Coupon Code"},
    {0x8C009C, 0x8C009C, "UPC/EAN Periodicals"},
    {0x8C009D, 0x8C009D, "UPC-A"},
    {0x8C009E, 0x8C009E, "UPC-A with 128 Mandatory"},
    {0x8C009F, 0x8C009F, "UPC-A with 128 Optional"},
    {0x8C00A0, 0x8C00A0, "UPC-A with P5 Optional"},
    {0x8C00A1, 0x8C00A1, "UPC-E"},
    {0x8C00A2, 0x8C00A2, "UPC-E1"},
    {0x8C00A3, 0x8C00A8, "Reserved"},
    {0x8C00A9, 0x8C00A9, "Periodical"},
    {0x8C00AA, 0x8C00AA, "Periodical Auto-Discriminate + 2"},
    {0x8C00AB, 0x8C00AB, "Periodical Only Decode with + 2"},
    {0x8C00AC, 0x8C00AC, "Periodical Ignore + 2"},
    {0x8C00AD, 0x8C00AD, "Periodical Auto-Discriminate + 5"},
    {0x8C00AE, 0x8C00AE, "Periodical Only Decode with + 5"},
    {0x8C00AF, 0x8C00AF, "Periodical Ignore + 5"},
    {0x8C00B0, 0x8C00B0, "Check"},
    {0x8C00B1, 0x8C00B1, "Check Disable Price"},
    {0x8C00B2, 0x8C00B2, "Check Enable 4 digit Price"},
    {0x8C00B3, 0x8C00B3, "Check Enable 5 digit Price"},
    {0x8C00B4, 0x8C00B4, "Check Enable European 4 digit Price"},
    {0x8C00B5, 0x8C00B5, "Check Enable European 5 digit Price"},
    {0x8C00B6, 0x8C00B6, "Reserved"},
    {0x8C00B7, 0x8C00B7, "EAN Two Label"},
    {0x8C00B8, 0x8C00B8, "EAN Three Label"},
    {0x8C00B9, 0x8C00B9, "EAN 8 Flag Digit 1"},
    {0x8C00BA, 0x8C00BA, "EAN 8 Flag Digit 2"},
    {0x8C00BB, 0x8C00BB, "EAN 8 Flag Digit 3"},
    {0x8C00BC, 0x8C00BC, "EAN 13 Flag Digit 1"},
    {0x8C00BD, 0x8C00BD, "EAN 13 Flag Digit 2"},
    {0x8C00BE, 0x8C00BE, "EAN 13 Flag Digit 3"},
    {0x8C00BF, 0x8C00BF, "Add EAN 2/3 Label Definition"},
    {0x8C00C0, 0x8C00C0, "Clear all EAN 2/3 Label Definitions"},
    {0x8C00C1, 0x8C00C1, "Reserved"},
    {0x8C00C2, 0x8C00C2, "Reserved"},
    {0x8C00C3, 0x8C00C3, "Codabar"},
    {0x8C00C4, 0x8C00C4, "Code 128"},
    {0x8C00C5, 0x8C00C6, "Reserved"},
    {0x8C00C7, 0x8C00C7, "Code 39"},
    {0x8C00C8, 0x8C00C8, "Code 93 "},
    {0x8C00C9, 0x8C00C9, "Full ASCII Conversion"},
    {0x8C00CA, 0x8C00CA, "Interleaved 2 of 5"},
    {0x8C00CB, 0x8C00CB, "Italian Pharmacy Code"},
    {0x8C00CC, 0x8C00CC, "MSI/Plessey"},
    {0x8C00CD, 0x8C00CD, "Standard 2 of 5 IATA"},
    {0x8C00CE, 0x8C00CE, "Standard 2 of 5"},
    {0x8C00CF, 0x8C00CF, "Reserved"},
    {0x8C00D0, 0x8C00D0, "Reserved"},
    {0x8C00D1, 0x8C00D1, "Reserved"},
    {0x8C00D2, 0x8C00D2, "Reserved"},
    {0x8C00D3, 0x8C00D3, "Transmit Start/Stop"},
    {0x8C00D4, 0x8C00D4, "Tri-Optic"},
    {0x8C00D5, 0x8C00D5, "UCC/EAN-128"},
    {0x8C00D6, 0x8C00D6, "Check Digit"},
    {0x8C00D7, 0x8C00D7, "Check Digit Disable"},
    {0x8C00D8, 0x8C00D8, "Check Digit Enable Interleaved 2 of 5 OPCC"},
    {0x8C00D9, 0x8C00D9, "Check Digit Enable Interleaved 2 of 5 USS"},
    {0x8C00DA, 0x8C00DA, "Check Digit Enable Standard 2 of 5 OPCC"},
    {0x8C00DB, 0x8C00DB, "Check Digit Enable Standard 2 of 5 USS"},
    {0x8C00DC, 0x8C00DC, "Check Digit Enable One MSI Plessey"},
    {0x8C00DD, 0x8C00DD, "Check Digit Enable Two MSI Plessey"},
    {0x8C00DE, 0x8C00DE, "Check Digit Codabar Enable"},
    {0x8C00DF, 0x8C00DF, "Check Digit Code 39 Enable"},
    {0x8C00E0, 0x8C00EF, "Reserved"},
    {0x8C00F0, 0x8C00F0, "Transmit Check Digit"},
    {0x8C00F1, 0x8C00F1, "Disable Check Digit Transmit"},
    {0x8C00F2, 0x8C00F2, "Enable Check Digit Transmit"},
    {0x8C00F3, 0x8C00FA, "Reserved"},
    {0x8C00FB, 0x8C00FB, "Symbology Identifier 1"},
    {0x8C00FC, 0x8C00FC, "Symbology Identifier 2"},
    {0x8C00FD, 0x8C00FD, "Symbology Identifier 3"},
    {0x8C00FE, 0x8C00FE, "Decoded Data"},
    {0x8C00FF, 0x8C00FF, "Decode Data Continued"},
    {0x8C0100, 0x8C0100, "Bar Space Data"},
    {0x8C0101, 0x8C0101, "Scanner Data Accuracy"},
    {0x8C0102, 0x8C0102, "Raw Data Polarity"},
    {0x8C0103, 0x8C0103, "Polarity Inverted Bar Code"},
    {0x8C0104, 0x8C0104, "Polarity Normal Bar Code"},
    {0x8C0105, 0x8C0105, "Reserved"},
    {0x8C0106, 0x8C0106, "Minimum Length to Decode"},
    {0x8C0107, 0x8C0107, "Maximum Length to Decode"},
    {0x8C0108, 0x8C0108, "First Discrete Length to Decode"},
    {0x8C0109, 0x8C0109, "Second Discrete Length to Decode"},
    {0x8C010A, 0x8C010A, "Data Length Method"},
    {0x8C010B, 0x8C010B, "DL Method Read any"},
    {0x8C010C, 0x8C010C, "DL Method Check in Range"},
    {0x8C010D, 0x8C010D, "DL Method Check for Discrete"},
    {0x8C010E, 0x8C010F, "Reserved"},
    {0x8C0110, 0x8C0110, "Aztec Code"},
    {0x8C0111, 0x8C0111, "BC412"},
    {0x8C0112, 0x8C0112, "Channel Code"},
    {0x8C0113, 0x8C0113, "Code 16"},
    {0x8C0114, 0x8C0114, "Code 32"},
    {0x8C0115, 0x8C0115, "Code 49"},
    {0x8C0116, 0x8C0116, "Code One"},
    {0x8C0117, 0x8C0117, "Colorcode"},
    {0x8C0118, 0x8C0118, "Data Matrix"},
    {0x8C0119, 0x8C0119, "MaxiCode"},
    {0x8C011A, 0x8C011A, "MicroPDF"},
    {0x8C011B, 0x8C011B, "PDF-417"},
    {0x8C011C, 0x8C011C, "PosiCode"},
    {0x8C011D, 0x8C011D, "QR Code"},
    {0x8C011E, 0x8C011E, "SuperCode"},
    {0x8C011F, 0x8C011F, "UltraCode"},
    {0x8C0120, 0x8C0120, "USD-5 (Slug Code)"},
    {0x8C0121, 0x8C0121, "VeriCode"},
    {0x8C0122, 0x8CFFFF, "Reserved"},

    // Scale page
    {0x8D0000, 0x8D0000, "Undefined"},
    {0x8D0001, 0x8D0001, "Weighing Device"},
    {0x8D0002, 0x8D001F, "Reserved"},
    {0x8D0020, 0x8D0020, "Scale Device"},
    {0x8D0021, 0x8D0021, "Scale Class I Metric"},
    {0x8D0022, 0x8D0022, "Scale Class I Metric"},
    {0x8D0023, 0x8D0023, "Scale Class II Metric"},
    {0x8D0024, 0x8D0024, "Scale Class III Metric"},
    {0x8D0025, 0x8D0025, "Scale Class IIIL Metric"},
    {0x8D0026, 0x8D0026, "Scale Class IV Metric"},
    {0x8D0027, 0x8D0027, "Scale Class III English"},
    {0x8D0028, 0x8D0028, "Scale Class IIIL English"},
    {0x8D0029, 0x8D0029, "Scale Class IV English"},
    {0x8D002A, 0x8D002A, "Scale Class Generic"},
    {0x8D002B, 0x8D002F, "Reserved"},
    {0x8D0030, 0x8D0030, "Scale Attribute Report"},
    {0x8D0031, 0x8D0031, "Scale Control Report"},
    {0x8D0032, 0x8D0032, "Scale Data Report"},
    {0x8D0033, 0x8D0033, "Scale Status Report"},
    {0x8D0034, 0x8D0034, "Scale Weight Limit Report"},
    {0x8D0035, 0x8D0035, "Scale Statistics Report"},
    {0x8D0036, 0x8D003F, "Reserved"},
    {0x8D0040, 0x8D0040, "Data Weight"},
    {0x8D0041, 0x8D0041, "Data Scaling"},
    {0x8D0042, 0x8D004F, "Reserved"},
    {0x8D0050, 0x8D0050, "Weight Unit"},
    {0x8D0051, 0x8D0051, "Weight Unit Milligram"},
    {0x8D0052, 0x8D0052, "Weight Unit Gram"},
    {0x8D0053, 0x8D0053, "Weight Unit Kilogram"},
    {0x8D0054, 0x8D0054, "Weight Unit Carats"},
    {0x8D0055, 0x8D0055, "Weight Unit Taels"},
    {0x8D0056, 0x8D0056, "Weight Unit Grains"},
    {0x8D0057, 0x8D0057, "Weight Unit Pennyweights"},
    {0x8D0058, 0x8D0058, "Weight Unit Metric Ton"},
    {0x8D0059, 0x8D0059, "Weight Unit Avoir Ton"},
    {0x8D005A, 0x8D005A, "Weight Unit Troy Ounce"},
    {0x8D005B, 0x8D005B, "Weight Unit Ounce"},
    {0x8D005C, 0x8D005C, "Weight Unit Pound"},
    {0x8D005D, 0x8D005F, "Reserved"},
    {0x8D0060, 0x8D0060, "Calibration Count"},
    {0x8D0061, 0x8D0061, "Re-Zero Count"},
    {0x8D0062, 0x8D006F, "Reserved"},
    {0x8D0070, 0x8D0070, "Scale Status"},
    {0x8D0071, 0x8D0071, "Scale Status Fault"},
    {0x8D0072, 0x8D0072, "Scale Status Stable at Center of Zero"},
    {0x8D0073, 0x8D0073, "Scale Status In Motion"},
    {0x8D0074, 0x8D0074, "Scale Status Weight Stable"},
    {0x8D0075, 0x8D0075, "Scale Status Under Zero"},
    {0x8D0076, 0x8D0076, "Scale Status Over Weight Limit"},
    {0x8D0077, 0x8D0077, "Scale Status Requires Calibration"},
    {0x8D0078, 0x8D0078, "Scale Status Requires Re- zeroing"},
    {0x8D0079, 0x8D007F, "Reserved"},
    {0x8D0080, 0x8D0080, "Zero Scale"},
    {0x8D0081, 0x8D0081, "Enforced Zero Return"},
    {0x8D0082, 0x8DFFFF, "Reserved"},

    // Magnetic Stripe Reading (MSR) devices
    {0x8E0000, 0x8E0000, "Undefined"},
    {0x8E0001, 0x8E0001, "MSR Device Read-Only"},
    {0x8E0002, 0x8E0010, "Reserved"},
    {0x8E0011, 0x8E0011, "Track 1 Length"},
    {0x8E0012, 0x8E0012, "Track 2 Length"},
    {0x8E0013, 0x8E0013, "Track 3 Length"},
    {0x8E0014, 0x8E0014, "Track JIS Length"},
    {0x8E0015, 0x8E001F, "Reserved"},
    {0x8E0020, 0x8E0020, "Track Data"},
    {0x8E0021, 0x8E0021, "Track 1 Data"},
    {0x8E0022, 0x8E0022, "Track 2 Data"},
    {0x8E0023, 0x8E0023, "Track 3 Data"},
    {0x8E0024, 0x8E0024, "Track JIS Data"},
    {0x8E0025, 0x8EFFFF, "Reserved"},

    {0x8F0000, 0x8FFFFF, "[Reserved Point of Sale page]"},
    {0x900000, 0x90FFFF, "Camera control page"},

    // Arcade page
    {0x910000, 0x910000, "Undefined"},
    {0x910001, 0x910001, "General Purpose IO Card"},
    {0x910002, 0x910002, "Coin Door"},
    {0x910003, 0x910003, "Watchdog Timer"},
    {0x910004, 0x91002F, "Reserved"},
    {0x910030, 0x910030, "General Purpose Analog Input State"},
    {0x910031, 0x910031, "General Purpose Digital Input State"},
    {0x910032, 0x910032, "General Purpose Optical Input State"},
    {0x910033, 0x910033, "General Purpose Digital Output State"},
    {0x910034, 0x910034, "Number of Coin Doors"},
    {0x910035, 0x910035, "Coin Drawer Drop Count"},
    {0x910036, 0x910036, "Coin Drawer Start"},
    {0x910037, 0x910037, "Coin Drawer Service"},
    {0x910038, 0x910038, "Coin Drawer Tilt"},
    {0x910039, 0x910039, "Coin Door Test"},
    {0x91003A, 0x91003F, "[Undefined]"},
    {0x910040, 0x910040, "Coin Door Lockout"},
    {0x910041, 0x910041, "Watchdog Timeout"},
    {0x910042, 0x910042, "Watchdog Action"},
    {0x910043, 0x910043, "Watchdog Reboot"},
    {0x910044, 0x910044, "Watchdog Restart"},
    {0x910045, 0x910045, "Alarm Input"},
    {0x910046, 0x910046, "Coin Door Counter"},
    {0x910047, 0x910047, "I/O Direction Mapping"},
    {0x910048, 0x910048, "Set I/O Direction"},
    {0x910049, 0x910049, "Extended Optical Input State"},
    {0x91004A, 0x91004A, "Pin Pad Input State"},
    {0x91004B, 0x91004B, "Pin Pad Status"},
    {0x91004C, 0x91004C, "Pin Pad Output"},
    {0x91004D, 0x91004D, "Pin Pad Command"},
    {0x91004E, 0x91FFFF, "Reserved"},

    {0x920000, 0xFEFFFFFF, "[Reserved]"},
    {0xFF000000, 0xFFFFFFFF, "[Vendor-defined]"},
    {0, 0, NULL}
};

static const value_string keycode_vals[] = {
    { 0x00,   "<ACTION KEY UP>" },
    { 0x01,   "ErrorRollOver" },
    { 0x02,   "POSTFail" },
    { 0x03,   "ErrorUndefined" },

    { 0x04,   "a" },
    { 0x05,   "b" },
    { 0x06,   "c" },
    { 0x07,   "d" },
    { 0x08,   "e" },
    { 0x09,   "f" },
    { 0x0A,   "g" },
    { 0x0B,   "h" },
    { 0x0C,   "i" },
    { 0x0D,   "j" },
    { 0x0E,   "k" },
    { 0x0F,   "l" },
    { 0x10,   "m" },
    { 0x11,   "n" },
    { 0x12,   "o" },
    { 0x13,   "p" },
    { 0x14,   "q" },
    { 0x15,   "r" },
    { 0x16,   "s" },
    { 0x17,   "t" },
    { 0x18,   "u" },
    { 0x19,   "v" },
    { 0x1A,   "w" },
    { 0x1B,   "x" },
    { 0x1C,   "y" },
    { 0x1D,   "z" },

    { 0x1E,   "1" },
    { 0x1F,   "2" },
    { 0x20,   "3" },
    { 0x21,   "4" },
    { 0x22,   "5" },
    { 0x23,   "6" },
    { 0x24,   "7" },
    { 0x25,   "8" },
    { 0x26,   "9" },
    { 0x27,   "0" },

    { 0x28,   "ENTER" },
    { 0x29,   "Escape" },
    { 0x2A,   "Backspace" },
    { 0x2B,   "Tab" },
    { 0x2C,   "Spacebar" },

    { 0x2D,   "-" },
    { 0x2E,   "=" },
    { 0x2F,   "[" },
    { 0x30,   "]" },
    { 0x31,   "\\" },
    { 0x32,   "NonUS #/~" },
    { 0x33,   ";" },
    { 0x34,   "'" },
    { 0x35,   "`" },
    { 0x36,   "," },
    { 0x37,   "." },
    { 0x38,   "/" },
    { 0x39,   "CapsLock" },
    { 0x3A,   "F1" },
    { 0x3B,   "F2" },
    { 0x3C,   "F3" },
    { 0x3D,   "F4" },
    { 0x3E,   "F5" },
    { 0x3F,   "F6" },
    { 0x40,   "F7" },
    { 0x41,   "F8" },
    { 0x42,   "F9" },
    { 0x43,   "F10" },
    { 0x44,   "F11" },
    { 0x45,   "F12" },
    { 0x46,   "PrintScreen" },
    { 0x47,   "ScrollLock" },
    { 0x48,   "Pause" },
    { 0x49,   "Insert" },
    { 0x4A,   "Home" },
    { 0x4B,   "PageUp" },
    { 0x4C,   "DeleteForward" },
    { 0x4D,   "End" },
    { 0x4E,   "PageDown" },
    { 0x4F,   "RightArrow" },
    { 0x50,   "LeftArrow" },
    { 0x51,   "DownArrow" },
    { 0x52,   "UpArrow" },
    { 0x53,   "NumLock" },

    /* Keypad */
    { 0x54,   "Keypad /" },
    { 0x55,   "Keypad *" },
    { 0x56,   "Keypad -" },
    { 0x57,   "Keypad +" },
    { 0x58,   "Keypad ENTER" },
    { 0x59,   "Keypad 1" },
    { 0x5A,   "Keypad 2" },
    { 0x5B,   "Keypad 3" },
    { 0x5C,   "Keypad 4" },
    { 0x5D,   "Keypad 5" },
    { 0x5E,   "Keypad 6" },
    { 0x5F,   "Keypad 7" },
    { 0x60,   "Keypad 8" },
    { 0x61,   "Keypad 9" },
    { 0x62,   "Keypad 0" },
    { 0x63,   "Keypad ." },

    /* non PC AT */
    { 0x64,   "NonUS \\/|" },
    { 0x65,   "Application" },
    { 0x66,   "Power" },
    { 0x67,   "Keypad =" },
    { 0x68,   "F13" },
    { 0x69,   "F14" },
    { 0x6A,   "F15" },
    { 0x6B,   "F16" },
    { 0x6C,   "F17" },
    { 0x6D,   "F18" },
    { 0x6E,   "F19" },
    { 0x6F,   "F20" },

    { 0x70,   "F21" },
    { 0x71,   "F22" },
    { 0x72,   "F23" },
    { 0x73,   "F24" },
    { 0x74,   "Execute" },
    { 0x75,   "Help" },
    { 0x76,   "Menu" },
    { 0x77,   "Select" },
    { 0x78,   "Stop" },
    { 0x79,   "Again" },
    { 0x7A,   "Undo" },
    { 0x7B,   "Cut" },
    { 0x7C,   "Copy" },
    { 0x7D,   "Paste" },
    { 0x7E,   "Find" },
    { 0x7F,   "Mute" },

    { 0x80,   "VolumeUp" },
    { 0x81,   "VolumeDown" },
    { 0x82,   "Locking CapsLock" },
    { 0x83,   "Locking NumLock" },
    { 0x84,   "Locking ScrollLock" },
    { 0x85,   "Keypad Comma" },
    { 0x86,   "Keypad EqualSign" },
    { 0x87,   "International1" },
    { 0x88,   "International2" },
    { 0x89,   "International3" },
    { 0x8A,   "International4" },
    { 0x8B,   "International5" },
    { 0x8C,   "International6" },
    { 0x8D,   "International7" },
    { 0x8E,   "International8" },
    { 0x8F,   "International9" },

    { 0x90,   "LANG1" },
    { 0x91,   "LANG2" },
    { 0x92,   "LANG3" },
    { 0x93,   "LANG4" },
    { 0x94,   "LANG5" },
    { 0x95,   "LANG6" },
    { 0x96,   "LANG7" },
    { 0x97,   "LANG8" },
    { 0x98,   "LANG9" },
    { 0x99,   "AlternateErase" },
    { 0x9A,   "SysReq/Attention" },
    { 0x9B,   "Cancel" },
    { 0x9C,   "Clear" },
    { 0x9D,   "Prior" },
    { 0x9E,   "Return" },
    { 0x9F,   "Separator" },

    { 0xA0,   "Out" },
    { 0xA1,   "Oper" },
    { 0xA2,   "Clear/Again" },
    { 0xA3,   "CrSel/Props" },
    { 0xA4,   "ExSel" },
    /* 0xA5..0xAF - reserved */
    { 0xB0,   "Keypad 00" },
    { 0xB1,   "Keypad 000" },
    { 0xB2,   "ThousandsSeparator" },
    { 0xB3,   "DecimalSeparator" },
    { 0xB4,   "CurrencyUnit" },
    { 0xB5,   "CurrencySubunit" },
    { 0xB6,   "Keypad (" },
    { 0xB7,   "Keypad )" },
    { 0xB8,   "Keypad {" },
    { 0xB9,   "Keypad }" },
    { 0xBA,   "Keypad Tab" },
    { 0xBB,   "Keypad Backspace" },
    { 0xBC,   "Keypad A" },
    { 0xBD,   "Keypad B" },
    { 0xBE,   "Keypad C" },
    { 0xBF,   "Keypad D" },

    { 0xC0,   "Keypad E" },
    { 0xC1,   "Keypad F" },
    { 0xC2,   "Keypad XOR" },
    { 0xC3,   "Keypad ^" },
    { 0xC4,   "Keypad %" },
    { 0xC5,   "Keypad <" },
    { 0xC6,   "Keypad >" },
    { 0xC7,   "Keypad &" },
    { 0xC8,   "Keypad &&" },
    { 0xC9,   "Keypad |" },
    { 0xCA,   "Keypad ||" },
    { 0xCB,   "Keypad :" },
    { 0xCC,   "Keypad #" },
    { 0xCD,   "Keypad Space" },
    { 0xCE,   "Keypad @" },
    { 0xCF,   "Keypad !" },

    { 0xD0,   "Keypad Memory Store" },
    { 0xD1,   "Keypad Memory Recall" },
    { 0xD2,   "Keypad Memory Clear" },
    { 0xD3,   "Keypad Memory Add" },
    { 0xD4,   "Keypad Memory Subtract" },
    { 0xD5,   "Keypad Memory Multiply" },
    { 0xD6,   "Keypad Memory Divide" },
    { 0xD7,   "Keypad +/-" },
    { 0xD8,   "Keypad Clear" },
    { 0xD9,   "Keypad Clear Entry" },
    { 0xDA,   "Keypad Binary" },
    { 0xDB,   "Keypad Octal" },
    { 0xDC,   "Keypad Decimal" },
    { 0xDD,   "Keypad Hexadecimal" },
    /* 0xDE..0xDF - reserved,  */
    { 0xE0,   "LeftControl" },
    { 0xE1,   "LeftShift" },
    { 0xE2,   "LeftAlt" },
    { 0xE3,   "LeftGUI" },
    { 0xE4,   "RightControl" },
    { 0xE5,   "RightShift" },
    { 0xE6,   "RightAlt" },
    { 0xE7,   "RightGUI" },

    { 0, NULL }
};
value_string_ext keycode_vals_ext = VALUE_STRING_EXT_INIT(keycode_vals);

/* Dissector for the data in a HID main report. */
static int
dissect_usb_hid_report_mainitem_data(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, unsigned int bSize, unsigned int bTag)
{
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
            if (bTag == USBHID_MAINITEM_TAG_INPUT) {
                proto_tree_add_item(tree, hf_usb_hid_mainitem_bit7_input, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            } else {
                proto_tree_add_item(tree, hf_usb_hid_mainitem_bit7, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            }
            if (bSize > 1) {
                proto_tree_add_item(tree, hf_usb_hid_mainitem_bit8, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            } else {
                proto_tree_add_boolean_format_value(tree, hf_usb_hid_mainitem_bit8, tvb, offset, 0, FALSE, "Buffered bytes (default, no second byte present)");
            }
            break;
        case USBHID_MAINITEM_TAG_COLLECTION:
            proto_tree_add_item(tree, hf_usb_hid_mainitem_colltype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_MAINITEM_TAG_ENDCOLLECTION:
            /* No item data */
            break;
        default:
            proto_tree_add_item(tree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
            break;
    }
    offset += bSize;
    return offset;
}

/* Dissector for the data in a HID main report. */
static int
dissect_usb_hid_report_globalitem_data(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, unsigned int bSize, unsigned int bTag, struct usb_hid_global_state *global)
{
    switch (bTag) {
        case USBHID_GLOBALITEM_TAG_USAGE_PAGE:
            switch (bSize) {
                case 1: global->usage_page = tvb_get_guint8(tvb, offset); break;
                case 2: global->usage_page = tvb_get_letohs(tvb, offset); break;
                case 3: global->usage_page = tvb_get_letoh24(tvb, offset); break;
                case 4: global->usage_page = tvb_get_letohl(tvb, offset); break;
                default: global->usage_page = 0; break;
            }
            proto_tree_add_item(tree, hf_usb_hid_globalitem_usage, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_LOG_MIN:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_log_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_LOG_MAX:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_log_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_PHY_MIN:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_phy_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_PHY_MAX:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_phy_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_UNIT_EXP:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_exp, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_UNIT:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_sys, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_len, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_mass, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_time, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_temp, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_current, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_brightness, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_SIZE:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_report_size, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_ID:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_report_id, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_COUNT:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_report_count, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_PUSH:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_push, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_GLOBALITEM_TAG_POP:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_pop, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(tree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
            break;
    }
    offset += bSize;
    return offset;
}

/* Dissector for the data in a HID main report. */
static int
dissect_usb_hid_report_localitem_data(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, unsigned int bSize, unsigned int bTag, struct usb_hid_global_state *global)
{
    unsigned int usage_page = 0xffffffff; /* in case bSize == 0 */

    switch (bTag) {
        case USBHID_LOCALITEM_TAG_USAGE_PAGE:
            if (bSize > 2) {
                /* Full page ID */
                proto_tree_add_item(tree, hf_usb_hid_localitem_usage, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            } else {
                /* Only lower few bits given, need to combine with last global ID */
                if (bSize == 1)
                    usage_page = global->usage_page<<16 | tvb_get_guint8(tvb, offset);
                else if (bSize == 2)
                    usage_page = global->usage_page<<16 | tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(tree, hf_usb_hid_localitem_usage, tvb, offset, bSize, usage_page);
            }
            break;
        case USBHID_LOCALITEM_TAG_USAGE_MIN:
            proto_tree_add_item(tree, hf_usb_hid_localitem_usage_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_LOCALITEM_TAG_USAGE_MAX:
            proto_tree_add_item(tree, hf_usb_hid_localitem_usage, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_LOCALITEM_TAG_DESIG_INDEX:
            proto_tree_add_item(tree, hf_usb_hid_localitem_desig_index, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_LOCALITEM_TAG_DESIG_MIN:
            proto_tree_add_item(tree, hf_usb_hid_localitem_desig_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_LOCALITEM_TAG_DESIG_MAX:
            proto_tree_add_item(tree, hf_usb_hid_localitem_desig_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_LOCALITEM_TAG_STRING_INDEX:
            proto_tree_add_item(tree, hf_usb_hid_localitem_string_index, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_LOCALITEM_TAG_STRING_MIN:
            proto_tree_add_item(tree, hf_usb_hid_localitem_string_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_LOCALITEM_TAG_STRING_MAX:
            proto_tree_add_item(tree, hf_usb_hid_localitem_string_max, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        case USBHID_LOCALITEM_TAG_DELIMITER:
            proto_tree_add_item(tree, hf_usb_hid_localitem_delimiter, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            break;
        default:
            proto_tree_add_item(tree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
            break;
    }
    offset += bSize;
    return offset;
}

/* Dissector for individual HID report items.  Recursive. */
static int
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

        tmp = tvb_get_guint8(tvb, offset);
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

        subtree = proto_tree_add_subtree_format(parent_tree, tvb, offset, bSize + 1,
            ett_usb_hid_item_header, &subitem, "%s item (%s)",
            val_to_str(bType, usb_hid_item_bType_vals, "Unknown/%u"),
            val_to_str(bTag, usb_hid_cur_bTag_vals, "Unknown/%u tag")
        );

        tree = proto_tree_add_subtree(subtree, tvb, offset, 1, ett_usb_hid_item_header, NULL, "Header");
        proto_tree_add_item(tree, hf_usb_hid_item_bSize, tvb, offset,   1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_hid_item_bType, tvb, offset,   1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_usb_hid_curitem_bTag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        if ((bType == 3) && (bTag == 16)) {
            /* Long item */
            bSize = tvb_get_guint8(tvb, offset);
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
                offset = dissect_usb_hid_report_item(pinfo, subtree, tvb, offset, usb_conv_info, &cur_global);
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

    proto_item_set_len(item, offset-old_offset);

    return offset;
}

/* Dissector for HID GET_REPORT request. See USBHID 1.11, Chapter 7.2.1 Get_Report Request */
static void
dissect_usb_hid_get_report(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_conv_info_t *usb_conv_info _U_)
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
dissect_usb_hid_set_report(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_conv_info_t *usb_conv_info _U_)
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
dissect_usb_hid_get_idle(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_conv_info_t *usb_conv_info _U_)
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
dissect_usb_hid_set_idle(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_conv_info_t *usb_conv_info _U_)
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
dissect_usb_hid_get_protocol(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_conv_info_t *usb_conv_info _U_)
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
dissect_usb_hid_set_protocol(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_conv_info_t *usb_conv_info _U_)
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


typedef void (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_request, usb_conv_info_t *usb_conv_info);

typedef struct _usb_setup_dissector_table_t {
    guint8 request;
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

static gint
dissect_usb_hid_boot_keyboard_input_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint      offset = 0;
    gboolean  shortcut_helper = FALSE;
    guint     modifier;
    guint     keycode;

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_right_gui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_right_alt, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_right_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_right_ctrl, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_left_gui, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_left_alt, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_left_shift, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_modifier_left_ctrl, tvb, offset, 1, ENC_BIG_ENDIAN);
    modifier = tvb_get_guint8(tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, " - ");
    if (modifier & 0x80) {
        col_append_str(pinfo->cinfo, COL_INFO, "RIGHT GUI");
        shortcut_helper = TRUE;
    }
    if (modifier & 0x40) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "RIGHT ALT");
        shortcut_helper = TRUE;
    }
    if (modifier & 0x20) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "RIGHT SHIFT");
        shortcut_helper = TRUE;
    }
    if (modifier & 0x10) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "RIGHT CTRL");
        shortcut_helper = TRUE;
    }
    if (modifier & 0x08) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "LEFT GUI");
        shortcut_helper = TRUE;
    }
    if (modifier & 0x04) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "LEFT ALT");
        shortcut_helper = TRUE;
    }
    if (modifier & 0x02) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "LEFT SHIFT");
        shortcut_helper = TRUE;
    }
    if (modifier & 0x01) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "LEFT CTRL");
        shortcut_helper = TRUE;
    }
    offset += 1;

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_1, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = TRUE;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_2, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = TRUE;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_3, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = TRUE;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = TRUE;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = TRUE;
    }

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_keycode_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    keycode = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (keycode) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(keycode, &keycode_vals_ext, "Unknown"));
        shortcut_helper = TRUE;
    }

    if (shortcut_helper == FALSE) {
        col_append_str(pinfo->cinfo, COL_INFO, "<action key up>");
    }

    return offset;
}

static gint
dissect_usb_hid_boot_keyboard_output_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint      offset = 0;
    gboolean  shortcut_helper = FALSE;
    guint     leds;

    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_constants, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_kana, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_compose, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_scroll_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_caps_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_keyboard_leds_num_lock, tvb, offset, 1, ENC_BIG_ENDIAN);
    leds = tvb_get_guint8(tvb, offset);

    col_append_str(pinfo->cinfo, COL_INFO, " - LEDs: ");
    if (leds & 0x01) {
        col_append_str(pinfo->cinfo, COL_INFO, "NumLock");
        shortcut_helper = TRUE;
    }
    if (leds & 0x02) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "CapsLock");
        shortcut_helper = TRUE;
    }
    if (leds & 0x04) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "ScrollLock");
        shortcut_helper = TRUE;
    }
    if (leds & 0x08) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Compose");
        shortcut_helper = TRUE;
    }
    if (leds & 0x10) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Kana");
        shortcut_helper = TRUE;
    }
    if (leds & 0x20) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Constant1");
        shortcut_helper = TRUE;
    }
    if (leds & 0x40) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Constant2");
        shortcut_helper = TRUE;
    }
    if (leds & 0x80) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_append_str(pinfo->cinfo, COL_INFO, "Constant3");
        /*shortcut_helper = TRUE;*/
    }
    if (!leds) {
        col_append_str(pinfo->cinfo, COL_INFO, "none");
    }

    offset += 1;

    return offset;
}

static gint
dissect_usb_hid_boot_mouse_input_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint      offset = 0;
    gboolean  shortcut_helper = FALSE;
    guint     buttons;

    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_8, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_7, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_middle, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_right, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_usbhid_boot_report_mouse_button_left, tvb, offset, 1, ENC_BIG_ENDIAN);
    buttons = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (buttons) col_append_str(pinfo->cinfo, COL_INFO, " - ");
    if (buttons & 0x01) {
        col_append_str(pinfo->cinfo, COL_INFO, "Button LEFT");
        shortcut_helper = TRUE;
    }
    if (buttons & 0x02) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button RIGHT");
        shortcut_helper = TRUE;
    }
    if (buttons & 0x04) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button MIDDLE");
    }
    if (buttons & 0x08) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 4");
        shortcut_helper = TRUE;
    }
    if (buttons & 0x10) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 5");
        shortcut_helper = TRUE;
    }
    if (buttons & 0x20) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 6");
        shortcut_helper = TRUE;
    }
    if (buttons & 0x40) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 7");
        shortcut_helper = TRUE;
    }
    if (buttons & 0x80) {
        if (shortcut_helper) col_append_str(pinfo->cinfo, COL_INFO, " + ");
        col_append_str(pinfo->cinfo, COL_INFO, "Button 8");
        /* Not necessary, this is the last case where it is used
         * shortcut_helper = TRUE;
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
static gint
dissect_usb_hid_control_std_intf(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, usb_conv_info_t *usb_conv_info)
{
    gint              offset = 0;
    usb_trans_info_t *usb_trans_info;
    guint8            req;

    usb_trans_info = usb_conv_info->usb_trans_info;

    /* XXX - can we do some plausibility checks here? */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBHID");

    /* we can't use usb_conv_info->is_request since usb_conv_info
       was replaced with the interface conversation */
    if (usb_trans_info->request_in == pinfo->num) {
        /* the tvb that we see here is the setup packet
           without the request type byte */

        req = tvb_get_guint8(tvb, offset);
        if (req != USB_SETUP_GET_DESCRIPTOR)
            return offset;
        col_clear(pinfo->cinfo, COL_INFO);
        col_append_str(pinfo->cinfo, COL_INFO, "GET DESCRIPTOR Request");
        offset += 1;

        proto_tree_add_item(tree, hf_usb_hid_bDescriptorIndex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        usb_trans_info->u.get_descriptor.usb_index = tvb_get_guint8(tvb, offset);
        offset += 1;

        proto_tree_add_item(tree, hf_usb_hid_bDescriptorType, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        usb_trans_info->u.get_descriptor.type = tvb_get_guint8(tvb, offset);
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
        if (usb_trans_info->u.get_descriptor.type == USB_DT_HID_REPORT) {
            offset = dissect_usb_hid_get_report_descriptor(
                    pinfo, tree, tvb, offset, usb_conv_info);
        }
    }

    return offset;
}

/* dissect a class-specific control message that's sent to an interface */
static gint
dissect_usb_hid_control_class_intf(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, usb_conv_info_t *usb_conv_info)
{
    usb_trans_info_t *usb_trans_info;
    gboolean is_request;
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
    if (!dissector) {
        return 0;
    }

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

/* Dissector for HID class-specific control request as defined in
 * USBHID 1.11, Chapter 7.2.
 * returns the number of bytes consumed */
static gint
dissect_usb_hid_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    usb_conv_info_t *usb_conv_info;
    usb_trans_info_t *usb_trans_info;
    guint8 type, recip;

    usb_conv_info = (usb_conv_info_t *)data;
    if (!usb_conv_info)
        return 0;
    usb_trans_info = usb_conv_info->usb_trans_info;
    if (!usb_trans_info)
        return 0;

    type = USB_TYPE(usb_trans_info->setup.requesttype);
    recip = USB_RECIPIENT(usb_trans_info->setup.requesttype);

    if (recip == RQT_SETUP_RECIPIENT_INTERFACE) {
        if (type == RQT_SETUP_TYPE_STANDARD) {
            return dissect_usb_hid_control_std_intf(
                    tvb, pinfo, tree, usb_conv_info);
        }
        else if (type == RQT_SETUP_TYPE_CLASS) {
            return dissect_usb_hid_control_class_intf(
                    tvb, pinfo, tree, usb_conv_info);
        }
    }

    return 0;
}

/* dissect a descriptor that is specific to the HID class */
static gint
dissect_usb_hid_class_descriptors(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, void *data _U_)
{
    guint8      type;
    gint        offset = 0;
    proto_item *ti;
    proto_tree *desc_tree;
    guint8      num_desc;
    guint       i;

    type = tvb_get_guint8(tvb, 1);

    /* for now, we only handle the HID descriptor here */
    if (type != USB_DT_HID)
        return 0;

    desc_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_usb_hid_descriptor, &ti, "HID DESCRIPTOR");

    dissect_usb_descriptor_header(desc_tree, tvb, offset,
            &hid_descriptor_type_vals_ext);
    offset += 2;
    proto_tree_add_item(desc_tree, hf_usb_hid_bcdHID,
            tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(desc_tree, hf_usb_hid_bCountryCode,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    num_desc = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(desc_tree, hf_usb_hid_bNumDescriptors,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    for (i=0;i<num_desc;i++) {
        proto_tree_add_item(desc_tree, hf_usb_hid_bDescriptorType,
                tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(desc_tree, hf_usb_hid_wDescriptorLength,
                tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
            { "[Reserved]", "usbhid.item.main.volatile", FT_BOOLEAN, 9,
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
                RVALS(usb_hid_item_usage_page_vals), 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_log_min,
            { "Logical minimum", "usbhid.item.global.log_min", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_log_max,
            { "Logical maximum", "usbhid.item.global.log_max", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_phy_min,
            { "Physical minimum", "usbhid.item.global.phy_min", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_phy_max,
            { "Physical maximum", "usbhid.item.global.phy_max", FT_UINT8, BASE_DEC,
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
                RVALS(usb_hid_item_usage_vals), 0, NULL, HFILL }},

        { &hf_usb_hid_localitem_usage_min,
            { "Usage minimum", "usbhid.item.local.usage_min", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},

#if 0
        { &hf_usb_hid_localitem_usage_max,
            { "Usage maximum", "usbhid.item.local.usage_max", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL }},
#endif

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
        { "bRequest", "usbhid.setup.bRequest", FT_UINT8, BASE_HEX, VALS(setup_request_names_vals), 0x0,
          NULL, HFILL }},

        { &hf_usb_hid_value,
        { "wValue", "usbhid.setup.wValue", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usb_hid_index,
        { "wIndex", "usbhid.setup.wIndex", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usb_hid_length,
        { "wLength", "usbhid.setup.wLength", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usb_hid_report_type,
        { "ReportType", "usbhid.setup.ReportType", FT_UINT8, BASE_DEC,
          VALS(usb_hid_report_type_vals), 0x0,
          NULL, HFILL }},

        { &hf_usb_hid_report_id,
        { "ReportID", "usbhid.setup.ReportID", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usb_hid_duration,
        { "Duration", "usbhid.setup.Duration", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usb_hid_zero,
        { "(zero)", "usbhid.setup.zero", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        /* components of the HID descriptor */
        { &hf_usb_hid_bcdHID,
        { "bcdHID", "usbhid.descriptor.hid.bcdHID", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usb_hid_bCountryCode,
        { "bCountryCode", "usbhid.descriptor.hid.bCountryCode", FT_UINT8,
            BASE_HEX, VALS(hid_country_code_vals), 0x0, NULL, HFILL }},

        { &hf_usb_hid_bNumDescriptors,
        { "bNumDescriptors", "usbhid.descriptor.hid.bNumDescriptors", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_bDescriptorIndex,
        { "bDescriptorIndex", "usbhid.descriptor.hid.bDescriptorIndex", FT_UINT8,
            BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_bDescriptorType,
        { "bDescriptorType", "usbhid.descriptor.hid.bDescriptorType", FT_UINT8,
            BASE_HEX|BASE_EXT_STRING, &hid_descriptor_type_vals_ext,
            0x00, NULL, HFILL }},

        { &hf_usb_hid_wInterfaceNumber,
        { "wInterfaceNumber", "usbhid.descriptor.hid.wInterfaceNumber", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_usb_hid_wDescriptorLength,
        { "wDescriptorLength", "usbhid.descriptor.hid.wDescriptorLength", FT_UINT16,
            BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_usbhid_boot_report_keyboard_reserved,
            { "Reserved",                        "usbhid.boot_report.keyboard.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_keycode_1,
            { "Keycode 1",                       "usbhid.boot_report.keyboard.keycode_1",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_keycode_2,
            { "Keycode 2",                       "usbhid.boot_report.keyboard.keycode_2",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_keycode_3,
            { "Keycode 3",                       "usbhid.boot_report.keyboard.keycode_3",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_keycode_4,
            { "Keycode 4",                       "usbhid.boot_report.keyboard.keycode_4",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_keycode_5,
            { "Keycode 5",                       "usbhid.boot_report.keyboard.keycode_5",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_keycode_6,
            { "Keycode 6",                       "usbhid.boot_report.keyboard.keycode_6",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &keycode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_modifier_right_gui,
            { "Modifier: RIGHT GUI",             "usbhid.boot_report.keyboard.modifier.right_gui",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_modifier_right_alt,
            { "Modifier: RIGHT ALT",             "usbhid.boot_report.keyboard.modifier.right_alt",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_modifier_right_shift,
            { "Modifier: RIGHT SHIFT",           "usbhid.boot_report.keyboard.modifier.right_shift",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_modifier_right_ctrl,
            { "Modifier: RIGHT CTRL",            "usbhid.boot_report.keyboard.modifier.right_ctrl",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_modifier_left_gui,
            { "Modifier: LEFT GUI",              "usbhid.boot_report.keyboard.modifier.left_gui",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_modifier_left_alt,
            { "Modifier: LEFT ALT",              "usbhid.boot_report.keyboard.modifier.left_alt",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_modifier_left_shift,
            { "Modifier: LEFT SHIFT",            "usbhid.boot_report.keyboard.modifier.left_shift",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_modifier_left_ctrl,
            { "Modifier: LEFT CTRL",             "usbhid.boot_report.keyboard.modifier.left_ctrl",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_leds_constants,
            { "Constants",                       "usbhid.boot_report.keyboard.leds.constants",
            FT_UINT8, BASE_HEX, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_leds_kana,
            { "KANA",                            "usbhid.boot_report.keyboard.leds.kana",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_leds_compose,
            { "COMPOSE",                         "usbhid.boot_report.keyboard.leds.compose",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_leds_scroll_lock,
            { "SCROLL LOCK",                     "usbhid.boot_report.keyboard.leds.scroll_lock",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_leds_caps_lock,
            { "CAPS LOCK",                       "usbhid.boot_report.keyboard.leds.caps_lock",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_keyboard_leds_num_lock,
            { "NUM LOCK",                        "usbhid.boot_report.keyboard.leds.num_lock",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_button_8,
            { "Button 8",                        "usbhid.boot_report.mouse.button.8",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_button_7,
            { "Button 7",                        "usbhid.boot_report.mouse.button.7",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_button_6,
            { "Button 6",                        "usbhid.boot_report.mouse.button.6",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_button_5,
            { "Button 5",                        "usbhid.boot_report.mouse.button.5",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_button_4,
            { "Button 4",                        "usbhid.boot_report.mouse.button.4",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_button_middle,
            { "Button Middle",                   "usbhid.boot_report.mouse.button.middle",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_button_right,
            { "Button Right",                    "usbhid.boot_report.mouse.button.right",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_button_left,
            { "Button Left",                     "usbhid.boot_report.mouse.button.left",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_x_displacement,
            { "X Displacement",                  "usbhid.boot_report.mouse.x_displacement",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_y_displacement,
            { "Y Displacement",                  "usbhid.boot_report.mouse.y_displacement",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_horizontal_scroll_wheel,
            { "Horizontal Scroll Wheel",         "usbhid.boot_report.mouse.scroll_wheel.horizontal",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_boot_report_mouse_vertical_scroll_wheel,
            { "Vertical Scroll Wheel",           "usbhid.boot_report.mouse.scroll_wheel.vertical",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_usbhid_data,
            { "Data",                            "usbhid.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *usb_hid_subtrees[] = {
        &ett_usb_hid_report,
        &ett_usb_hid_item_header,
        &ett_usb_hid_wValue,
        &ett_usb_hid_descriptor
    };

    proto_usb_hid = proto_register_protocol("USB HID", "USBHID", "usbhid");
    proto_register_field_array(proto_usb_hid, hf, array_length(hf));
    proto_register_subtree_array(usb_hid_subtrees, array_length(usb_hid_subtrees));

    /*usb_hid_boot_keyboard_input_report_handle  =*/ register_dissector("usbhid.boot_report.keyboard.input",  dissect_usb_hid_boot_keyboard_input_report,  proto_usb_hid);
    /*usb_hid_boot_keyboard_output_report_handle =*/ register_dissector("usbhid.boot_report.keyboard.output", dissect_usb_hid_boot_keyboard_output_report, proto_usb_hid);
    /*usb_hid_boot_mouse_input_report_handle     =*/ register_dissector("usbhid.boot_report.mouse.input",     dissect_usb_hid_boot_mouse_input_report,     proto_usb_hid);

}

void
proto_reg_handoff_usb_hid(void)
{
    dissector_handle_t usb_hid_control_handle, usb_hid_descr_handle;

    usb_hid_control_handle = create_dissector_handle(
                        dissect_usb_hid_control, proto_usb_hid);
    dissector_add_uint("usb.control", IF_CLASS_HID, usb_hid_control_handle);

    dissector_add_for_decode_as("usb.device", usb_hid_control_handle);

    usb_hid_descr_handle = create_dissector_handle(
                        dissect_usb_hid_class_descriptors, proto_usb_hid);
    dissector_add_uint("usb.descriptor", IF_CLASS_HID, usb_hid_descr_handle);
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
