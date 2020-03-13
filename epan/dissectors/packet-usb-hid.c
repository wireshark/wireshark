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
#define PID_PAGE                        0x0F
#define UNICODE_PAGE                    0x10
#define ALPHANUMERIC_DISPLAY_PAGE       0x14
#define MEDICAL_INSTRUMENTS_PAGE        0x40
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
#define VENDOR_PAGE_HBYTE               0xFF00
static const value_string usb_hid_item_usage_page_vals[] = {
    {0x00, "Undefined"},
    {GENERIC_DESKTOP_CONTROLS_PAGE, "Generic Desktop Controls"},
    {SIMULATION_CONTROLS_PAGE,      "Simulation Controls"},
    {VR_CONTROLS_PAGE,              "VR Controls"},
    {SPORT_CONTROLS_PAGE,           "Sport Controls"},
    {GAME_CONTROLS_PAGE,            "Game Controls"},
    {GENERIC_DEVICE_CONTROLS_PAGE,  "Generic Device Controls"},
    {KEYBOARD_KEYPAD_PAGE,          "Keyboard/Keypad"},
    {LED_PAGE,                      "LED"},
    {BUTTON_PAGE,                   "Button"},
    {ORDINAL_PAGE,                  "Ordinal"},
    {TELEPHONY_PAGE,                "Telephony"},
    {CONSUMER_PAGE,                 "Consumer"},
    {DIGITIZER_PAGE,                "Digitizer"},
    {PID_PAGE,                      "Physical Interface Device (PID)"},
    {UNICODE_PAGE,                  "Unicode"},
    {ALPHANUMERIC_DISPLAY_PAGE,     "Alphanumeric Display"},
    {MEDICAL_INSTRUMENTS_PAGE,      "Medical Instruments"},
    {USB_MONITOR_PAGE,              "USB Monitor"},
    {USB_ENUMERATED_VALUES_PAGE,    "USB Enumerated Values"},
    {VESA_VIRTUAL_CONTROLS_PAGE,    "VESA Virtual Controls"},
    {POWER_DEVICE_PAGE,             "Power Device"},
    {BATTERY_SYSTEM_PAGE,           "Battery Device"},
    {BARCODE_SCANNER_PAGE,          "Barcode Scanner"},
    {WEIGHING_PAGE,                 "Weighing"},
    {MSR_PAGE,                      "Magnetic Stripe Reading (MSR) Devices"},
    {RESERVED_POS_PAGE,             "[Reserved Point of Sale page]"},
    {CAMERA_CONTROL_PAGE,           "Camera Control Page"},
    {ARCADE_PAGE,                   "Arcade"},
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
    {0x9F, "Reserved"},
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
    {0x00, "Unidentified"},
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
    {0x00, "Unidentified"},
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
    {0x38, "[Undefined]"},
    {0x39, "Gamepad Trigger"},
    {0, NULL}
};
static const value_string usb_hid_generic_device_controls_usage_page_vals[] = {
    {0x00, "Unidentified"},
    {0x20, "Battery Strength"},
    {0x21, "Wireless Channel"},
    {0x22, "Wireless ID"},
    {0x23, "Discover Wireless Control"},
    {0x24, "Security Code Character Entered"},
    {0x25, "Security Code Character Erased"},
    {0x26, "Security Code Cleared"},
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
    {0x43, "Keyboard F11"},
    {0x44, "Keyboard F12"},
    {0x45, "Keyboard F13"},
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
    {0xDF, "Reserved"},
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
    {0, NULL}
};
static const value_string usb_hid_button_usage_page_vals[] = {
    {0x00, "No button pressed"},
    {0x01, "Button 1 (primary/trigger)"},
    {0x02, "Button 2 (secondary)"},
    {0x03, "Button 3 (tertiary)"},
    {0, NULL}
};
static const value_string usb_hid_ordinal_usage_page_vals[] = {
    {0x00, "Reserved"},
    {0, NULL}
};
static const value_string usb_hid_telephony_device_usage_page_vals[] = {
    {0x00, "Unassigned"},
    {0x01, "Phone"},
    {0x02, "Answering Machine"},
    {0x03, "Message Controls"},
    {0x04, "Handset"},
    {0x05, "Headset"},
    {0x06, "Telephony Key Pad"},
    {0x07, "Programmable Button"},
    {0x20, "Hook Switch"},
    {0x21, "Flash"},
    {0x22, "Feature"},
    {0x23, "Hold"},
    {0x24, "Redial"},
    {0x25, "Transfer"},
    {0x26, "Drop"},
    {0x27, "Park"},
    {0x28, "Forward Calls"},
    {0x29, "Alternate Function"},
    {0x2A, "Line"},
    {0x2B, "Speaker Phone"},
    {0x2C, "Conference"},
    {0x2D, "Ring Enable"},
    {0x2E, "Ring Select"},
    {0x2F, "Phone Mute"},
    {0x30, "Caller ID"},
    {0x31, "Send"},
    {0x50, "Speed Dial"},
    {0x51, "Store Number"},
    {0x52, "Recall Number"},
    {0x53, "Phone Directory"},
    {0x70, "Voice Mail"},
    {0x71, "Screen Calls"},
    {0x72, "Do Not Disturb"},
    {0x73, "Message"},
    {0x74, "Answer On/Off"},
    {0x90, "Inside Dial Tone"},
    {0x91, "Outside Dial Tone"},
    {0x92, "Inside Ring Tone"},
    {0x93, "Outside Ring Tone"},
    {0x94, "Priority Ring Tone"},
    {0x95, "Inside Ringback"},
    {0x96, "Priority Ringback"},
    {0x97, "Line Busy Tone"},
    {0x98, "Reorder Tone"},
    {0x99, "Call Waiting Tone"},
    {0x9A, "Confirmation Tone 1"},
    {0x9B, "Confirmation Tone 2"},
    {0x9C, "Tones Off"},
    {0x9D, "Outside Ringback"},
    {0x9E, "Ringer"},
    {0xB0, "Phone Key 0"},
    {0xB1, "Phone Key 1"},
    {0xB2, "Phone Key 2"},
    {0xB3, "Phone Key 3"},
    {0xB4, "Phone Key 4"},
    {0xB5, "Phone Key 5"},
    {0xB6, "Phone Key 6"},
    {0xB7, "Phone Key 7"},
    {0xB8, "Phone Key 8"},
    {0xB9, "Phone Key 9"},
    {0xBA, "Phone Key Star"},
    {0xBB, "Phone Key Pound"},
    {0xBC, "Phone Key A"},
    {0xBD, "Phone Key B"},
    {0xBE, "Phone Key C"},
    {0xBF, "Phone Key D"},
    {0, NULL}
};
static const value_string usb_hid_consumer_usage_page_vals[] = {
    {0x000, "Unassigned"},
    {0x001, "Consumer Control"},
    {0x002, "Numeric Key Pad"},
    {0x003, "Programmable Buttons"},
    {0x004, "Microphone"},
    {0x005, "Headphone"},
    {0x006, "Graphic Equalizer"},
    {0x01F, "Reserved"},
    {0x020, "+10"},
    {0x021, "+100"},
    {0x022, "AM/PM"},
    {0x02F, "Reserved"},
    {0x030, "Power"},
    {0x031, "Reset"},
    {0x032, "Sleep"},
    {0x033, "Sleep After"},
    {0x034, "Sleep Mode"},
    {0x035, "Illumination"},
    {0x036, "Function Buttons"},
    {0x03F, "Reserved"},
    {0x040, "Menu"},
    {0x041, "Menu Pick"},
    {0x042, "Menu Up"},
    {0x043, "Menu Down"},
    {0x044, "Menu Left"},
    {0x045, "Menu Right"},
    {0x046, "Menu Escape"},
    {0x047, "Menu Value Increase"},
    {0x048, "Menu Value Decrease"},
    {0x05F, "Reserved"},
    {0x060, "Data On Screen"},
    {0x061, "Closed Caption"},
    {0x062, "Closed Caption Select"},
    {0x063, "VCR/TV"},
    {0x064, "Broadcast Mode"},
    {0x065, "Snapshot"},
    {0x066, "Still"},
    {0x07F, "Reserved"},
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
    {0x091, "Media Select CD "},
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
    {0x09F, "Reserved"},
    {0x0A0, "VCR Plus"},
    {0x0A1, "Once"},
    {0x0A2, "Daily"},
    {0x0A3, "Weekly"},
    {0x0A4, "Monthly"},
    {0x0AF, "Reserved"},
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
    {0x0DF, "Reserved"},
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
    {0x0EF, "Reserved"},
    {0x0F0, "Speed Select"},
    {0x0F1, "Playback Speed"},
    {0x0F2, "Standard Play"},
    {0x0F3, "Long Play"},
    {0x0F4, "Extended Play"},
    {0x0F5, "Slow"},
    {0x0FF, "Reserved"},
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
    {0x14F, "Reserved"},
    {0x150, "Balance Right"},
    {0x151, "Balance Left"},
    {0x152, "Bass Increment"},
    {0x153, "Bass Decrement"},
    {0x154, "Treble Increment"},
    {0x155, "Treble Decrement"},
    {0x15F, "Reserved"},
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
    {0x16F, "Reserved"},
    {0x170, "Sub-channel"},
    {0x171, "Sub-channel Increment"},
    {0x172, "Sub-channel Decrement"},
    {0x173, "Alternate Audio Increment"},
    {0x174, "Alternate Audio Decrement"},
    {0x17F, "Reserved"},
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
    {0x1BB, "Reserved"},
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
    {0x1FF, "Reserved"},
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
    {0x219, "[Undefined]"},
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
    {0x247, "AC Flip horizontal"},
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
    {0x29B, "AC Disribute Horizontally"},
    {0x29C, "AC Distribute Vertically"},
    {0, NULL}
};
static const value_string usb_hid_digitizers_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Digitizer"},
    {0x02, "Pen"},
    {0x03, "Light Pen"},
    {0x04, "Touch Screen"},
    {0x05, "Touch Pad"},
    {0x06, "White Board"},
    {0x07, "Coordinate Measuring Machine"},
    {0x08, "3D Digitizer"},
    {0x09, "Stereo Plotter"},
    {0x0A, "Articulated Arm"},
    {0x0B, "Armature"},
    {0x0C, "Multiple Point Digitizer"},
    {0x0D, "Free Space Wand"},
    {0x20, "Stylus"},
    {0x21, "Puck"},
    {0x22, "Finger"},
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
static const value_string usb_hid_alphanumeric_display_usage_page_vals[] = {
    {0x00, "Undefined"},
    {0x01, "Alphanumeric Display"},
    {0x02, "Bitmapped Display"},
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
    {0x83, "Bit Depth Format"},
    {0x84, "Display Orientation"},
    {0x85, "Palette Report"},
    {0x86, "Palette Data Size"},
    {0x87, "Palette Data Offset"},
    {0x88, "Palette Data"},
    {0x89, "[Undefined]"},
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
    {0, NULL}
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
    {0x3F, "Reserved"},
    {0x40, "Cine"},
    {0x41, "Transmit Power"},
    {0x42, "Volume"},
    {0x43, "Focus"},
    {0x44, "Depth"},
    {0x60, "Soft Step - Primary"},
    {0x61, "Soft Step - Secondary"},
    {0x6F, "Reserved"},
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
    {0x8B, "Rechargable"},
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
value_string_ext keycode_vals_ext = VALUE_STRING_EXT_INIT(keycode_vals);

/* Returns usage page string */
static const char*
get_usage_page_string(guint32 usage_page)
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
static gchar*
get_usage_page_item_string(guint32 usage_page, guint32 id)
{
    const char *str = NULL;

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
            str = "Button %u";
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
            str = "Instance %u";
        break;
    case DIGITIZER_PAGE:
        str = try_val_to_str(id, usb_hid_digitizers_usage_page_vals);
        break;
    case PID_PAGE:
        str = try_val_to_str(id, usb_hid_physical_input_device_usage_page_vals);
        break;
    case UNICODE_PAGE:
        str = "Character U+%04X";
        break;
    case ALPHANUMERIC_DISPLAY_PAGE:
        str = try_val_to_str(id, usb_hid_alphanumeric_display_usage_page_vals);
        break;
    case MEDICAL_INSTRUMENTS_PAGE:
        str = try_val_to_str(id, usb_hid_medical_instrument_usage_page_vals);
        break;
    case USB_MONITOR_PAGE:
        str = try_val_to_str(id, usb_hid_monitor_usage_page_vals);
        break;
    case USB_ENUMERATED_VALUES_PAGE:
        str = "ENUM_%u";
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
    case ARCADE_PAGE:
        str = try_val_to_str(id, usb_hid_arcade_usage_page_vals);
        break;
    default:
        if ((usage_page & VENDOR_PAGE_HBYTE) == VENDOR_PAGE_HBYTE)
            str = "Vendor";
        break;
    }

    if (!str)
        str = "Reserved";

    return g_strdup_printf(str, id);
}

/* Dissector for the data in a HID main report. */
static int
dissect_usb_hid_report_mainitem_data(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, unsigned int bSize, unsigned int bTag)
{
    proto_item *ti = proto_tree_get_parent(tree);
    guint32 val;

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
                proto_tree_add_boolean_format_value(tree, hf_usb_hid_mainitem_bit8, tvb, offset, 0, FALSE, "Buffered bytes (default, no second byte present)");

            val = tvb_get_guint8(tvb, offset);
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
            proto_item_append_text(ti, " (%s)", rval_to_str(val, usb_hid_mainitem_colltype_vals, "Unknown"));
            break;
        case USBHID_MAINITEM_TAG_ENDCOLLECTION:
            /* No item data */
            break;
        default:
            proto_tree_add_item(tree, hf_usb_hid_item_unk_data, tvb, offset, bSize, ENC_NA);
            proto_item_append_text(ti, " (Unkown)");
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
    guint32 val;
    gint32 val_sig;

    switch (bTag) {
        case USBHID_GLOBALITEM_TAG_USAGE_PAGE:
            switch (bSize) {
                case 1: global->usage_page = tvb_get_guint8(tvb, offset); break;
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
                proto_item_append_text(ti, " (%d)", val);
            else
                proto_item_append_text(ti, " (%d)", 16-val);
            break;
        case USBHID_GLOBALITEM_TAG_UNIT:
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_sys, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_len, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_mass, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_time, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_temp, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_current, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_usb_hid_globalitem_unit_brightness, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            proto_item_append_text(ti, " (0x%02x)", tvb_get_guint8(tvb, offset));
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_SIZE:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_report_size, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (%d)", val);
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_ID:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_report_id, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_GLOBALITEM_TAG_REPORT_COUNT:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_report_count, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (%d)", val);
            break;
        case USBHID_GLOBALITEM_TAG_PUSH:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_push, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (%d)", val);
            break;
        case USBHID_GLOBALITEM_TAG_POP:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_globalitem_pop, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (%d)", val);
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
dissect_usb_hid_report_localitem_data(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, unsigned int bSize, unsigned int bTag, struct usb_hid_global_state *global)
{
    guint32 id = 0xffff;
    proto_item *ti = proto_tree_get_parent(tree);
    gchar *str = NULL;
    guint32 val;

    switch (bTag) {
        case USBHID_LOCALITEM_TAG_USAGE_PAGE:
            if (bSize > 2) {
                /* Full page ID */
                proto_tree_add_item(tree, hf_usb_hid_localitem_usage, tvb, offset, bSize, ENC_LITTLE_ENDIAN);
            } else {
                /* Only lower few bits given, need to combine with last global ID */
                if (bSize == 1)
                    id = tvb_get_guint8(tvb, offset);
                else if (bSize == 2)
                    id = tvb_get_ntohs(tvb, offset);
                str = get_usage_page_item_string(global->usage_page, id);
                proto_tree_add_uint_format(tree, hf_usb_hid_localitem_usage, tvb, offset, bSize, id, "Usage: %s (0x%02x)", str, id);
                proto_item_append_text(ti, " (%s)", str);
            }
            break;
        case USBHID_LOCALITEM_TAG_USAGE_MIN:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_usage_min, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
            proto_item_append_text(ti, " (0x%02x)", val);
            break;
        case USBHID_LOCALITEM_TAG_USAGE_MAX:
            proto_tree_add_item_ret_uint(tree, hf_usb_hid_localitem_usage, tvb, offset, bSize, ENC_LITTLE_ENDIAN, &val);
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

    g_free(str);

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

        subtree = proto_tree_add_subtree_format(parent_tree, tvb, offset, bSize + 1, ett_usb_hid_item_header, &subitem, "%s", val_to_str(bTag, usb_hid_cur_bTag_vals, "Unknown/%u tag"));

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
        if (usb_trans_info->u.get_descriptor.type == USB_DT_HID_REPORT)
            offset = dissect_usb_hid_get_report_descriptor(pinfo, tree, tvb, offset, usb_conv_info);
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
        if (type == RQT_SETUP_TYPE_STANDARD)
            return dissect_usb_hid_control_std_intf(tvb, pinfo, tree, usb_conv_info);
        else if (type == RQT_SETUP_TYPE_CLASS)
            return dissect_usb_hid_control_class_intf(tvb, pinfo, tree, usb_conv_info);
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

    dissect_usb_descriptor_header(desc_tree, tvb, offset, &hid_descriptor_type_vals_ext);
    offset += 2;
    proto_tree_add_item(desc_tree, hf_usb_hid_bcdHID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(desc_tree, hf_usb_hid_bCountryCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    num_desc = tvb_get_guint8(tvb, offset);
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
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_log_min,
            { "Logical minimum", "usbhid.item.global.log_min", FT_INT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_log_max,
            { "Logical maximum", "usbhid.item.global.log_max", FT_INT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_phy_min,
            { "Physical minimum", "usbhid.item.global.phy_min", FT_INT8, BASE_DEC,
                NULL, 0, NULL, HFILL }},

        { &hf_usb_hid_globalitem_phy_max,
            { "Physical maximum", "usbhid.item.global.phy_max", FT_INT8, BASE_DEC,
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
            { "Data", "usbhid.data", FT_NONE, BASE_NONE,
                NULL, 0x00, NULL, HFILL }},
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
