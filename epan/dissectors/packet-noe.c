/* packet-noe.c
 * Routines for UA/UDP (Universal Alcatel over UDP) and NOE packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include "epan/packet.h"
#include <epan/wmem/wmem.h>

void proto_register_noe(void);
void proto_reg_handoff_noe(void);

#define OPCODE_C_context             0
#define OPCODE_C_terminal            1
#define OPCODE_C_keyboard            2
#define OPCODE_C_audioconfig         3
#define OPCODE_C_security            4
#define OPCODE_C_leds                5
#define OPCODE_C_screen              6
#define OPCODE_C_date                7
#define OPCODE_C_AOMV                8
#define OPCODE_C_bluetooth           9
#define OPCODE_C_callstate          12
#define OPCODE_C_resource           13
#define OPCODE_C_widgets_default    14
#define OPCODE_C_framebox          128
#define OPCODE_C_tabbox            129
#define OPCODE_C_listbox           130
#define OPCODE_C_actionlistbox     131
#define OPCODE_C_textbox           132
#define OPCODE_C_actionbox         133
#define OPCODE_C_inputbox          134
#define OPCODE_C_checkbox          135
#define OPCODE_C_datebox           136
#define OPCODE_C_timerbox          137
#define OPCODE_C_popupbox          138
#define OPCODE_C_dialogbox         139
#define OPCODE_C_sliderbar         140
#define OPCODE_C_progressbar       141
#define OPCODE_C_imagebox          142
#define OPCODE_C_iconbox           143
#define OPCODE_C_AOMVbox           144
#define OPCODE_C_telephonicbox     145
#define OPCODE_C_keyboard_context  146
#define OPCODE_C_AOMEL             147
#define OPCODE_C_AOM10             148
#define OPCODE_C_AOM40             149
#define OPCODE_C_idletimer         150
#define OPCODE_C_telephonicboxitem 151
#define OPCODE_C_bluetooth_device  152
#define OPCODE_C_headerbox         153
#define OPCODE_C_ime_context       154

static const value_string val_str_class[] = {
    {OPCODE_C_context           , "Context"},
    {OPCODE_C_terminal          , "Terminal"},
    {OPCODE_C_keyboard          , "Keyboard"},
    {OPCODE_C_audioconfig       , "AudioConfig"},
    {OPCODE_C_security          , "Security"},
    {OPCODE_C_leds              , "Leds"},
    {OPCODE_C_screen            , "Screen"},
    {OPCODE_C_date              , "Date"},
    {OPCODE_C_AOMV              , "AOMV"},
    {OPCODE_C_bluetooth         , "Bluetooth"},
    {OPCODE_C_callstate         , "Callstate"},
    {OPCODE_C_framebox          , "FrameBox"},
    {OPCODE_C_tabbox            , "TabBox"},
    {OPCODE_C_listbox           , "ListBox"},
    {OPCODE_C_actionlistbox     , "ActionlistBox"},
    {OPCODE_C_textbox           , "TextBox"},
    {OPCODE_C_actionbox         , "ActionBox"},
    {OPCODE_C_inputbox          , "InputBox"},
    {OPCODE_C_checkbox          , "CheckBox"},
    {OPCODE_C_datebox           , "DateBox"},
    {OPCODE_C_timerbox          , "TimerBox"},
    {OPCODE_C_popupbox          , "PopupBox"},
    {OPCODE_C_dialogbox         , "DialogBox"},
    {OPCODE_C_sliderbar         , "SliderBar"},
    {OPCODE_C_progressbar       , "ProgressBar"},
    {OPCODE_C_imagebox          , "ImageBox"},
    {OPCODE_C_iconbox           , "IconBox"},
    {OPCODE_C_AOMVbox           , "AOMVBox"},
    {OPCODE_C_telephonicbox     , "TelephonicBox"},
    {OPCODE_C_keyboard_context  , "Keyboard_context"},
    {OPCODE_C_AOMEL             , "AOMEL"},
    {OPCODE_C_AOM10             , "AOM10"},
    {OPCODE_C_AOM40             , "AOM40"},
    {OPCODE_C_idletimer         , "IdleTimer"},
    {OPCODE_C_telephonicboxitem , "TelephonicBoxItem"},
    {OPCODE_C_bluetooth_device  , "Bluetooth_device"},
    {OPCODE_C_headerbox         , "HeaderBox"},
    {OPCODE_C_ime_context       , "ime_context"},
    {0, NULL}
};
static value_string_ext val_str_class_ext = VALUE_STRING_EXT_INIT(val_str_class);

#define OPCODE_P_B_objectid              0
#define OPCODE_P_B_ownership             1
#define OPCODE_P_B_reset_mode            2
#define OPCODE_P_B_mtu                   3
#define OPCODE_P_B_negative_ack          4
#define OPCODE_P_B_type                  5
#define OPCODE_P_B_help_timeout          6
#define OPCODE_P_B_longpress             7
#define OPCODE_P_B_count                 8
#define OPCODE_P_B_eventmode             9
#define OPCODE_P_B_numpad_ownership     10
#define OPCODE_P_B_navigator_ownership  11
#define OPCODE_P_B_telephony_ownership  12
#define OPCODE_P_B_progkeys_ownership   13
#define OPCODE_P_B_alphakeys_ownership  14
#define OPCODE_P_B_numpad_eventmode     15
#define OPCODE_P_B_onoff                16
#define OPCODE_P_B_bpp                  17
#define OPCODE_P_B_w                    18
#define OPCODE_P_B_h                    19
#define OPCODE_P_B_contrast             20
#define OPCODE_P_B_clearscreen          21
#define OPCODE_P_B_year                 24
#define OPCODE_P_B_month                25
#define OPCODE_P_B_day                  26
#define OPCODE_P_B_m                    27
#define OPCODE_P_B_s                    28
#define OPCODE_P_B_enable               29
#define OPCODE_P_B_address              30
#define OPCODE_P_B_port                 31
#define OPCODE_P_B_protocol             32
#define OPCODE_P_B_name                 33
#define OPCODE_P_B_checked              34
#define OPCODE_P_B_unchecked            35
#define OPCODE_P_B_anchorid             36
#define OPCODE_P_B_grid                 37
#define OPCODE_P_B_x                    38
#define OPCODE_P_B_y                    39
#define OPCODE_P_B_visible              40
#define OPCODE_P_B_border               41
#define OPCODE_P_B_fontid               42
#define OPCODE_P_B_active               43
#define OPCODE_P_B_halign               44
#define OPCODE_P_B_valign               45
#define OPCODE_P_B_size                 46
#define OPCODE_P_B_mode                 47
#define OPCODE_P_B_showevent            48
#define OPCODE_P_B_showactive           49
#define OPCODE_P_B_action_active        50
#define OPCODE_P_B_action_count         51
#define OPCODE_P_B_foreground           52
#define OPCODE_P_B_background           53
#define OPCODE_P_B_icon                 54
#define OPCODE_P_B_label                55
#define OPCODE_P_B_value                56
#define OPCODE_P_B_password             57
#define OPCODE_P_B_cursor               58
#define OPCODE_P_B_mask                 59
#define OPCODE_P_B_qos_ticket           60
#define OPCODE_P_B_focus                61
#define OPCODE_P_B_state                62
#define OPCODE_P_B_format               63
#define OPCODE_P_B_incdec               64
#define OPCODE_P_B_value_notify         65
#define OPCODE_P_B_timeout              66
#define OPCODE_P_B_min                  67
#define OPCODE_P_B_max                  68
#define OPCODE_P_B_data                 69
#define OPCODE_P_B_custversion          70
#define OPCODE_P_B_L10Nversion          71
#define OPCODE_P_B_append               72
#define OPCODE_P_B_shortpress           73
#define OPCODE_P_B_autorepeat           74
#define OPCODE_P_B_repetition           75
#define OPCODE_P_B_vsplit               76
#define OPCODE_P_B_accesskey            77
#define OPCODE_P_B_realcount            78
#define OPCODE_P_B_start                79
#define OPCODE_P_B_modal                80
#define OPCODE_P_B_session_timeout      81
#define OPCODE_P_B_softkeys_ownership   82
#define OPCODE_P_B_ringings_count       83
#define OPCODE_P_B_cod                  84
#define OPCODE_P_B_bonded               85
#define OPCODE_P_B_link_key             86
#define OPCODE_P_B_pin                  87
#define OPCODE_P_B_term_type            88
#define OPCODE_P_B_link_type            89
#define OPCODE_P_B_circular             90
#define OPCODE_P_B_autospread           91
#define OPCODE_P_B_backlight_timeout    92
#define OPCODE_P_B_screensaver_timeout  93
#define OPCODE_P_B_cycling              94
#define OPCODE_P_B_CS_idle_state        95
#define OPCODE_P_B_PS_idle_state        96
#define OPCODE_P_B_bonded_devices       97
#define OPCODE_P_B_serialnum            98
#define OPCODE_P_B_hardversion          99
#define OPCODE_P_B_softversion         100
#define OPCODE_P_B_rom_size            101
#define OPCODE_P_B_ram_size            102
#define OPCODE_P_B_reset_cause         103
#define OPCODE_P_B_cycling_time        104
#define OPCODE_P_B_inputborder         106
#define OPCODE_P_B_disablelongpress    107
#define OPCODE_P_B_all_icons_off       108
#define OPCODE_P_B_all_labels_off      109
#define OPCODE_P_B_widgets_size        110
#define OPCODE_P_B_list_type           111
#define OPCODE_P_B_frame_type          112
#define OPCODE_P_B_bth_ringing         113
#define OPCODE_P_B_URI                 114
#define OPCODE_P_B_fetch_timeout       115
#define OPCODE_P_B_mask_subst          116
#define OPCODE_P_B_use_customisation   117
#define OPCODE_P_B_ADTTS_request       118
#define OPCODE_P_B_AP_mac_notify       119
#define OPCODE_P_B_page_active         120
#define OPCODE_P_B_overwrite           121
#define OPCODE_P_B_ime_lock            122
#define OPCODE_P_B_method              123
#define OPCODE_P_B_login               124
#define OPCODE_P_B_binary_suffix       125
#define OPCODE_P_B_binary_count        126
#define OPCODE_P_B_SIPCversion         127
#define OPCODE_P_A_dflt                128
#define OPCODE_P_A_shift               129
#define OPCODE_P_A_alt                 130
#define OPCODE_P_A_key_ownership       131
#define OPCODE_P_A_key_eventmode       132
#define OPCODE_P_A_value               133
#define OPCODE_P_A_mode                134
#define OPCODE_P_A_color               135
#define OPCODE_P_A_type                136
#define OPCODE_P_A_icon                137
#define OPCODE_P_A_label               138
#define OPCODE_P_A_ownership           139
#define OPCODE_P_A_enable              140
#define OPCODE_P_A_state               141
#define OPCODE_P_A_name                142
#define OPCODE_P_A_number              143
#define OPCODE_P_A_action_icon         144
#define OPCODE_P_A_action_label        145
#define OPCODE_P_A_action_value        146
#define OPCODE_P_A_today               147
#define OPCODE_P_A_tomorrow            148
#define OPCODE_P_A_action_key          149
#define OPCODE_P_A_code                150
#define OPCODE_P_A_data                151
#define OPCODE_P_A_delay_max_handset   152
#define OPCODE_P_A_delay_max_handsfree 153
#define OPCODE_P_A_delay_tx            154
#define OPCODE_P_A_delay_rx            155
#define OPCODE_P_A_pem_data            156
#define OPCODE_P_A_serial_number       157
#define OPCODE_P_A_owner_name          158
#define OPCODE_P_A_issuer_name         159
#define OPCODE_P_A_end_date            160

static const value_string val_str_props[] = {
    {OPCODE_P_B_objectid            , "objectid"},
    {OPCODE_P_B_ownership           , "ownership"},
    {OPCODE_P_B_reset_mode          , "reset_mode"},
    {OPCODE_P_B_mtu                 , "mtu"},
    {OPCODE_P_B_negative_ack        , "negative_ack"},
    {OPCODE_P_B_type                , "type"},
    {OPCODE_P_B_help_timeout        , "help_timeout"},
    {OPCODE_P_B_longpress           , "longpress"},
    {OPCODE_P_B_count               , "count"},
    {OPCODE_P_B_eventmode           , "eventmode"},
    {OPCODE_P_B_numpad_ownership    , "numpad_ownership"},
    {OPCODE_P_B_navigator_ownership , "navigator_ownership"},
    {OPCODE_P_B_telephony_ownership , "telephony_ownership"},
    {OPCODE_P_B_progkeys_ownership  , "progkeys_ownership"},
    {OPCODE_P_B_alphakeys_ownership , "alphakeys_ownership"},
    {OPCODE_P_B_numpad_eventmode    , "numpad_eventmode"},
    {OPCODE_P_B_onoff               , "onoff"},
    {OPCODE_P_B_bpp                 , "bpp"},
    {OPCODE_P_B_w                   , "w"},
    {OPCODE_P_B_h                   , "h"},
    {OPCODE_P_B_contrast            , "contrast"},
    {OPCODE_P_B_clearscreen         , "clearscreen"},
    {OPCODE_P_B_year                , "year"},
    {OPCODE_P_B_month               , "month"},
    {OPCODE_P_B_day                 , "day"},
    {OPCODE_P_B_m                   , "m"},
    {OPCODE_P_B_s                   , "s"},
    {OPCODE_P_B_enable              , "enable"},
    {OPCODE_P_B_address             , "address"},
    {OPCODE_P_B_name                , "name"},
    {OPCODE_P_B_anchorid            , "anchorid"},
    {OPCODE_P_B_grid                , "grid"},
    {OPCODE_P_B_x                   , "x"},
    {OPCODE_P_B_y                   , "y"},
    {OPCODE_P_B_visible             , "visible"},
    {OPCODE_P_B_border              , "border"},
    {OPCODE_P_B_fontid              , "fontid"},
    {OPCODE_P_B_active              , "active"},
    {OPCODE_P_B_halign              , "halign"},
    {OPCODE_P_B_valign              , "valign"},
    {OPCODE_P_B_size                , "size"},
    {OPCODE_P_B_mode                , "mode"},
    {OPCODE_P_B_showevent           , "showevent"},
    {OPCODE_P_B_showactive          , "showactive"},
    {OPCODE_P_B_icon                , "icon"},
    {OPCODE_P_B_label               , "label"},
    {OPCODE_P_B_value               , "value"},
    {OPCODE_P_B_password            , "password"},
    {OPCODE_P_B_cursor              , "cursor"},
    {OPCODE_P_B_mask                , "mask"},
    {OPCODE_P_B_qos_ticket          , "qos_ticket"},
    {OPCODE_P_B_focus               , "focus"},
    {OPCODE_P_B_state               , "state"},
    {OPCODE_P_B_format              , "format"},
    {OPCODE_P_B_incdec              , "incdec"},
    {OPCODE_P_B_value_notify        , "value_notify"},
    {OPCODE_P_B_timeout             , "timeout"},
    {OPCODE_P_B_min                 , "min"},
    {OPCODE_P_B_max                 , "max"},
    {OPCODE_P_B_data                , "data"},
    {OPCODE_P_B_custversion         , "custversion"},
    {OPCODE_P_B_L10Nversion         , "L10Nversion"},
    {OPCODE_P_B_append              , "append"},
    {OPCODE_P_B_shortpress          , "shortpress"},
    {OPCODE_P_B_autorepeat          , "autorepeat"},
    {OPCODE_P_B_repetition          , "repetition"},
    {OPCODE_P_B_vsplit              , "vsplit"},
    {OPCODE_P_B_accesskey           , "accesskey"},
    {OPCODE_P_B_realcount           , "realcount"},
    {OPCODE_P_B_start               , "start"},
    {OPCODE_P_B_modal               , "modal"},
    {OPCODE_P_B_session_timeout     , "session_timeout"},
    {OPCODE_P_B_softkeys_ownership  , "softkeys_ownership"},
    {OPCODE_P_B_ringings_count      , "ringings_count"},
    {OPCODE_P_B_cod                 , "cod"},
    {OPCODE_P_B_bonded              , "bonded"},
    {OPCODE_P_B_link_key            , "link_key"},
    {OPCODE_P_B_pin                 , "pin"},
    {OPCODE_P_B_term_type           , "term_type"},
    {OPCODE_P_B_link_type           , "link_type"},
    {OPCODE_P_B_circular            , "circular"},
    {OPCODE_P_B_autospread          , "autospread"},
    {OPCODE_P_B_backlight_timeout   , "backlight_timeout"},
    {OPCODE_P_B_screensaver_timeout , "screensaver_timeout"},
    {OPCODE_P_B_cycling             , "cycling"},
    {OPCODE_P_B_CS_idle_state       , "CS_idle_state"},
    {OPCODE_P_B_PS_idle_state       , "PS_idle_state"},
    {OPCODE_P_B_bonded_devices      , "bonded_devices"},
    {OPCODE_P_B_serialnum           , "serialnum"},
    {OPCODE_P_B_hardversion         , "hardversion"},
    {OPCODE_P_B_softversion         , "softversion"},
    {OPCODE_P_B_rom_size            , "rom_size"},
    {OPCODE_P_B_ram_size            , "ram_size"},
    {OPCODE_P_B_reset_cause         , "reset_cause"},
    {OPCODE_P_B_cycling_time        , "cycling_time"},
    {OPCODE_P_B_inputborder         , "inputborder"},
    {OPCODE_P_B_disablelongpress    , "disablelongpress"},
    {OPCODE_P_B_all_icons_off       , "all_icons_off"},
    {OPCODE_P_B_all_labels_off      , "all_labels_off"},
    {OPCODE_P_B_widgets_size        , "widgets_size"},
    {OPCODE_P_B_list_type           , "list_type"},
    {OPCODE_P_B_frame_type          , "frame_type"},
    {OPCODE_P_B_bth_ringing         , "bth_ringing"},
    {OPCODE_P_B_URI                 , "URI"},
    {OPCODE_P_B_fetch_timeout       , "fetch_timeout"},
    {OPCODE_P_B_mask_subst          , "mask_subst"},
    {OPCODE_P_B_use_customisation   , "use_customisation"},
    {OPCODE_P_B_page_active         , "page_active"},
    {OPCODE_P_B_overwrite           , "overwrite"},
    {OPCODE_P_B_ime_lock            , "ime_lock"},
    {OPCODE_P_B_method              , "method"},
    {OPCODE_P_B_login               , "login"},
    {OPCODE_P_B_binary_suffix       , "binary_suffix"},
    {OPCODE_P_B_binary_count        , "binary_count"},
    {OPCODE_P_B_SIPCversion         , "SIPCversion"},
    {OPCODE_P_A_key_ownership       , "key_ownership"},
    {OPCODE_P_A_key_eventmode       , "key_eventmode"},
    {OPCODE_P_A_value               , "value"},
    {OPCODE_P_A_mode                , "mode"},
    {OPCODE_P_A_color               , "color"},
    {OPCODE_P_A_type                , "type"},
    {OPCODE_P_A_icon                , "icon"},
    {OPCODE_P_A_label               , "label"},
    {OPCODE_P_A_ownership           , "ownership"},
    {OPCODE_P_A_enable              , "enable"},
    {OPCODE_P_A_state               , "state"},
    {OPCODE_P_A_name                , "name"},
    {OPCODE_P_A_number              , "number"},
    {OPCODE_P_A_action_icon         , "action_icon"},
    {OPCODE_P_A_action_label        , "action_label"},
    {OPCODE_P_A_action_value        , "action_value"},
    {OPCODE_P_A_today               , "today"},
    {OPCODE_P_A_tomorrow            , "tomorrow"},
    {OPCODE_P_A_code                , "code"},
    {OPCODE_P_A_data                , "data"},
    {OPCODE_P_A_delay_max_handset   , "delay_max_handset"},
    {OPCODE_P_A_delay_max_handsfree , "delay_max_handsfree"},
    {OPCODE_P_A_delay_tx            , "delay_tx"},
    {OPCODE_P_A_delay_rx            , "delay_rx"},
    {OPCODE_P_A_pem_data            , "pem_data"},
    {OPCODE_P_A_serial_number       , "serial_number"},
    {OPCODE_P_A_owner_name          , "owner_name"},
    {OPCODE_P_A_issuer_name         , "issuer_name"},
    {OPCODE_P_A_end_date            , "end_date"},
    {0, NULL}
};
static value_string_ext val_str_props_ext = VALUE_STRING_EXT_INIT(val_str_props);

#define OPCODE_EVT_CONTEXT_SWITCH         0
#define OPCODE_EVT_RESET                  1
#define OPCODE_EVT_KEY_PRESS              2
#define OPCODE_EVT_KEY_RELEASE            3
#define OPCODE_EVT_KEY_SHORTPRESS         4
#define OPCODE_EVT_KEY_LONGPRESS          5
#define OPCODE_EVT_ONHOOK                 6
#define OPCODE_EVT_OFFHOOK                7
#define OPCODE_EVT_HELP                   8
#define OPCODE_EVT_WIDGETS_GC             9
#define OPCODE_EVT_ERROR_PROTOCOL        10
#define OPCODE_EVT_ERROR_CREATE          11
#define OPCODE_EVT_ERROR_DELETE          12
#define OPCODE_EVT_ERROR_SET_PROPERTY    13
#define OPCODE_EVT_ERROR_GET_PROPERTY    14
#define OPCODE_EVT_SUCCESS_CREATE        15
#define OPCODE_EVT_SUCCESS_DELETE        16
#define OPCODE_EVT_SUCCESS_SET_PROPERTY  17
#define OPCODE_EVT_ERROR_INSERT_ITEM     18
#define OPCODE_EVT_ERROR_DELETE_ITEM     19
#define OPCODE_EVT_SUCCESS_INSERT_ITEM   20
#define OPCODE_EVT_DEVICE_PRESENCE       21
#define OPCODE_EVT_KEY_LINE              22
#define OPCODE_EVT_SUCCESS_DELETE_ITEM   23
#define OPCODE_EVT_BT_BONDING_RESULT     24
#define OPCODE_EVT_BT_KEY_SHORTPRESS     25
#define OPCODE_EVT_BT_KEY_LONGPRESS      26
#define OPCODE_EVT_BT_KEY_VERYLONGPRESS  27
#define OPCODE_EVT_LOCAL_APPLICATION     28
#define OPCODE_EVT_WARNING_CREATE        29
#define OPCODE_EVT_WARNING_SET_PROPERTY  30
#define OPCODE_EVT_ARP_SPOOFING          31
#define OPCODE_EVT_CHAR_NOT_FOUND        32
#define OPCODE_EVT_CHAR_BAD_LENGTH       33
#define OPCODE_EVT_QOS_TICKET            34
#define OPCODE_EVT_UA3_ERROR             35
#define OPCODE_EVT_TABBOX               128
#define OPCODE_EVT_LISTBOX              129
#define OPCODE_EVT_LISTBOX_FIRST        130
#define OPCODE_EVT_LISTBOX_LAST         131
#define OPCODE_EVT_ACTIONLISTBOX        132
#define OPCODE_EVT_ACTIONBOX            133
#define OPCODE_EVT_INPUTBOX             134
#define OPCODE_EVT_INPUTBOX_FOCUS_LOST  135
#define OPCODE_EVT_CHECKBOX             136
#define OPCODE_EVT_TIMERBOX             137
#define OPCODE_EVT_POPUPBOX_TIMEOUT     138
#define OPCODE_EVT_DIALOGBOX            139
#define OPCODE_EVT_SLIDERBAR            140
#define OPCODE_EVT_PROGRESSBAR          141
#define OPCODE_EVT_AOMVBOX              142
#define OPCODE_EVT_TELEPHONICBOX_FOCUS  143
#define OPCODE_EVT_AOM_INSERTED         144
#define OPCODE_EVT_AOM_REMOVED          145
#define OPCODE_EVT_AOM_KEY_PRESS        146
#define OPCODE_EVT_IDLETIMER            147
#define OPCODE_EVT_GET_PROPERTY_RESULT  148
#define OPCODE_EVT_AOM_KEY_RELEASE      149
#define OPCODE_EVT_POPUPBOX_DISMISSED   150
#define OPCODE_EVT_DIALOGBOX_TIMEOUT    151
#define OPCODE_EVT_DIALOGBOX_DISMISSED  152
#define OPCODE_EVT_BT_BONDED_DEVICE     153
#define OPCODE_EVT_BT_INQUIRY_RESULT    154
#define OPCODE_EVT_BT_NAME_DISCOVERY    155
#define OPCODE_EVT_IME_REMOTEOPEN       156
#define OPCODE_EVT_BT_BATTERY           158
#define OPCODE_EVT_IME_LIST             159
#define OPCODE_EVT_IME_CHANGE           160
#define OPCODE_EVT_IME_OPEN             161
#define OPCODE_EVT_TELEPHONICBOX_EVENT  162
#define OPCODE_EVT_ACTLISTBOX_TIMEOUT   163
#define OPCODE_EVT_ACTLISTBOX_DISMISSED 164
#define OPCODE_EVT_ADTTS_RESPONSE       165
#define OPCODE_EVT_AP_MAC               166

static const value_string val_str_event[] = {
    {OPCODE_EVT_CONTEXT_SWITCH       , "EVT_CONTEXT_SWITCH"},
    {OPCODE_EVT_RESET                , "EVT_RESET"},
    {OPCODE_EVT_KEY_PRESS            , "EVT_KEY_PRESS"},
    {OPCODE_EVT_KEY_RELEASE          , "EVT_KEY_RELEASE"},
    {OPCODE_EVT_KEY_SHORTPRESS       , "EVT_KEY_SHORTPRESS"},
    {OPCODE_EVT_KEY_LONGPRESS        , "EVT_KEY_LONGPRESS"},
    {OPCODE_EVT_ONHOOK               , "EVT_ONHOOK"},
    {OPCODE_EVT_OFFHOOK              , "EVT_OFFHOOK"},
    {OPCODE_EVT_HELP                 , "EVT_HELP"},
    {OPCODE_EVT_WIDGETS_GC           , "EVT_WIDGETS_GC"},
    {OPCODE_EVT_ERROR_PROTOCOL       , "EVT_ERROR_PROTOCOL"},
    {OPCODE_EVT_ERROR_CREATE         , "EVT_ERROR_CREATE"},
    {OPCODE_EVT_ERROR_DELETE         , "EVT_ERROR_DELETE"},
    {OPCODE_EVT_ERROR_SET_PROPERTY   , "EVT_ERROR_SET_PROPERTY"},
    {OPCODE_EVT_ERROR_GET_PROPERTY   , "EVT_ERROR_GET_PROPERTY"},
    {OPCODE_EVT_SUCCESS_CREATE       , "EVT_SUCCESS_CREATE"},
    {OPCODE_EVT_SUCCESS_DELETE       , "EVT_SUCCESS_DELETE"},
    {OPCODE_EVT_SUCCESS_SET_PROPERTY , "EVT_SUCCESS_SET_PROPERTY"},
    {OPCODE_EVT_ERROR_INSERT_ITEM    , "EVT_ERROR_INSERT_ITEM"},
    {OPCODE_EVT_ERROR_DELETE_ITEM    , "EVT_ERROR_DELETE_ITEM"},
    {OPCODE_EVT_SUCCESS_INSERT_ITEM  , "EVT_SUCCESS_INSERT_ITEM"},
    {OPCODE_EVT_DEVICE_PRESENCE      , "EVT_DEVICE_PRESENCE"},
    {OPCODE_EVT_KEY_LINE             , "EVT_KEY_LINE"},
    {OPCODE_EVT_SUCCESS_DELETE_ITEM  , "EVT_SUCCESS_DELETE_ITEM"},
    {OPCODE_EVT_BT_BONDING_RESULT    , "EVT_BT_BONDING_RESULT"},
    {OPCODE_EVT_BT_KEY_SHORTPRESS    , "EVT_BT_KEY_SHORTPRESS"},
    {OPCODE_EVT_BT_KEY_LONGPRESS     , "EVT_BT_KEY_LONGPRESS"},
    {OPCODE_EVT_BT_KEY_VERYLONGPRESS , "EVT_BT_KEY_VERYLONGPRESS"},
    {OPCODE_EVT_LOCAL_APPLICATION    , "EVT_LOCAL_APPLICATION"},
    {OPCODE_EVT_WARNING_CREATE       , "EVT_WARNING_CREATE"},
    {OPCODE_EVT_WARNING_SET_PROPERTY , "EVT_WARNING_SET_PROPERTY"},
    {OPCODE_EVT_ARP_SPOOFING         , "EVT_ARP_SPOOFING"},
    {OPCODE_EVT_CHAR_NOT_FOUND       , "EVT_CHAR_NOT_FOUND"},
    {OPCODE_EVT_QOS_TICKET           , "EVT_QOS_TICKET"},
    {OPCODE_EVT_UA3_ERROR            , "EVT_UA3_ERROR"},
    {OPCODE_EVT_TABBOX               , "EVT_TABBOX"},
    {OPCODE_EVT_LISTBOX              , "EVT_LISTBOX"},
    {OPCODE_EVT_LISTBOX_FIRST        , "EVT_LISTBOX_FIRST"},
    {OPCODE_EVT_LISTBOX_LAST         , "EVT_LISTBOX_LAST"},
    {OPCODE_EVT_ACTIONLISTBOX        , "EVT_ACTIONLISTBOX"},
    {OPCODE_EVT_ACTIONBOX            , "EVT_ACTIONBOX"},
    {OPCODE_EVT_INPUTBOX             , "EVT_INPUTBOX"},
    {OPCODE_EVT_INPUTBOX_FOCUS_LOST  , "EVT_INPUTBOX_FOCUS_LOST"},
    {OPCODE_EVT_CHECKBOX             , "EVT_CHECKBOX"},
    {OPCODE_EVT_TIMERBOX             , "EVT_TIMERBOX"},
    {OPCODE_EVT_POPUPBOX_TIMEOUT     , "EVT_POPUPBOX_TIMEOUT"},
    {OPCODE_EVT_DIALOGBOX            , "EVT_DIALOGBOX"},
    {OPCODE_EVT_SLIDERBAR            , "EVT_SLIDERBAR"},
    {OPCODE_EVT_PROGRESSBAR          , "EVT_PROGRESSBAR"},
    {OPCODE_EVT_AOMVBOX              , "EVT_AOMVBOX"},
    {OPCODE_EVT_TELEPHONICBOX_FOCUS  , "EVT_TELEPHONICBOX_FOCUS"},
    {OPCODE_EVT_AOM_INSERTED         , "EVT_AOM_INSERTED"},
    {OPCODE_EVT_AOM_REMOVED          , "EVT_AOM_REMOVED"},
    {OPCODE_EVT_AOM_KEY_PRESS        , "EVT_AOM_KEY_PRESS"},
    {OPCODE_EVT_IDLETIMER            , "EVT_IDLETIMER"},
    {OPCODE_EVT_GET_PROPERTY_RESULT  , "EVT_GET_PROPERTY_RESULT"},
    {OPCODE_EVT_AOM_KEY_RELEASE      , "EVT_AOM_KEY_RELEASE"},
    {OPCODE_EVT_POPUPBOX_DISMISSED   , "EVT_POPUPBOX_DISMISSED"},
    {OPCODE_EVT_DIALOGBOX_TIMEOUT    , "EVT_DIALOGBOX_TIMEOUT"},
    {OPCODE_EVT_DIALOGBOX_DISMISSED  , "EVT_DIALOGBOX_DISMISSED"},
    {OPCODE_EVT_BT_BONDED_DEVICE     , "EVT_BT_BONDED_DEVICE"},
    {OPCODE_EVT_BT_INQUIRY_RESULT    , "EVT_BT_INQUIRY_RESULT"},
    {OPCODE_EVT_BT_NAME_DISCOVERY    , "EVT_BT_NAME_DISCOVERY"},
    {OPCODE_EVT_IME_REMOTEOPEN       , "EVT_IME_REMOTEOPEN"},
    {OPCODE_EVT_BT_BATTERY           , "EVT_BT_BATTERY"},
    {OPCODE_EVT_IME_LIST             , "EVT_IME_LIST"},
    {OPCODE_EVT_IME_CHANGE           , "EVT_IME_CHANGE"},
    {OPCODE_EVT_IME_OPEN             , "EVT_IME_OPEN"},
    {OPCODE_EVT_TELEPHONICBOX_EVENT  , "EVT_TELEPHONICBOX_EVENT"},
    {OPCODE_EVT_ACTLISTBOX_TIMEOUT   , "EVT_ACTLISTBOX_TIMEOUT"},
    {OPCODE_EVT_ACTLISTBOX_DISMISSED , "EVT_ACTLISTBOX_DISMISSED"},
    {0, NULL}
};
static value_string_ext val_str_event_ext = VALUE_STRING_EXT_INIT(val_str_event);

#define P_BASIC           0
#define P_ARRAY         128
#define P_INVALID       255
#define P_INVALID_INDEX 255

#define C_STATIC          0
#define C_DYNAMIC       128
#define C_INVALID       255

#define E_INVALID       255


/*-----------------------------------------------------------------------------
  globals
  ---------------------------------------------------------------------------*/
static int  proto_noe           = -1;
static gint ett_noe             = -1;
static gint ett_body            = -1;
static gint ett_property        = -1;
static gint ett_value           = -1;

static int  hf_noe_length               = -1;
static int  hf_noe_server               = -1;
static int  hf_noe_method_ack           = -1;
static int  hf_noe_method               = -1;
static int  hf_noe_class                = -1;
static int  hf_noe_event                = -1;
static int  hf_noe_objectid             = -1;
static int  hf_noe_method_index         = -1;
static int  hf_noe_pcode                = -1;
static int  hf_noe_psize                = -1;
static int  hf_noe_aindx                = -1;
static int  hf_noe_errcode              = -1;
static int  hf_noe_value                = -1;
static int  hf_noe_message              = -1;
static int  hf_noe_property_item_u8     = -1;
static int  hf_noe_property_item_u16    = -1;
static int  hf_noe_property_item_u24    = -1;
static int  hf_noe_property_item_u32    = -1;
static int  hf_noe_property_item_bytes  = -1;
static int  hf_event_value_u8           = -1;
static int  hf_event_context_switch     = -1;
static int  hf_event_widget_gc          = -1;

static const value_string servers_vals[] = {
    {0x15,  "Call Server"},
    {0x16,  "Presentation Server"},
    {0, NULL}
};
static const value_string servers_short_vals[] = {
    {0x15,  "CS"},
    {0x16,  "PS"},
    {0, NULL}
};

enum
{
    METHOD_CREATE       = 0x00,
    METHOD_DELETE       = 0x01,
    METHOD_SET_PROPERTY = 0x02,
    METHOD_GET_PROPERTY = 0x03,
    METHOD_NOTIFY       = 0x04,
    METHOD_DELETE_ITEM  = 0x05,
    METHOD_INSERT_ITEM  = 0x06,
    METHOD_INVALID
};
static const value_string methods_vals[] = {
    {METHOD_CREATE       , "Create"},
    {METHOD_DELETE       , "Delete"},
    {METHOD_SET_PROPERTY , "SetProperty"},
    {METHOD_GET_PROPERTY , "GetProperty"},
    {METHOD_NOTIFY       , "Notify"},
    {METHOD_DELETE_ITEM  , "DeleteItem"},
    {METHOD_INSERT_ITEM  , "InsertItem"},
    {0, NULL}
};


#define ERROR_INVALID_METHOD         0
#define ERROR_UNKNOWN_CLASS          1
#define ERROR_STATIC_CLASS           2
#define ERROR_DUPLICATE_OBJECTID     3
#define ERROR_UNKNOWN_PROPERTY_      4
#define ERROR_BAD_INDEX              5
#define ERROR_BAD_LENGTH__           6
#define ERROR_REQUIRED_MISSING       7
#define ERROR_BAD_VALUE              8
#define ERROR_READONLY_PROPERTY      9
#define ERROR_UNKNOWN_OBJECTID      10
#define ERROR_INVALID_CONTAINER     11
#define ERROR_PROPERTY_VMIN         12
#define ERROR_PROPERTY_VMAX         13
#define ERROR_POSITIVE_ACK          14
#define ERROR_NOT_IMPLEMENTED       15
#define ERROR_INVALID_CLASS         16
#define ERROR_INVALID_PROPERTY      17
#define ERROR_BAD_UTF8              18

#define ERROR_MESSAGE_DROP         128
#define ERROR_MAX_SET_PROPERTY     129
#define ERROR_INTERNAL             130


static const value_string errcode_vals[] = {
    {ERROR_INVALID_METHOD       , "An invalid method opcode was received"},
    {ERROR_UNKNOWN_CLASS        , "An invalid class opcode was received"},
    {ERROR_STATIC_CLASS         , "Trying to create or delete a static class"},
    {ERROR_DUPLICATE_OBJECTID   , "Trying to create an existing object"},
    {ERROR_UNKNOWN_PROPERTY_    , "Property opcode doesn't exist in specified class"},
    {ERROR_BAD_INDEX            , "Bad property index (array overflow)"},
    {ERROR_BAD_LENGTH__         , "Short message or bad property length"},
    {ERROR_REQUIRED_MISSING     , "A required property was not specified in create method"},
    {ERROR_BAD_VALUE            , "Bad property value"},
    {ERROR_READONLY_PROPERTY    , "Trying to set a read-only property"},
    {ERROR_UNKNOWN_OBJECTID     , "The specified object doesn't exist (delete, setProperty or getProperty methods)"},
    {ERROR_INVALID_CONTAINER    , "Invalid container"},
    {ERROR_PROPERTY_VMIN        , "Property value < property minimum value"},
    {ERROR_PROPERTY_VMAX        , "Property value > property maximum value"},
    {ERROR_POSITIVE_ACK         , "Positive ack requested with a getProperty method"},
    {ERROR_NOT_IMPLEMENTED      , "The specified property is not implemented"},
    {ERROR_INVALID_CLASS        , "Invalid class specified with insertItem and deleteItem"},
    {ERROR_INVALID_PROPERTY     , "Invalid property specified with insertItem and deleteItem"},
    {ERROR_BAD_UTF8             , "Invalid UTF8 value in UA message"},
    {ERROR_MESSAGE_DROP         , "Decoder queue is full"},
    {ERROR_MAX_SET_PROPERTY     , "A maximum of 256 properties can be received in a setProperty method"},
    {ERROR_INTERNAL             , "Internal error"},
    {0, NULL}
};
static value_string_ext errcode_vals_ext = VALUE_STRING_EXT_INIT(errcode_vals);

static const value_string str_key_name[] = {
    {0x00   , "Null Char."},
    {0x01   , "Start Of Header"},
    {0x02   , "Start Of Text"},
    {0x03   , "End Of Text"},
    {0x04   , "End Of Transmission"},
    {0x05   , "Enquiry"},
    {0x06   , "Acknowledgment"},
    {0x07   , "Bell"},
    {0x08   , "Backspace"},
    {0x09   , "Horizontal Tab"},
    {0x0A   , "Line Feed"},
    {0x0B   , "Vertical Tab"},
    {0x0C   , "Form Feed"},
    {0x0D   , "Enter"},
    {0x0E   , "Shift Out"},
    {0x0F   , "Shift In"},
    {0x10   , "Data Link Escape"},
    {0x11   , "Device Control 1"},
    {0x12   , "Device Control 2"},
    {0x13   , "Device Control 3"},
    {0x14   , "Device Control 4"},
    {0x15   , "Negative Acknowledgment"},
    {0x16   , "Synchronous Idle"},
    {0x17   , "End Of Trans. Block"},
    {0x18   , "Cancel"},
    {0x19   , "End Of Medium"},
    {0x1A   , "Substitute"},
    {0x1B   , "Escape"},
    {0x1C   , "File Separator"},
    {0x1D   , "Group Separator"},
    {0x1E   , "Request To Send"},
    {0x1F   , "Unit Separator"},
    {0x20   , "Space"},
    {0x7F   , "Delete"},
    {0xE0   , "a`"},
    {0xE7   , "c,"},
    {0xE8   , "e`"},
    {0xE9   , "e'"},
    {0xF9   , "u`"},
    {0x20AC , "Euro Character"},
    {0xE100 , "Release"},
    {0xE101 , "Bis"},
    {0xE102 , "Message"},
    {0xE103 , "Handsfree"},
    {0xE104 , "Mute"},
    {0xE105 , "Volume Dec"},
    {0xE106 , "Volume Inc"},
    {0xE107 , "Hookswitch"},
    {0xE110 , "Ok"},
    {0xE111 , "Left"},
    {0xE112 , "Right"},
    {0xE113 , "Down"},
    {0xE114 , "Up"},
    {0xE115 , "Home"},
    {0xE116 , "Help"},
    {0xE117 , "Directory"},
    {0xE120 , "ProgKey 0"},
    {0xE121 , "ProgKey 1"},
    {0xE122 , "ProgKey 2"},
    {0xE123 , "ProgKey 3"},
    {0xE124 , "ProgKey 4"},
    {0xE125 , "ProgKey 5"},
    {0xE130 , "SoftKey 0"},
    {0xE131 , "SoftKey 1"},
    {0xE132 , "SoftKey 2"},
    {0xE133 , "SoftKey 3"},
    {0xE134 , "SoftKey 4"},
    {0xE135 , "SoftKey 5"},
    {0xE136 , "SoftKey 6"},
    {0xE137 , "SoftKey 7"},
    {0xE138 , "SoftKey 8"},
    {0xE139 , "SoftKey 9"},
    {0, NULL}
};
static value_string_ext str_key_name_ext = VALUE_STRING_EXT_INIT(str_key_name);

static const value_string noe_event_str_struct[] = {
    {0x00, "RJ9 Plug"},
    {0x01, "BT Handset Link"},
    {0, NULL}
    };

/*-----------------------------------------------------------------------------
    DECODE UTF8 TO UNICODE
    This function translates an UTF8 vale to an UNICODE one.
    Need to have at least 48 bits value.
    ---------------------------------------------------------------------------*/
static guint64 decode_utf8(guint64 utf8)
{
    static guint64 unicode;

    if (utf8 <= G_GUINT64_CONSTANT(0xFF))
    {
        unicode =
            utf8 & G_GUINT64_CONSTANT(0x7F);
    }
    else if (utf8 <= G_GUINT64_CONSTANT(0xFFFF))
    {
        unicode =
            ((utf8 & G_GUINT64_CONSTANT(0x1F00) >> 2) +
             (utf8 & G_GUINT64_CONSTANT(0x3F)));
    }
    else if (utf8 <= G_GUINT64_CONSTANT(0xFFFFFF))
    {
        unicode =
            ((utf8 & G_GUINT64_CONSTANT(0x0F0000)) >> 4) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F00)) >> 2) +
            (utf8 & G_GUINT64_CONSTANT(0x3F));
    }
    else if (utf8 <= G_GUINT64_CONSTANT(0xFFFFFFFF))
    {
        unicode =
            ((utf8 & G_GUINT64_CONSTANT(0x07000000)) >> 6) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F0000)) >> 4) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F00)) >> 2) +
            (utf8 & G_GUINT64_CONSTANT(0x3F));
    }
    else if (utf8 <= G_GUINT64_CONSTANT(0xFFFFFFFFFF))
    {
        unicode =
            ((utf8 & G_GUINT64_CONSTANT(0x0300000000)) >> 8) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F000000)) >> 6) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F0000)) >> 4) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F00)) >> 2) +
            (utf8 & G_GUINT64_CONSTANT(0x3F));
    }
    else if (utf8 <= G_GUINT64_CONSTANT(0xFFFFFFFFFFFF))
    {
        unicode =
            ((utf8 & G_GUINT64_CONSTANT(0x010000000000)) >> 10) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F00000000)) >> 8) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F000000)) >> 6) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F0000)) >> 4) +
            ((utf8 & G_GUINT64_CONSTANT(0x3F00)) >> 2) +
            (utf8 & G_GUINT64_CONSTANT(0x3F));
    }
    else
    {
        unicode = G_GUINT64_CONSTANT(0);
    }
    return unicode;
}


/*-----------------------------------------------------------------------------
    DECODE KEY NAME
    This function translates an UNICODE to the name associated.
    Need to have at least 48 bits value.
    ---------------------------------------------------------------------------*/
static char *decode_key_name(int unicode)
{
    char *key_name;

    key_name = (char *)wmem_alloc(wmem_packet_scope(), 10);

    if ((unicode <= 0x20)
        || (unicode == 0x7F)
        || (unicode == 0xE0)
        || (unicode == 0xE7)
        || (unicode == 0xE8)
        || (unicode == 0xE9)
        || (unicode == 0xF9))
    {
        g_snprintf(key_name, 10, "%s", val_to_str_ext_const(unicode, &str_key_name_ext, "Unknown"));
    }
    else if (unicode <= 0xFF)
    {
        g_snprintf(key_name, 10, "%c", unicode);
    }
    else
    {
        g_snprintf(key_name, 10, "%s", val_to_str_ext_const(unicode, &str_key_name_ext, "Unknown"));
    }
    return key_name;
}


/*-----------------------------------------------------------------------------
    DECODE EVT ERROR
    ---------------------------------------------------------------------------*/
static void decode_evt_error(proto_tree *tree,
                             tvbuff_t   *tvb,
                             guint       offset,
                             guint       length)
{
    if (!tree)
        return;

    proto_tree_add_item(tree, hf_noe_errcode, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    length -= 2;

    proto_tree_add_item(tree, hf_noe_method, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset  += 1;
    length  -= 1;

    proto_tree_add_item(tree, hf_noe_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset  += 1;
    length  -= 1;

    proto_tree_add_item(tree, hf_noe_objectid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    length -= 2;

    proto_tree_add_item(tree, hf_noe_pcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset  += 1;
    length  -= 1;

    proto_tree_add_item(tree, hf_noe_aindx, tvb, offset, 1, ENC_NA);
    offset  += 1;
    length  -= 1;

    proto_tree_add_item(tree, hf_noe_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    length -= 2;

    proto_tree_add_item(tree, hf_noe_value, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    length -= 4;

    proto_tree_add_item(tree, hf_noe_message, tvb, offset, length, ENC_NA);
}


/*-----------------------------------------------------------------------------
    MESSAGE BODY DECODER
    This function decodes the message body of an 0x15 (and 0x16) UA3G message.
    ---------------------------------------------------------------------------*/
static void decode_tlv(proto_tree *tree,
                       tvbuff_t   *tvb,
                       guint       offset,
                       guint       length)
{
    proto_item *property_item;
    proto_tree *property_tree;
    guint8      property_type;
    guint16     property_length;
/*  guint64     property_index;*/

    /* add text to the frame tree */
    property_item = proto_tree_add_text(tree,
        tvb,
        offset,
        length,
        "NOE Message Body");
    property_tree = proto_item_add_subtree(property_item, ett_body);

    while(length > 0)
    {
        property_type = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(property_tree, hf_noe_pcode, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        length -= 1;

        if (property_type >= P_ARRAY)
        {
            proto_tree_add_item(property_item, hf_noe_aindx, tvb, offset, 1, ENC_NA);
            offset += 1;
            length -= 1;
        }

        property_length = tvb_get_guint8(tvb, offset);
        if (property_length & 0x80)
        {
            property_length = tvb_get_ntohs(tvb, offset);
            property_length &= 0x7fff;
            proto_tree_add_uint(property_tree, hf_noe_psize, tvb, offset, 2,
                tvb_get_guint8(tvb, offset) * 256 + tvb_get_guint8(tvb, offset+1));
            offset += 2;
            length -= 2;
        }
        else
        {
            proto_tree_add_uint(property_tree, hf_noe_psize, tvb, offset, 1,
                tvb_get_guint8(tvb, offset));
            offset += 1;
            length -= 1;
        }

        switch(property_length)
        {
        case 0:
            {
                break;
            }
        case 1:
            proto_tree_add_item(property_tree, hf_noe_property_item_u8, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            length -= 1;
            break;
        case 2:
            proto_tree_add_item(property_tree, hf_noe_property_item_u16, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            length -= 2;
            break;
        case 3:
            proto_tree_add_item(property_tree, hf_noe_property_item_u24, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            length -= 3;
            break;
        case 4:
            proto_tree_add_item(property_tree, hf_noe_property_item_u32, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            length -= 4;
            break;
        default:
            proto_tree_add_item(property_tree, hf_noe_property_item_bytes, tvb, offset, property_length, ENC_NA);
            offset += property_length;
            length -= property_length;
            break;
        }
    }
}



/*-----------------------------------------------------------------------------
    GETPROPERTY MESSAGE BODY DECODER
    This function decodes the message body of an 0x15 (and 0x16) UA3G message.
    ---------------------------------------------------------------------------*/
static void decode_getproperty_tlv(proto_tree *tree,
                                   tvbuff_t   *tvb,
                                   guint       offset,
                                   guint       length)
{
    proto_item *body_item;
    proto_tree *body_tree;
    guint8      body_type;

    /* add text to the frame tree */
    body_item = proto_tree_add_text(tree,
        tvb,
        offset,
        length,
        "NOE Message Body");
    body_tree = proto_item_add_subtree(body_item, ett_property);

    while(length > 0)
    {
        body_type = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(body_tree, hf_noe_pcode, tvb, offset, 1, ENC_BIG_ENDIAN);

        offset += 1;
        length -= 1;

        if (body_type >= P_ARRAY)
        {
            proto_tree_add_item(body_item, hf_noe_aindx, tvb, offset, 1, ENC_NA);
            offset += 1;
            length -= 1;
        }
    }
}



/*-----------------------------------------------------------------------------
    TERMINAL TO SERVER EVENT MESSAGE BODY DECODER
    This function decodes the message body of an 0x15 (and 0x16) UA3G message.
    ---------------------------------------------------------------------------*/
static void decode_evt(proto_tree  *tree,
                       tvbuff_t    *tvb,
                       packet_info *pinfo,
                       guint        offset,
                       guint        length)
{
    proto_item *ti;
    guint8 event = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_noe_event, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
        val_to_str_ext_const(event, &val_str_event_ext, "Unknown"));
    /* update text of the main proto item */
    proto_item_append_text(tree, ", %s",
        val_to_str_ext_const(event, &val_str_event_ext, "Unknown"));

    offset += 1;
    length -= 1;

    switch(event)
    {
    case OPCODE_EVT_BT_KEY_SHORTPRESS:
    case OPCODE_EVT_BT_KEY_LONGPRESS:
    case OPCODE_EVT_BT_KEY_VERYLONGPRESS:
    case OPCODE_EVT_KEY_LINE:
    case OPCODE_EVT_ONHOOK:
    case OPCODE_EVT_OFFHOOK:
        ti = proto_tree_add_item(tree, hf_event_value_u8, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_set_len(ti, length);
        break;
    case OPCODE_EVT_KEY_PRESS:
    case OPCODE_EVT_KEY_RELEASE:
    case OPCODE_EVT_KEY_SHORTPRESS:
    case OPCODE_EVT_KEY_LONGPRESS:
    case OPCODE_EVT_HELP:
        {
            /* utf8_value is the utf8 value to translate into Unicode with the decode_uft8 function */
            guint64  utf8_value = 0;
            guint64  unicode_value;
            char    *key_name;
            int      pt_length  = length;
            int      pt_offset  = offset;

            while(pt_length > 0)
            {
                utf8_value = (utf8_value << 8) + tvb_get_guint8(tvb, pt_offset);
                pt_offset  += 1;
                pt_length  -= 1;
            }
            unicode_value = decode_utf8(utf8_value);
            key_name      = (char *)wmem_alloc(wmem_packet_scope(), 30);
            g_snprintf(key_name, 30, "\"%s\"", decode_key_name((int)unicode_value));

            /* add text to the frame "INFO" column */
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", key_name);
            /* update text of the main proto item */
            proto_item_append_text(tree, ", %s",
                key_name);

            proto_tree_add_text(tree,
                tvb,
                offset,
                length,
                "Key Name: %s (UTF-8 Value: %s, Unicode Value: 0x%" G_GINT64_MODIFIER "x)",
                key_name,
                tvb_bytes_to_ep_str(tvb, offset, length),
                unicode_value);
            break;
        }
    case OPCODE_EVT_ERROR_PROTOCOL:
    case OPCODE_EVT_ERROR_CREATE:
    case OPCODE_EVT_ERROR_DELETE:
    case OPCODE_EVT_ERROR_SET_PROPERTY:
    case OPCODE_EVT_ERROR_GET_PROPERTY:
        {
            decode_evt_error(tree, tvb, offset, length);
            break;
        }
    case OPCODE_EVT_CONTEXT_SWITCH:
        proto_tree_add_item(tree, hf_event_context_switch, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case OPCODE_EVT_SUCCESS_CREATE:
    case OPCODE_EVT_SUCCESS_DELETE:
    case OPCODE_EVT_SUCCESS_SET_PROPERTY:
    case OPCODE_EVT_SUCCESS_INSERT_ITEM:
    case OPCODE_EVT_SUCCESS_DELETE_ITEM:
        proto_tree_add_item(tree, hf_noe_objectid, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    case OPCODE_EVT_WIDGETS_GC:
        proto_tree_add_item(tree, hf_event_widget_gc, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
    case OPCODE_EVT_BT_BONDING_RESULT:
        {
            proto_tree_add_item(tree, hf_noe_objectid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /*length -= 2;*/

            /* XXX - should a 16-bit value be gotten if the size is only 8-bit? */
            proto_tree_add_text(tree,
                tvb,
                offset,
                1,
                "Bonded: %d",
                tvb_get_ntohs(tvb, offset));
            offset += 1;
            /*length -= 1;*/

            proto_tree_add_text(tree,
                tvb,
                offset,
                1,
                "Value: %d",
                tvb_get_ntohs(tvb, offset));
            break;
        }
    default:
        proto_tree_add_item(tree, hf_noe_objectid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        length -= 2;

        if (length > 0)
            decode_tlv(tree, tvb, offset, length);
        break;
    }
}



/*-----------------------------------------------------------------------------
    METHOD DECODER
    This function decodes the method of an 0x15 (and 0x16) UA3G message.
    ---------------------------------------------------------------------------*/
static void decode_mtd(proto_tree  *tree,
                       tvbuff_t    *tvb,
                       packet_info *pinfo,
                       guint8       method,
                       guint        offset,
                       guint        length)
{
    guint8 noe_class = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_noe_class, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
        val_to_str_ext_const(noe_class, &val_str_class_ext, "Unknown"));
    /* update text of the main proto item */
    proto_item_append_text(tree, ", %s",
        val_to_str_ext_const(noe_class, &val_str_class_ext, "Unknown"));

    offset += 1;
    length -= 1;

    if (noe_class >= C_DYNAMIC)
    {
        proto_tree_add_item(tree, hf_noe_objectid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        length -= 2;
    }

    switch(method)
    {
    case METHOD_INSERT_ITEM:
        {
            proto_tree_add_item(tree, hf_noe_method_index, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            length -= 1;
            if (length > 0)
                decode_tlv(tree, tvb, offset, length);
            break;
        }
    case METHOD_DELETE_ITEM:
        {
            proto_tree_add_item(tree, hf_noe_method_index, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        }
    case METHOD_GET_PROPERTY:
        {
            decode_getproperty_tlv(tree, tvb, offset, length);
            break;
        }
    default:
        {
            if (length > 0)
                decode_tlv(tree, tvb, offset, length);
            break;
        }
    }
}


/*-----------------------------------------------------------------------------
  NOE DISSECTOR
  ---------------------------------------------------------------------------*/
static void dissect_noe(tvbuff_t    *tvb,
                        packet_info *pinfo,
                        proto_tree  *tree)
{
    proto_item *noe_item;
    proto_tree *noe_tree;
    gint        length;
    guint8      server;
    guint8      method;
    gboolean    methodack;
    gint        offset    = 0;

    noe_item = proto_tree_add_item(tree, proto_noe, tvb, 0, -1, ENC_NA);
    noe_tree = proto_item_add_subtree(noe_item, ett_noe);

    length = tvb_get_letohs(tvb, offset);

    proto_tree_add_uint(noe_tree,
        hf_noe_length,
        tvb,
        offset,
        2,
        length);
    offset += 2;

    server = tvb_get_guint8(tvb, offset);

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " - NOE Protocol (%s)",
        val_to_str_const(server, servers_short_vals, "Unknown"));

    proto_tree_add_uint(noe_tree,
        hf_noe_server,
        tvb,
        offset,
        1,
        server);
    offset += 1;
    length -= 1;

    /* update text of the main proto item */
    proto_item_append_text(noe_item, ", %s",
        val_to_str_const(server, servers_short_vals, "Unknown"));

    method    = tvb_get_guint8(tvb, offset);
    methodack = (method & 0x80) != 0;
    method    = (method & 0x7f);

    proto_tree_add_uint_format_value(noe_tree,
        hf_noe_method,
        tvb,
        offset,
        1,
        method,
        "%s (%d)",
        val_to_str_const(method, methods_vals, "Unknown"),
        method);

    if (method >= METHOD_INVALID)
        return;

    /* add text to the frame "INFO" column */
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
        val_to_str_const(method, methods_vals, "Unknown"));

    /* update text of the main proto item */
    proto_item_append_text(noe_item, ", %s",
        val_to_str_const(method, methods_vals, "Unknown"));

    if (method == METHOD_NOTIFY)
    {
        offset += 1;
        length -= 1;
        decode_evt(noe_tree, tvb, pinfo, offset, length);
    }
    else
    /* Create, Delete, SetProperty, GetProperty, DeleteItem, InsertItem properties */
    {
        proto_tree_add_boolean(noe_tree,
            hf_noe_method_ack,
            tvb,
            offset,
            1,
            methodack);
        offset += 1;
        length -= 1;
        decode_mtd(noe_tree, tvb, pinfo, method, offset, length);
    }
}



/*-----------------------------------------------------------------------------
  DISSECTORS REGISTRATION FUNCTIONS
  ---------------------------------------------------------------------------*/
void proto_register_noe(void)
{
    static hf_register_info hf_noe[] =
        {
            { &hf_noe_length,
              {
                  "Length",
                  "noe.length",
                  FT_UINT16,
                  BASE_DEC,
                  NULL,
                  0x0,
                  "Method Length",
                  HFILL
              }
            },
            { &hf_noe_server,
              {
                  "Server",
                  "noe.server",
                  FT_UINT8,
                  BASE_HEX,
                  VALS(servers_vals),
                  0x0,
                  "Method Opcode",
                  HFILL
              }
            },
            { &hf_noe_method_ack,
              {
                  "Ack",
                  "noe.method_ack",
                  FT_BOOLEAN,
                  BASE_NONE,
                  NULL,
                  0x0,
                  "Method Acknowledge",
                  HFILL
              }
            },
            { &hf_noe_method,
              {
                  "Method",
                  "noe.method",
                  FT_UINT8,
                  BASE_DEC,
                  VALS(methods_vals),
                  0x0,
                  "Method Opcode",
                  HFILL
              }
            },
            { &hf_noe_class,
              {
                  "Class",
                  "noe.class",
                  FT_UINT8,
                  BASE_DEC|BASE_EXT_STRING,
                  &val_str_class_ext,
                  0x0,
                  "Class Opcode",
                  HFILL
              }
            },
            { &hf_noe_event,
              {
                  "Event",
                  "noe.event",
                  FT_UINT8,
                  BASE_DEC|BASE_EXT_STRING,
                  &val_str_event_ext,
                  0x0,
                  "Event Opcode",
                  HFILL
              }
            },
            { &hf_noe_objectid,
              {
                  "Objectid",
                  "noe.objectid",
                  FT_UINT16,
                  BASE_HEX,
                  NULL,
                  0x0,
                  "Object Identifier",
                  HFILL
              }
            },
            { &hf_noe_method_index,
              {
                  "ItemIndx",
                  "noe.item_index",
                  FT_UINT8,
                  BASE_DEC,
                  NULL,
                  0x0,
                  "Delete/Insert Index",
                  HFILL
              }
            },
            { &hf_noe_pcode,
              {
                  "Property",
                  "noe.property",
                  FT_UINT8,
                  BASE_HEX|BASE_EXT_STRING,
                  &val_str_props_ext,
                  0x0,
                  "Property Identifier",
                  HFILL
              }
            },
            { &hf_noe_psize,
              {
                  "PropLength",
                  "noe.prop_len",
                  FT_UINT16,
                  BASE_DEC,
                  NULL,
                  0x0,
                  "Property Length",
                  HFILL
              }
            },
            { &hf_noe_errcode,
              {
                  "ErrCode",
                  "noe.errcode",
                  FT_UINT16,
                  BASE_DEC|BASE_EXT_STRING,
                  &errcode_vals_ext,
                  0x0,
                  "Error Code",
                  HFILL
              }
            },
            { &hf_noe_aindx,
              {
                  "ArrIndex",
                  "noe.array_index",
                  FT_UINT8,
                  BASE_DEC,
                  NULL,
                  0x0,
                  "Array Index",
                  HFILL
              }
            },
            { &hf_noe_value,
              {
                  "Value",
                  "noe.value",
                  FT_UINT32,
                  BASE_HEX,
                  NULL,
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_noe_message,
              {
                  "Message",
                  "noe.messages",
                  FT_BYTES,
                  BASE_NONE,
                  NULL,
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_noe_property_item_u8,
              {
                  "Value",
                  "noe.property_item.uint",
                  FT_UINT8,
                  BASE_DEC,
                  NULL,
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_noe_property_item_u16,
              {
                  "Value",
                  "noe.property_item.uint",
                  FT_UINT16,
                  BASE_DEC,
                  NULL,
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_noe_property_item_u24,
              {
                  "Value",
                  "noe.property_item.uint",
                  FT_UINT24,
                  BASE_DEC,
                  NULL,
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_noe_property_item_u32,
              {
                  "Value",
                  "noe.property_item.uint",
                  FT_UINT32,
                  BASE_DEC,
                  NULL,
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_noe_property_item_bytes,
              {
                  "Value",
                  "noe.property_item.bytes",
                  FT_BYTES,
                  BASE_NONE,
                  NULL,
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_event_value_u8,
              {
                  "Value",
                  "noe.event_value.uint",
                  FT_UINT8,
                  BASE_DEC,
                  VALS(noe_event_str_struct),
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_event_context_switch,
              {
                  "Context",
                  "noe.event_context_switch",
                  FT_UINT8,
                  BASE_DEC,
                  VALS(servers_vals),
                  0x0,
                  NULL,
                  HFILL
              }
            },
            { &hf_event_widget_gc,
              {
                  "FreeMem (bytes)",
                  "noe.event_widget_gc",
                  FT_UINT32,
                  BASE_DEC,
                  NULL,
                  0x0,
                  NULL,
                  HFILL
              }
            },
        };

    static gint *ett[] =
        {
            &ett_noe,
            &ett_body,
            &ett_property,
            &ett_value,
        };

    /* NOE dissector registration */
    proto_noe = proto_register_protocol("NOE Protocol", "NOE", "noe");

    proto_register_field_array(proto_noe, hf_noe, array_length(hf_noe));

    register_dissector("noe", dissect_noe, proto_noe);

    /* Common subtree array registration */
    proto_register_subtree_array(ett, array_length(ett));
}



void proto_reg_handoff_noe(void)
{
#if 0 /*  Future */
    dissector_handle_t handle_noe = find_dissector("noe");

    /* hooking of NOE on UA */
    dissector_add_uint("ua.opcode", 0x15, handle_noe);
#endif
}
