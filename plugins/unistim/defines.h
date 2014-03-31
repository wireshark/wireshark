/* defines.h
  * Contains all bitmask defines for unistim dissecting
  * Copyright 2007 Don Newton <dnewton@cypresscom.net>
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
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef UNISTIM_DEFINES
#define UNISTIM_DEFINES



#define QUERY_AUDIO_MGR_ATTRIBUTES 0x01
#define QUERY_AUDIO_MGR_OPTIONS    0x02
#define QUERY_AUDIO_MGR_ALERTING   0x04
#define QUERY_AUDIO_MGR_ADJ_RX_VOL 0x08
#define QUERY_AUDIO_MGR_DEF_RX_VOL 0x10
#define QUERY_AUDIO_MGR_HANDSET    0x40
#define QUERY_AUDIO_MGR_HEADSET    0x80
#define AUDIO_MGR_OPTS_MAX_VOL     0x01
#define AUDIO_MGR_ADJ_VOL          0x02
#define AUDIO_MGR_AUTO_RX_VOL_RPT  0x04
#define AUDIO_MGR_HS_ON_AIR        0x08
#define AUDIO_MGR_HD_ON_AIR        0x10
#define AUDIO_MGR_NOISE_SQUELCH    0x20
#define AUDIO_MGR_MUTE             0x01
#define AUDIO_MGR_TX_RX            0x02
#define AUDIO_MGR_ATTENUATED       0x08
#define AUDIO_MGR_VISUAL_TONE      0x01
#define AUDIO_STREAM_BASED_TONE_RX_TX 0x40
#define AUDIO_STREAM_BASED_TONE_MUTE 0x80
#define AUDIO_VOCODER_CONFIG_PARAM 0x3f
#define AUDIO_VOCODER_CONFIG_ENTITY 0xc0
#define AUDIO_VOCODER_ANNEXA      0x01
#define AUDIO_VOCODER_ANNEXB      0x02
#define AUDIO_TYPE_OF_SERVICE     0x0f
#define AUDIO_PRECENDENCE         0x70
#define AUDIO_FRF_11              0x80
#define AUDIO_RTCP_BUCKET_ID      0x0f
#define AUDIO_CLEAR_BUCKET        0x10
#define AUDIO_TRANSDUCER_PAIR_ID  0x3f
#define AUDIO_RX_ENABLE           0x40
#define AUDIO_TX_ENABLE           0x80
#define AUDIO_APB_NUMBER          0x0f
#define AUDIO_SIDETONE_DISABLE    0x10
#define AUDIO_DESTRUCT_ADD        0x20
#define AUDIO_DONT_FORCE_ACTIVE   0x40
#define AUDIO_SOURCE_DESCRIPTION  0x0f
#define AUDIO_SDES_RTCP_BUCKET    0xf0
#define AUDIO_DIRECTION_CODE      0x03
#define AUDIO_HF_SUPPORT          0x01
#define AUDIO_ENABLED_MAX_TONE    0x01
#define AUDIO_ENABLED_ADJ_VOL     0x02
#define AUDIO_AUTO_ADJ_RX_REP     0x04
#define AUDIO_HS_ON_AIR_FEATURE   0x08
#define AUDIO_HD_ON_AIR_FEATURE   0x10
#define AUDIO_NOISE_SQUELCH_DIS   0x20
#define AUDIO_APB_VOL_RPT         0x1f
#define AUDIO_VOL_UP_RPT          0x20
#define AUDIO_VOL_FLR_RPT         0x40
#define AUDIO_VOL_CEIL_RPT        0x80
#define AUDIO_ALERT_CADENCE_SEL   0x07
#define AUDIO_ALERT_WARBLER_SEL   0x38
#define AUDIO_SDES_INFO_RPT_DESC  0x0f
#define AUDIO_SDES_INFO_RPT_BUK   0xf0
#define AUDIO_STREAM_DIRECTION    0x03
#define AUDIO_STREAM_DIRECTION_RX 0x01
#define AUDIO_STREAM_DIRECTION_TX 0x02
#define AUDIO_STREAM_STATE        0x01


#define BASIC_QUERY_ATTRIBUTES    0x01
#define BASIC_QUERY_OPTIONS       0x02
#define BASIC_QUERY_FW            0x04
#define BASIC_QUERY_HW_ID         0x08
#define BASIC_QUERY_IT_TYPE       0x10
#define BASIC_QUERY_PROD_ENG_CODE 0x40
#define BASIC_QUERY_GRAY_MKT_INFO 0x80
#define BASIC_OPTION_SECURE       0x01




#define QUERY_NETWORK_MANAGER_DIAGNOSTIC    0x01
#define QUERY_NETWORK_MANAGER_MANAGERS      0x02
#define QUERY_NETWORK_MANAGER_ATTRIBUTES    0x04
#define QUERY_NETWORK_MANAGER_SERVER_INFO   0x08
#define QUERY_NETWORK_MANAGER_OPTIONS       0x10
#define QUERY_NETWORK_MANAGER_SANITY        0x80
#define NETWORK_MANAGER_ENABLE_DIAG         0x01
#define NETWORK_MANAGER_ENABLE_RUDP         0x02
#define RX_BUFFER_OVERFLOW 0x01
#define TX_BUFFER_OVERFLOW 0x02
#define RX_UNEXPECT_EMPTY  0x08
#define INVALID_MSG        0x20
#define EEPROM_INSANE      0x40
#define EEPROM_UNSAFE      0x80
#define NETWORK_MGR_REPORT_DIAG 0x01
#define NETWORK_MGR_REPORT_RUDP 0x02




#define DISPLAY_WRITE_ADDRESS_NUMERIC_FLAG    0x01
#define DISPLAY_WRITE_ADDRESS_CONTEXT_FLAG    0x02
#define DISPLAY_WRITE_ADDRESS_LINE_FLAG       0x04
#define DISPLAY_WRITE_ADDRESS_SOFT_KEY_FLAG   0x08
#define DISPLAY_WRITE_ADDRESS_SOFT_LABEL_FLAG 0x10
#define DISPLAY_WRITE_ADDRESS_SOFT_KEY_ID     0xe0
#define DISPLAY_WRITE_ADDRESS_CHAR_POS        0x1f
#define DISPLAY_WRITE_ADDRESS_LINE_NUM        0xe0
#define DISPLAY_WRITE_CURSOR_MOVE      0x01
#define DISPLAY_WRITE_CLEAR_LEFT       0x02
#define DISPLAY_WRITE_CLEAR_RIGHT      0x04
#define DISPLAY_WRITE_SHIFT_LEFT       0x08
#define DISPLAY_WRITE_SHIFT_RIGHT      0x10
#define DISPLAY_WRITE_HIGHLIGHT        0x20
#define DISPLAY_CURSOR_BLINK           0x80
#define DISPLAY_CURSOR_MOVE_CMD        0x0f

#define DISPLAY_CLEAR_NUMERIC          0x01
#define DISPLAY_CLEAR_CONTEXT          0x02
#define DISPLAY_CLEAR_DATE             0x04
#define DISPLAY_CLEAR_TIME             0x08
#define DISPLAY_CLEAR_LINE             0x10
#define DISPLAY_CLEAR_STATUS_BAR_ICON  0x20
#define DISPLAY_CLEAR_SOFTKEY          0x40
#define DISPLAY_CLEAR_SOFTKEY_LABEL    0x80

#define DISPLAY_CLEAR_LINE_1           0x01
#define DISPLAY_CLEAR_LINE_2           0x02
#define DISPLAY_CLEAR_LINE_3           0x04
#define DISPLAY_CLEAR_LINE_4           0x08
#define DISPLAY_CLEAR_LINE_5           0x10
#define DISPLAY_CLEAR_LINE_6           0x20
#define DISPLAY_CLEAR_LINE_7           0x40
#define DISPLAY_CLEAR_LINE_8           0x80

#define DISPLAY_STATUS_BAR_ICON_1           0x01
#define DISPLAY_STATUS_BAR_ICON_2           0x02
#define DISPLAY_STATUS_BAR_ICON_3           0x04
#define DISPLAY_STATUS_BAR_ICON_4           0x08
#define DISPLAY_STATUS_BAR_ICON_5           0x10
#define DISPLAY_STATUS_BAR_ICON_6           0x20
#define DISPLAY_STATUS_BAR_ICON_7           0x40
#define DISPLAY_STATUS_BAR_ICON_8           0x80
#define DISPLAY_ICON_ID                     0x1f

#define DISPLAY_SOFT_KEY_1           0x01
#define DISPLAY_SOFT_KEY_2           0x02
#define DISPLAY_SOFT_KEY_3           0x04
#define DISPLAY_SOFT_KEY_4           0x08
#define DISPLAY_SOFT_KEY_5           0x10
#define DISPLAY_SOFT_KEY_6           0x20
#define DISPLAY_SOFT_KEY_7           0x40
#define DISPLAY_SOFT_KEY_8           0x80

#define DISPLAY_CLEAR_SK_LABEL_KEY_ID  0x1f
#define DISPLAY_CLEAR_ALL_SLKS         0x20

#define KEY_LED_CADENCE          0x07
#define KEY_LED_ID               0x18

#define DISPLAY_LINE_WIDTH       0x1f
#define DISPLAY_LINES            0xe0
#define DISPLAY_SKEY_WIDTH       0x0f
#define DISPLAY_SKEYS            0x70
#define DISPLAY_ICON             0x80
#define DISPLAY_SOFTLABEL_WIDTH  0x0f
#define DISPLAY_CONTEXT_WIDTH    0xf0
#define DISPLAY_NUMERIC_WIDTH    0x03
#define DISPLAY_TIME_WIDTH       0x1c
#define DISPLAY_DATE_WIDTH       0xe0
#define DISPLAY_CHAR_DLOAD       0x0f
#define DISPLAY_FFORM_ICON_DLOAD 0x70
#define DISPLAY_ICON_TYPE        0x80
#define DISPLAY_CHARSET          0x0f
#define DISPLAY_CURSOR_NUMERIC   0x01
#define DISPLAY_CURSOR_CONTEXT   0x02
#define DISPLAY_CURSOR_LINE      0x04
#define DISPLAY_CURSOR_SKEY      0x08
#define DISPLAY_CURSOR_SKEY_ID   0xe0
#define DISPLAY_CURSOR_CHAR_POS  0x1f
#define DISPLAY_CURSOR_LINE_NUM  0xe0
#define DISPLAY_TIME_FORMAT      0x03
#define DISPLAY_DATE_FORMAT      0x0c
#define DISPLAY_USE_DATE_FORMAT  0x20
#define DISPLAY_USE_TIME_FORMAT  0x10
#define DISPLAY_CTX_FORMAT       0x0f
#define DISPLAY_CTX_FIELD        0x30
#define DISPLAY_LAYER_SKEY_ID    0x07
#define DISPLAY_LAYER_ALL_SKEYS  0x80
#define DISPLAY_ONE_OR_CYCLIC    0x80

#define DISPLAY_CALL_TIMER_MODE    0x01
#define DISPLAY_CALL_TIMER_RESET   0x02
#define DISPLAY_CALL_TIMER_DISPLAY 0x04
#define DISPLAY_CALL_TIMER_DELAY   0x08
#define DISPLAY_CALL_TIMER_ID      0x3f

#define KEY_NUM_PROG_KEYS        0x1f
#define KEY_NUM_SOFT_KEYS        0xe0
#define KEY_HD_KEY_EXISTS        0x01
#define KEY_MUTE_KEY_EXISTS      0x02
#define KEY_QUIT_KEY_EXISTS      0x04
#define KEY_COPY_KEY_EXISTS      0x08
#define KEY_MWI_EXISTS           0x10
#define KEY_NUM_NAV_KEYS         0x03
#define KEY_NUM_CONSPIC_KEYS     0x1c
#define KEY_SEND_KEY_RELEASE     0x01
#define KEY_ENABLE_VOL_KEY       0x02
#define KEY_CONSPIC_PROG_KEY0    0x08
#define KEY_ACD_SUP_CONTROL      0x10
#define KEY_LOCAL_DIAL_PAD_FEED  0x60
#define KEY_ADMIN_CMD            0xe0

#define NETWORK_FILE_XFER_MODE   0x1f
#define NETWORK_FORCE_DLOAD      0x20
#define NETWORK_USE_FSERV_PORT   0x40
#define NETWORK_USE_LOCAL_PORT   0x80



#endif
