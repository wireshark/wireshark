/* packet-x11-keysymdef.h
 * Key symbol definitions for X11 (XFree86 distribution: keysymdef.h)
 * Copyright holders: Digital, The Open Group
 * (see below for their copyright statement)
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

/* $TOG: keysymdef.h /main/28 1998/05/22 16:18:01 kaleb $ */

/***********************************************************
Copyright 1987, 1994, 1998  The Open Group

All Rights Reserved.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall
not be used in advertising or otherwise to promote the sale, use or
other dealings in this Software without prior written authorization
from The Open Group.


Copyright 1987 by Digital Equipment Corporation, Maynard, Massachusetts

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Digital not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

DIGITAL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
DIGITAL BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/
/* $XFree86: xc/include/keysymdef.h,v 1.10 2000/10/27 18:30:46 dawes Exp $ */

#define XK_VoidSymbol		0xFFFFFF	/* void symbol */

#define XK_MISCELLANY
#ifdef XK_MISCELLANY
/*
 * TTY Functions, cleverly chosen to map to ascii, for convenience of
 * programming, but could have been arbitrary (at the cost of lookup
 * tables in client code.
 */

#define XK_BackSpace		0xFF08	/* back space, back char */
#define XK_Tab			0xFF09
#define XK_Linefeed		0xFF0A	/* Linefeed, LF */
#define XK_Clear		0xFF0B
#define XK_Return		0xFF0D	/* Return, enter */
#define XK_Pause		0xFF13	/* Pause, hold */
#define XK_Scroll_Lock		0xFF14
#define XK_Sys_Req		0xFF15
#define XK_Escape		0xFF1B
#define XK_Delete		0xFFFF	/* Delete, rubout */



/* International & multi-key character composition */

#define XK_Multi_key		0xFF20  /* Multi-key character compose */
#define XK_Codeinput		0xFF37
#define XK_SingleCandidate	0xFF3C
#define XK_MultipleCandidate	0xFF3D
#define XK_PreviousCandidate	0xFF3E

/* Japanese keyboard support */

#define XK_Kanji		0xFF21	/* Kanji, Kanji convert */
#define XK_Muhenkan		0xFF22  /* Cancel Conversion */
#define XK_Henkan_Mode		0xFF23  /* Start/Stop Conversion */
#define XK_Henkan		0xFF23  /* Alias for Henkan_Mode */
#define XK_Romaji		0xFF24  /* to Romaji */
#define XK_Hiragana		0xFF25  /* to Hiragana */
#define XK_Katakana		0xFF26  /* to Katakana */
#define XK_Hiragana_Katakana	0xFF27  /* Hiragana/Katakana toggle */
#define XK_Zenkaku		0xFF28  /* to Zenkaku */
#define XK_Hankaku		0xFF29  /* to Hankaku */
#define XK_Zenkaku_Hankaku	0xFF2A  /* Zenkaku/Hankaku toggle */
#define XK_Touroku		0xFF2B  /* Add to Dictionary */
#define XK_Massyo		0xFF2C  /* Delete from Dictionary */
#define XK_Kana_Lock		0xFF2D  /* Kana Lock */
#define XK_Kana_Shift		0xFF2E  /* Kana Shift */
#define XK_Eisu_Shift		0xFF2F  /* Alphanumeric Shift */
#define XK_Eisu_toggle		0xFF30  /* Alphanumeric toggle */
#define XK_Kanji_Bangou		0xFF37  /* Codeinput */
#define XK_Zen_Koho		0xFF3D	/* Multiple/All Candidate(s) */
#define XK_Mae_Koho		0xFF3E	/* Previous Candidate */

/* 0xFF31 thru 0xFF3F are under XK_KOREAN */

/* Cursor control & motion */

#define XK_Home			0xFF50
#define XK_Left			0xFF51	/* Move left, left arrow */
#define XK_Up			0xFF52	/* Move up, up arrow */
#define XK_Right		0xFF53	/* Move right, right arrow */
#define XK_Down			0xFF54	/* Move down, down arrow */
#define XK_Prior		0xFF55	/* Prior, previous */
#define XK_Page_Up		0xFF55
#define XK_Next			0xFF56	/* Next */
#define XK_Page_Down		0xFF56
#define XK_End			0xFF57	/* EOL */
#define XK_Begin		0xFF58	/* BOL */


/* Misc Functions */

#define XK_Select		0xFF60	/* Select, mark */
#define XK_Print		0xFF61
#define XK_Execute		0xFF62	/* Execute, run, do */
#define XK_Insert		0xFF63	/* Insert, insert here */
#define XK_Undo			0xFF65	/* Undo, oops */
#define XK_Redo			0xFF66	/* redo, again */
#define XK_Menu			0xFF67
#define XK_Find			0xFF68	/* Find, search */
#define XK_Cancel		0xFF69	/* Cancel, stop, abort, exit */
#define XK_Help			0xFF6A	/* Help */
#define XK_Break		0xFF6B
#define XK_Mode_switch		0xFF7E	/* Character set switch */
#define XK_script_switch        0xFF7E  /* Alias for mode_switch */
#define XK_Num_Lock		0xFF7F

/* Keypad Functions, keypad numbers cleverly chosen to map to ascii */

#define XK_KP_Space		0xFF80	/* space */
#define XK_KP_Tab		0xFF89
#define XK_KP_Enter		0xFF8D	/* enter */
#define XK_KP_F1		0xFF91	/* PF1, KP_A, ... */
#define XK_KP_F2		0xFF92
#define XK_KP_F3		0xFF93
#define XK_KP_F4		0xFF94
#define XK_KP_Home		0xFF95
#define XK_KP_Left		0xFF96
#define XK_KP_Up		0xFF97
#define XK_KP_Right		0xFF98
#define XK_KP_Down		0xFF99
#define XK_KP_Prior		0xFF9A
#define XK_KP_Page_Up		0xFF9A
#define XK_KP_Next		0xFF9B
#define XK_KP_Page_Down		0xFF9B
#define XK_KP_End		0xFF9C
#define XK_KP_Begin		0xFF9D
#define XK_KP_Insert		0xFF9E
#define XK_KP_Delete		0xFF9F
#define XK_KP_Equal		0xFFBD	/* equals */
#define XK_KP_Multiply		0xFFAA
#define XK_KP_Add		0xFFAB
#define XK_KP_Separator		0xFFAC	/* separator, often comma */
#define XK_KP_Subtract		0xFFAD
#define XK_KP_Decimal		0xFFAE
#define XK_KP_Divide		0xFFAF

#define XK_KP_0			0xFFB0
#define XK_KP_1			0xFFB1
#define XK_KP_2			0xFFB2
#define XK_KP_3			0xFFB3
#define XK_KP_4			0xFFB4
#define XK_KP_5			0xFFB5
#define XK_KP_6			0xFFB6
#define XK_KP_7			0xFFB7
#define XK_KP_8			0xFFB8
#define XK_KP_9			0xFFB9



/*
 * Auxilliary Functions; note the duplicate definitions for left and right
 * function keys;  Sun keyboards and a few other manufactures have such
 * function key groups on the left and/or right sides of the keyboard.
 * We've not found a keyboard with more than 35 function keys total.
 */

#define XK_F1			0xFFBE
#define XK_F2			0xFFBF
#define XK_F3			0xFFC0
#define XK_F4			0xFFC1
#define XK_F5			0xFFC2
#define XK_F6			0xFFC3
#define XK_F7			0xFFC4
#define XK_F8			0xFFC5
#define XK_F9			0xFFC6
#define XK_F10			0xFFC7
#define XK_F11			0xFFC8
#define XK_L1			0xFFC8
#define XK_F12			0xFFC9
#define XK_L2			0xFFC9
#define XK_F13			0xFFCA
#define XK_L3			0xFFCA
#define XK_F14			0xFFCB
#define XK_L4			0xFFCB
#define XK_F15			0xFFCC
#define XK_L5			0xFFCC
#define XK_F16			0xFFCD
#define XK_L6			0xFFCD
#define XK_F17			0xFFCE
#define XK_L7			0xFFCE
#define XK_F18			0xFFCF
#define XK_L8			0xFFCF
#define XK_F19			0xFFD0
#define XK_L9			0xFFD0
#define XK_F20			0xFFD1
#define XK_L10			0xFFD1
#define XK_F21			0xFFD2
#define XK_R1			0xFFD2
#define XK_F22			0xFFD3
#define XK_R2			0xFFD3
#define XK_F23			0xFFD4
#define XK_R3			0xFFD4
#define XK_F24			0xFFD5
#define XK_R4			0xFFD5
#define XK_F25			0xFFD6
#define XK_R5			0xFFD6
#define XK_F26			0xFFD7
#define XK_R6			0xFFD7
#define XK_F27			0xFFD8
#define XK_R7			0xFFD8
#define XK_F28			0xFFD9
#define XK_R8			0xFFD9
#define XK_F29			0xFFDA
#define XK_R9			0xFFDA
#define XK_F30			0xFFDB
#define XK_R10			0xFFDB
#define XK_F31			0xFFDC
#define XK_R11			0xFFDC
#define XK_F32			0xFFDD
#define XK_R12			0xFFDD
#define XK_F33			0xFFDE
#define XK_R13			0xFFDE
#define XK_F34			0xFFDF
#define XK_R14			0xFFDF
#define XK_F35			0xFFE0
#define XK_R15			0xFFE0

/* Modifiers */

#define XK_Shift_L		0xFFE1	/* Left shift */
#define XK_Shift_R		0xFFE2	/* Right shift */
#define XK_Control_L		0xFFE3	/* Left control */
#define XK_Control_R		0xFFE4	/* Right control */
#define XK_Caps_Lock		0xFFE5	/* Caps lock */
#define XK_Shift_Lock		0xFFE6	/* Shift lock */

#define XK_Meta_L		0xFFE7	/* Left meta */
#define XK_Meta_R		0xFFE8	/* Right meta */
#define XK_Alt_L		0xFFE9	/* Left alt */
#define XK_Alt_R		0xFFEA	/* Right alt */
#define XK_Super_L		0xFFEB	/* Left super */
#define XK_Super_R		0xFFEC	/* Right super */
#define XK_Hyper_L		0xFFED	/* Left hyper */
#define XK_Hyper_R		0xFFEE	/* Right hyper */
#endif /* XK_MISCELLANY */

/*
 * ISO 9995 Function and Modifier Keys
 * Byte 3 = 0xFE
 */

#define XK_XKB_KEYS
#ifdef XK_XKB_KEYS
#define	XK_ISO_Lock					0xFE01
#define	XK_ISO_Level2_Latch				0xFE02
#define	XK_ISO_Level3_Shift				0xFE03
#define	XK_ISO_Level3_Latch				0xFE04
#define	XK_ISO_Level3_Lock				0xFE05
#define	XK_ISO_Group_Shift		0xFF7E	/* Alias for mode_switch */
#define	XK_ISO_Group_Latch				0xFE06
#define	XK_ISO_Group_Lock				0xFE07
#define	XK_ISO_Next_Group				0xFE08
#define	XK_ISO_Next_Group_Lock				0xFE09
#define	XK_ISO_Prev_Group				0xFE0A
#define	XK_ISO_Prev_Group_Lock				0xFE0B
#define	XK_ISO_First_Group				0xFE0C
#define	XK_ISO_First_Group_Lock				0xFE0D
#define	XK_ISO_Last_Group				0xFE0E
#define	XK_ISO_Last_Group_Lock				0xFE0F

#define	XK_ISO_Left_Tab					0xFE20
#define	XK_ISO_Move_Line_Up				0xFE21
#define	XK_ISO_Move_Line_Down				0xFE22
#define	XK_ISO_Partial_Line_Up				0xFE23
#define	XK_ISO_Partial_Line_Down			0xFE24
#define	XK_ISO_Partial_Space_Left			0xFE25
#define	XK_ISO_Partial_Space_Right			0xFE26
#define	XK_ISO_Set_Margin_Left				0xFE27
#define	XK_ISO_Set_Margin_Right				0xFE28
#define	XK_ISO_Release_Margin_Left			0xFE29
#define	XK_ISO_Release_Margin_Right			0xFE2A
#define	XK_ISO_Release_Both_Margins			0xFE2B
#define	XK_ISO_Fast_Cursor_Left				0xFE2C
#define	XK_ISO_Fast_Cursor_Right			0xFE2D
#define	XK_ISO_Fast_Cursor_Up				0xFE2E
#define	XK_ISO_Fast_Cursor_Down				0xFE2F
#define	XK_ISO_Continuous_Underline			0xFE30
#define	XK_ISO_Discontinuous_Underline			0xFE31
#define	XK_ISO_Emphasize				0xFE32
#define	XK_ISO_Center_Object				0xFE33
#define	XK_ISO_Enter					0xFE34

#define	XK_dead_grave					0xFE50
#define	XK_dead_acute					0xFE51
#define	XK_dead_circumflex				0xFE52
#define	XK_dead_tilde					0xFE53
#define	XK_dead_macron					0xFE54
#define	XK_dead_breve					0xFE55
#define	XK_dead_abovedot				0xFE56
#define	XK_dead_diaeresis				0xFE57
#define	XK_dead_abovering				0xFE58
#define	XK_dead_doubleacute				0xFE59
#define	XK_dead_caron					0xFE5A
#define	XK_dead_cedilla					0xFE5B
#define	XK_dead_ogonek					0xFE5C
#define	XK_dead_iota					0xFE5D
#define	XK_dead_voiced_sound				0xFE5E
#define	XK_dead_semivoiced_sound			0xFE5F
#define	XK_dead_belowdot				0xFE60
#define XK_dead_hook					0xFE61
#define XK_dead_horn					0xFE62

#define	XK_First_Virtual_Screen				0xFED0
#define	XK_Prev_Virtual_Screen				0xFED1
#define	XK_Next_Virtual_Screen				0xFED2
#define	XK_Last_Virtual_Screen				0xFED4
#define	XK_Terminate_Server				0xFED5

#define	XK_AccessX_Enable				0xFE70
#define	XK_AccessX_Feedback_Enable			0xFE71
#define	XK_RepeatKeys_Enable				0xFE72
#define	XK_SlowKeys_Enable				0xFE73
#define	XK_BounceKeys_Enable				0xFE74
#define	XK_StickyKeys_Enable				0xFE75
#define	XK_MouseKeys_Enable				0xFE76
#define	XK_MouseKeys_Accel_Enable			0xFE77
#define	XK_Overlay1_Enable				0xFE78
#define	XK_Overlay2_Enable				0xFE79
#define	XK_AudibleBell_Enable				0xFE7A

#define	XK_Pointer_Left					0xFEE0
#define	XK_Pointer_Right				0xFEE1
#define	XK_Pointer_Up					0xFEE2
#define	XK_Pointer_Down					0xFEE3
#define	XK_Pointer_UpLeft				0xFEE4
#define	XK_Pointer_UpRight				0xFEE5
#define	XK_Pointer_DownLeft				0xFEE6
#define	XK_Pointer_DownRight				0xFEE7
#define	XK_Pointer_Button_Dflt				0xFEE8
#define	XK_Pointer_Button1				0xFEE9
#define	XK_Pointer_Button2				0xFEEA
#define	XK_Pointer_Button3				0xFEEB
#define	XK_Pointer_Button4				0xFEEC
#define	XK_Pointer_Button5				0xFEED
#define	XK_Pointer_DblClick_Dflt			0xFEEE
#define	XK_Pointer_DblClick1				0xFEEF
#define	XK_Pointer_DblClick2				0xFEF0
#define	XK_Pointer_DblClick3				0xFEF1
#define	XK_Pointer_DblClick4				0xFEF2
#define	XK_Pointer_DblClick5				0xFEF3
#define	XK_Pointer_Drag_Dflt				0xFEF4
#define	XK_Pointer_Drag1				0xFEF5
#define	XK_Pointer_Drag2				0xFEF6
#define	XK_Pointer_Drag3				0xFEF7
#define	XK_Pointer_Drag4				0xFEF8
#define	XK_Pointer_Drag5				0xFEFD

#define	XK_Pointer_EnableKeys				0xFEF9
#define	XK_Pointer_Accelerate				0xFEFA
#define	XK_Pointer_DfltBtnNext				0xFEFB
#define	XK_Pointer_DfltBtnPrev				0xFEFC

#endif

/*
 * 3270 Terminal Keys
 * Byte 3 = 0xFD
 */

#define XK_3270
#ifdef XK_3270
#define XK_3270_Duplicate      0xFD01
#define XK_3270_FieldMark      0xFD02
#define XK_3270_Right2         0xFD03
#define XK_3270_Left2          0xFD04
#define XK_3270_BackTab        0xFD05
#define XK_3270_EraseEOF       0xFD06
#define XK_3270_EraseInput     0xFD07
#define XK_3270_Reset          0xFD08
#define XK_3270_Quit           0xFD09
#define XK_3270_PA1            0xFD0A
#define XK_3270_PA2            0xFD0B
#define XK_3270_PA3            0xFD0C
#define XK_3270_Test           0xFD0D
#define XK_3270_Attn           0xFD0E
#define XK_3270_CursorBlink    0xFD0F
#define XK_3270_AltCursor      0xFD10
#define XK_3270_KeyClick       0xFD11
#define XK_3270_Jump           0xFD12
#define XK_3270_Ident          0xFD13
#define XK_3270_Rule           0xFD14
#define XK_3270_Copy           0xFD15
#define XK_3270_Play           0xFD16
#define XK_3270_Setup          0xFD17
#define XK_3270_Record         0xFD18
#define XK_3270_ChangeScreen   0xFD19
#define XK_3270_DeleteWord     0xFD1A
#define XK_3270_ExSelect       0xFD1B
#define XK_3270_CursorSelect   0xFD1C
#define XK_3270_PrintScreen    0xFD1D
#define XK_3270_Enter          0xFD1E
#endif

/*
 *  Latin 1
 *  Byte 3 = 0
 */
#define XK_LATIN1
#ifdef XK_LATIN1
#define XK_space               0x020
#define XK_exclam              0x021
#define XK_quotedbl            0x022
#define XK_numbersign          0x023
#define XK_dollar              0x024
#define XK_percent             0x025
#define XK_ampersand           0x026
#define XK_apostrophe          0x027
#define XK_quoteright          0x027	/* deprecated */
#define XK_parenleft           0x028
#define XK_parenright          0x029
#define XK_asterisk            0x02a
#define XK_plus                0x02b
#define XK_comma               0x02c
#define XK_minus               0x02d
#define XK_period              0x02e
#define XK_slash               0x02f
#define XK_0                   0x030
#define XK_1                   0x031
#define XK_2                   0x032
#define XK_3                   0x033
#define XK_4                   0x034
#define XK_5                   0x035
#define XK_6                   0x036
#define XK_7                   0x037
#define XK_8                   0x038
#define XK_9                   0x039
#define XK_colon               0x03a
#define XK_semicolon           0x03b
#define XK_less                0x03c
#define XK_equal               0x03d
#define XK_greater             0x03e
#define XK_question            0x03f
#define XK_at                  0x040
#define XK_A                   0x041
#define XK_B                   0x042
#define XK_C                   0x043
#define XK_D                   0x044
#define XK_E                   0x045
#define XK_F                   0x046
#define XK_G                   0x047
#define XK_H                   0x048
#define XK_I                   0x049
#define XK_J                   0x04a
#define XK_K                   0x04b
#define XK_L                   0x04c
#define XK_M                   0x04d
#define XK_N                   0x04e
#define XK_O                   0x04f
#define XK_P                   0x050
#define XK_Q                   0x051
#define XK_R                   0x052
#define XK_S                   0x053
#define XK_T                   0x054
#define XK_U                   0x055
#define XK_V                   0x056
#define XK_W                   0x057
#define XK_X                   0x058
#define XK_Y                   0x059
#define XK_Z                   0x05a
#define XK_bracketleft         0x05b
#define XK_backslash           0x05c
#define XK_bracketright        0x05d
#define XK_asciicircum         0x05e
#define XK_underscore          0x05f
#define XK_grave               0x060
#define XK_quoteleft           0x060	/* deprecated */
#define XK_a                   0x061
#define XK_b                   0x062
#define XK_c                   0x063
#define XK_d                   0x064
#define XK_e                   0x065
#define XK_f                   0x066
#define XK_g                   0x067
#define XK_h                   0x068
#define XK_i                   0x069
#define XK_j                   0x06a
#define XK_k                   0x06b
#define XK_l                   0x06c
#define XK_m                   0x06d
#define XK_n                   0x06e
#define XK_o                   0x06f
#define XK_p                   0x070
#define XK_q                   0x071
#define XK_r                   0x072
#define XK_s                   0x073
#define XK_t                   0x074
#define XK_u                   0x075
#define XK_v                   0x076
#define XK_w                   0x077
#define XK_x                   0x078
#define XK_y                   0x079
#define XK_z                   0x07a
#define XK_braceleft           0x07b
#define XK_bar                 0x07c
#define XK_braceright          0x07d
#define XK_asciitilde          0x07e

#define XK_nobreakspace        0x0a0
#define XK_exclamdown          0x0a1
#define XK_cent        	       0x0a2
#define XK_sterling            0x0a3
#define XK_currency            0x0a4
#define XK_yen                 0x0a5
#define XK_brokenbar           0x0a6
#define XK_section             0x0a7
#define XK_diaeresis           0x0a8
#define XK_copyright           0x0a9
#define XK_ordfeminine         0x0aa
#define XK_guillemotleft       0x0ab	/* left angle quotation mark */
#define XK_notsign             0x0ac
#define XK_hyphen              0x0ad
#define XK_registered          0x0ae
#define XK_macron              0x0af
#define XK_degree              0x0b0
#define XK_plusminus           0x0b1
#define XK_twosuperior         0x0b2
#define XK_threesuperior       0x0b3
#define XK_acute               0x0b4
#define XK_mu                  0x0b5
#define XK_paragraph           0x0b6
#define XK_periodcentered      0x0b7
#define XK_cedilla             0x0b8
#define XK_onesuperior         0x0b9
#define XK_masculine           0x0ba
#define XK_guillemotright      0x0bb	/* right angle quotation mark */
#define XK_onequarter          0x0bc
#define XK_onehalf             0x0bd
#define XK_threequarters       0x0be
#define XK_questiondown        0x0bf
#define XK_Agrave              0x0c0
#define XK_Aacute              0x0c1
#define XK_Acircumflex         0x0c2
#define XK_Atilde              0x0c3
#define XK_Adiaeresis          0x0c4
#define XK_Aring               0x0c5
#define XK_AE                  0x0c6
#define XK_Ccedilla            0x0c7
#define XK_Egrave              0x0c8
#define XK_Eacute              0x0c9
#define XK_Ecircumflex         0x0ca
#define XK_Ediaeresis          0x0cb
#define XK_Igrave              0x0cc
#define XK_Iacute              0x0cd
#define XK_Icircumflex         0x0ce
#define XK_Idiaeresis          0x0cf
#define XK_ETH                 0x0d0
#define XK_Eth                 0x0d0	/* deprecated */
#define XK_Ntilde              0x0d1
#define XK_Ograve              0x0d2
#define XK_Oacute              0x0d3
#define XK_Ocircumflex         0x0d4
#define XK_Otilde              0x0d5
#define XK_Odiaeresis          0x0d6
#define XK_multiply            0x0d7
#define XK_Ooblique            0x0d8
#define XK_Oslash              XK_Ooblique
#define XK_Ugrave              0x0d9
#define XK_Uacute              0x0da
#define XK_Ucircumflex         0x0db
#define XK_Udiaeresis          0x0dc
#define XK_Yacute              0x0dd
#define XK_THORN               0x0de
#define XK_Thorn               0x0de	/* deprecated */
#define XK_ssharp              0x0df
#define XK_agrave              0x0e0
#define XK_aacute              0x0e1
#define XK_acircumflex         0x0e2
#define XK_atilde              0x0e3
#define XK_adiaeresis          0x0e4
#define XK_aring               0x0e5
#define XK_ae                  0x0e6
#define XK_ccedilla            0x0e7
#define XK_egrave              0x0e8
#define XK_eacute              0x0e9
#define XK_ecircumflex         0x0ea
#define XK_ediaeresis          0x0eb
#define XK_igrave              0x0ec
#define XK_iacute              0x0ed
#define XK_icircumflex         0x0ee
#define XK_idiaeresis          0x0ef
#define XK_eth                 0x0f0
#define XK_ntilde              0x0f1
#define XK_ograve              0x0f2
#define XK_oacute              0x0f3
#define XK_ocircumflex         0x0f4
#define XK_otilde              0x0f5
#define XK_odiaeresis          0x0f6
#define XK_division            0x0f7
#define XK_oslash              0x0f8
#define XK_ooblique            XK_oslash
#define XK_ugrave              0x0f9
#define XK_uacute              0x0fa
#define XK_ucircumflex         0x0fb
#define XK_udiaeresis          0x0fc
#define XK_yacute              0x0fd
#define XK_thorn               0x0fe
#define XK_ydiaeresis          0x0ff
#endif /* XK_LATIN1 */

/*
 *   Latin 2
 *   Byte 3 = 1
 */

#define XK_LATIN2
#ifdef XK_LATIN2
#define XK_Aogonek             0x1a1
#define XK_breve               0x1a2
#define XK_Lstroke             0x1a3
#define XK_Lcaron              0x1a5
#define XK_Sacute              0x1a6
#define XK_Scaron              0x1a9
#define XK_Scedilla            0x1aa
#define XK_Tcaron              0x1ab
#define XK_Zacute              0x1ac
#define XK_Zcaron              0x1ae
#define XK_Zabovedot           0x1af
#define XK_aogonek             0x1b1
#define XK_ogonek              0x1b2
#define XK_lstroke             0x1b3
#define XK_lcaron              0x1b5
#define XK_sacute              0x1b6
#define XK_caron               0x1b7
#define XK_scaron              0x1b9
#define XK_scedilla            0x1ba
#define XK_tcaron              0x1bb
#define XK_zacute              0x1bc
#define XK_doubleacute         0x1bd
#define XK_zcaron              0x1be
#define XK_zabovedot           0x1bf
#define XK_Racute              0x1c0
#define XK_Abreve              0x1c3
#define XK_Lacute              0x1c5
#define XK_Cacute              0x1c6
#define XK_Ccaron              0x1c8
#define XK_Eogonek             0x1ca
#define XK_Ecaron              0x1cc
#define XK_Dcaron              0x1cf
#define XK_Dstroke             0x1d0
#define XK_Nacute              0x1d1
#define XK_Ncaron              0x1d2
#define XK_Odoubleacute        0x1d5
#define XK_Rcaron              0x1d8
#define XK_Uring               0x1d9
#define XK_Udoubleacute        0x1db
#define XK_Tcedilla            0x1de
#define XK_racute              0x1e0
#define XK_abreve              0x1e3
#define XK_lacute              0x1e5
#define XK_cacute              0x1e6
#define XK_ccaron              0x1e8
#define XK_eogonek             0x1ea
#define XK_ecaron              0x1ec
#define XK_dcaron              0x1ef
#define XK_dstroke             0x1f0
#define XK_nacute              0x1f1
#define XK_ncaron              0x1f2
#define XK_odoubleacute        0x1f5
#define XK_udoubleacute        0x1fb
#define XK_rcaron              0x1f8
#define XK_uring               0x1f9
#define XK_tcedilla            0x1fe
#define XK_abovedot            0x1ff
#endif /* XK_LATIN2 */

/*
 *   Latin 3
 *   Byte 3 = 2
 */

#define XK_LATIN3
#ifdef XK_LATIN3
#define XK_Hstroke             0x2a1
#define XK_Hcircumflex         0x2a6
#define XK_Iabovedot           0x2a9
#define XK_Gbreve              0x2ab
#define XK_Jcircumflex         0x2ac
#define XK_hstroke             0x2b1
#define XK_hcircumflex         0x2b6
#define XK_idotless            0x2b9
#define XK_gbreve              0x2bb
#define XK_jcircumflex         0x2bc
#define XK_Cabovedot           0x2c5
#define XK_Ccircumflex         0x2c6
#define XK_Gabovedot           0x2d5
#define XK_Gcircumflex         0x2d8
#define XK_Ubreve              0x2dd
#define XK_Scircumflex         0x2de
#define XK_cabovedot           0x2e5
#define XK_ccircumflex         0x2e6
#define XK_gabovedot           0x2f5
#define XK_gcircumflex         0x2f8
#define XK_ubreve              0x2fd
#define XK_scircumflex         0x2fe
#endif /* XK_LATIN3 */


/*
 *   Latin 4
 *   Byte 3 = 3
 */

#define XK_LATIN4
#ifdef XK_LATIN4
#define XK_kra                 0x3a2
#define XK_kappa               0x3a2	/* deprecated */
#define XK_Rcedilla            0x3a3
#define XK_Itilde              0x3a5
#define XK_Lcedilla            0x3a6
#define XK_Emacron             0x3aa
#define XK_Gcedilla            0x3ab
#define XK_Tslash              0x3ac
#define XK_rcedilla            0x3b3
#define XK_itilde              0x3b5
#define XK_lcedilla            0x3b6
#define XK_emacron             0x3ba
#define XK_gcedilla            0x3bb
#define XK_tslash              0x3bc
#define XK_ENG                 0x3bd
#define XK_eng                 0x3bf
#define XK_Amacron             0x3c0
#define XK_Iogonek             0x3c7
#define XK_Eabovedot           0x3cc
#define XK_Imacron             0x3cf
#define XK_Ncedilla            0x3d1
#define XK_Omacron             0x3d2
#define XK_Kcedilla            0x3d3
#define XK_Uogonek             0x3d9
#define XK_Utilde              0x3dd
#define XK_Umacron             0x3de
#define XK_amacron             0x3e0
#define XK_iogonek             0x3e7
#define XK_eabovedot           0x3ec
#define XK_imacron             0x3ef
#define XK_ncedilla            0x3f1
#define XK_omacron             0x3f2
#define XK_kcedilla            0x3f3
#define XK_uogonek             0x3f9
#define XK_utilde              0x3fd
#define XK_umacron             0x3fe
#endif /* XK_LATIN4 */

/*
 * Latin-8
 * Byte 3 = 18
 */
#define XK_LATIN8
#ifdef XK_LATIN8
#define XK_Babovedot           0x12a1
#define XK_babovedot           0x12a2
#define XK_Dabovedot           0x12a6
#define XK_Wgrave              0x12a8
#define XK_Wacute              0x12aa
#define XK_dabovedot           0x12ab
#define XK_Ygrave              0x12ac
#define XK_Fabovedot           0x12b0
#define XK_fabovedot           0x12b1
#define XK_Mabovedot           0x12b4
#define XK_mabovedot           0x12b5
#define XK_Pabovedot           0x12b7
#define XK_wgrave              0x12b8
#define XK_pabovedot           0x12b9
#define XK_wacute              0x12ba
#define XK_Sabovedot           0x12bb
#define XK_ygrave              0x12bc
#define XK_Wdiaeresis          0x12bd
#define XK_wdiaeresis          0x12be
#define XK_sabovedot           0x12bf
#define XK_Wcircumflex         0x12d0
#define XK_Tabovedot           0x12d7
#define XK_Ycircumflex         0x12de
#define XK_wcircumflex         0x12f0
#define XK_tabovedot           0x12f7
#define XK_ycircumflex         0x12fe
#endif /* XK_LATIN8 */

/*
 * Latin-9 (a.k.a. Latin-0)
 * Byte 3 = 19
 */

#define XK_LATIN9
#ifdef XK_LATIN9
#define XK_OE                  0x13bc
#define XK_oe                  0x13bd
#define XK_Ydiaeresis          0x13be
#endif /* XK_LATIN9 */

/*
 * Katakana
 * Byte 3 = 4
 */

#define XK_KATAKANA
#ifdef XK_KATAKANA
#define XK_overline				       0x47e
#define XK_kana_fullstop                               0x4a1
#define XK_kana_openingbracket                         0x4a2
#define XK_kana_closingbracket                         0x4a3
#define XK_kana_comma                                  0x4a4
#define XK_kana_conjunctive                            0x4a5
#define XK_kana_middledot                              0x4a5  /* deprecated */
#define XK_kana_WO                                     0x4a6
#define XK_kana_a                                      0x4a7
#define XK_kana_i                                      0x4a8
#define XK_kana_u                                      0x4a9
#define XK_kana_e                                      0x4aa
#define XK_kana_o                                      0x4ab
#define XK_kana_ya                                     0x4ac
#define XK_kana_yu                                     0x4ad
#define XK_kana_yo                                     0x4ae
#define XK_kana_tsu                                    0x4af
#define XK_kana_tu                                     0x4af  /* deprecated */
#define XK_prolongedsound                              0x4b0
#define XK_kana_A                                      0x4b1
#define XK_kana_I                                      0x4b2
#define XK_kana_U                                      0x4b3
#define XK_kana_E                                      0x4b4
#define XK_kana_O                                      0x4b5
#define XK_kana_KA                                     0x4b6
#define XK_kana_KI                                     0x4b7
#define XK_kana_KU                                     0x4b8
#define XK_kana_KE                                     0x4b9
#define XK_kana_KO                                     0x4ba
#define XK_kana_SA                                     0x4bb
#define XK_kana_SHI                                    0x4bc
#define XK_kana_SU                                     0x4bd
#define XK_kana_SE                                     0x4be
#define XK_kana_SO                                     0x4bf
#define XK_kana_TA                                     0x4c0
#define XK_kana_CHI                                    0x4c1
#define XK_kana_TI                                     0x4c1  /* deprecated */
#define XK_kana_TSU                                    0x4c2
#define XK_kana_TU                                     0x4c2  /* deprecated */
#define XK_kana_TE                                     0x4c3
#define XK_kana_TO                                     0x4c4
#define XK_kana_NA                                     0x4c5
#define XK_kana_NI                                     0x4c6
#define XK_kana_NU                                     0x4c7
#define XK_kana_NE                                     0x4c8
#define XK_kana_NO                                     0x4c9
#define XK_kana_HA                                     0x4ca
#define XK_kana_HI                                     0x4cb
#define XK_kana_FU                                     0x4cc
#define XK_kana_HU                                     0x4cc  /* deprecated */
#define XK_kana_HE                                     0x4cd
#define XK_kana_HO                                     0x4ce
#define XK_kana_MA                                     0x4cf
#define XK_kana_MI                                     0x4d0
#define XK_kana_MU                                     0x4d1
#define XK_kana_ME                                     0x4d2
#define XK_kana_MO                                     0x4d3
#define XK_kana_YA                                     0x4d4
#define XK_kana_YU                                     0x4d5
#define XK_kana_YO                                     0x4d6
#define XK_kana_RA                                     0x4d7
#define XK_kana_RI                                     0x4d8
#define XK_kana_RU                                     0x4d9
#define XK_kana_RE                                     0x4da
#define XK_kana_RO                                     0x4db
#define XK_kana_WA                                     0x4dc
#define XK_kana_N                                      0x4dd
#define XK_voicedsound                                 0x4de
#define XK_semivoicedsound                             0x4df
#define XK_kana_switch          0xFF7E  /* Alias for mode_switch */
#endif /* XK_KATAKANA */

/*
 *  Arabic
 *  Byte 3 = 5
 */

#define XK_ARABIC
#ifdef XK_ARABIC
#define XK_Farsi_0                                     0x590
#define XK_Farsi_1                                     0x591
#define XK_Farsi_2                                     0x592
#define XK_Farsi_3                                     0x593
#define XK_Farsi_4                                     0x594
#define XK_Farsi_5                                     0x595
#define XK_Farsi_6                                     0x596
#define XK_Farsi_7                                     0x597
#define XK_Farsi_8                                     0x598
#define XK_Farsi_9                                     0x599
#define XK_Arabic_percent                              0x5a5
#define XK_Arabic_superscript_alef                     0x5a6
#define XK_Arabic_tteh                                 0x5a7
#define XK_Arabic_peh                                  0x5a8
#define XK_Arabic_tcheh                                0x5a9
#define XK_Arabic_ddal                                 0x5aa
#define XK_Arabic_rreh                                 0x5ab
#define XK_Arabic_comma                                0x5ac
#define XK_Arabic_fullstop                             0x5ae
#define XK_Arabic_0                                    0x5b0
#define XK_Arabic_1                                    0x5b1
#define XK_Arabic_2                                    0x5b2
#define XK_Arabic_3                                    0x5b3
#define XK_Arabic_4                                    0x5b4
#define XK_Arabic_5                                    0x5b5
#define XK_Arabic_6                                    0x5b6
#define XK_Arabic_7                                    0x5b7
#define XK_Arabic_8                                    0x5b8
#define XK_Arabic_9                                    0x5b9
#define XK_Arabic_semicolon                            0x5bb
#define XK_Arabic_question_mark                        0x5bf
#define XK_Arabic_hamza                                0x5c1
#define XK_Arabic_maddaonalef                          0x5c2
#define XK_Arabic_hamzaonalef                          0x5c3
#define XK_Arabic_hamzaonwaw                           0x5c4
#define XK_Arabic_hamzaunderalef                       0x5c5
#define XK_Arabic_hamzaonyeh                           0x5c6
#define XK_Arabic_alef                                 0x5c7
#define XK_Arabic_beh                                  0x5c8
#define XK_Arabic_tehmarbuta                           0x5c9
#define XK_Arabic_teh                                  0x5ca
#define XK_Arabic_theh                                 0x5cb
#define XK_Arabic_jeem                                 0x5cc
#define XK_Arabic_hah                                  0x5cd
#define XK_Arabic_khah                                 0x5ce
#define XK_Arabic_dal                                  0x5cf
#define XK_Arabic_thal                                 0x5d0
#define XK_Arabic_ra                                   0x5d1
#define XK_Arabic_zain                                 0x5d2
#define XK_Arabic_seen                                 0x5d3
#define XK_Arabic_sheen                                0x5d4
#define XK_Arabic_sad                                  0x5d5
#define XK_Arabic_dad                                  0x5d6
#define XK_Arabic_tah                                  0x5d7
#define XK_Arabic_zah                                  0x5d8
#define XK_Arabic_ain                                  0x5d9
#define XK_Arabic_ghain                                0x5da
#define XK_Arabic_tatweel                              0x5e0
#define XK_Arabic_feh                                  0x5e1
#define XK_Arabic_qaf                                  0x5e2
#define XK_Arabic_kaf                                  0x5e3
#define XK_Arabic_lam                                  0x5e4
#define XK_Arabic_meem                                 0x5e5
#define XK_Arabic_noon                                 0x5e6
#define XK_Arabic_ha                                   0x5e7
#define XK_Arabic_heh                                  0x5e7  /* deprecated */
#define XK_Arabic_waw                                  0x5e8
#define XK_Arabic_alefmaksura                          0x5e9
#define XK_Arabic_yeh                                  0x5ea
#define XK_Arabic_fathatan                             0x5eb
#define XK_Arabic_dammatan                             0x5ec
#define XK_Arabic_kasratan                             0x5ed
#define XK_Arabic_fatha                                0x5ee
#define XK_Arabic_damma                                0x5ef
#define XK_Arabic_kasra                                0x5f0
#define XK_Arabic_shadda                               0x5f1
#define XK_Arabic_sukun                                0x5f2
#define XK_Arabic_madda_above                          0x5f3
#define XK_Arabic_hamza_above                          0x5f4
#define XK_Arabic_hamza_below                          0x5f5
#define XK_Arabic_jeh                                  0x5f6
#define XK_Arabic_veh                                  0x5f7
#define XK_Arabic_keheh                                0x5f8
#define XK_Arabic_gaf                                  0x5f9
#define XK_Arabic_noon_ghunna                          0x5fa
#define XK_Arabic_heh_doachashmee                      0x5fb
#define XK_Farsi_yeh                                   0x5fc
#define XK_Arabic_farsi_yeh                     XK_Farsi_yeh
#define XK_Arabic_yeh_baree                            0x5fd
#define XK_Arabic_heh_goal                             0x5fe
#define XK_Arabic_switch        0xFF7E  /* Alias for mode_switch */
#endif /* XK_ARABIC */

/*
 * Cyrillic
 * Byte 3 = 6
 */
#define XK_CYRILLIC
#ifdef XK_CYRILLIC
#define XK_Cyrillic_GHE_bar	                           0x680
#define XK_Cyrillic_ghe_bar	                           0x690
#define XK_Cyrillic_ZHE_descender	                   0x681
#define XK_Cyrillic_zhe_descender	                   0x691
#define XK_Cyrillic_KA_descender	                   0x682
#define XK_Cyrillic_ka_descender	                   0x692
#define XK_Cyrillic_KA_vertstroke	                   0x683
#define XK_Cyrillic_ka_vertstroke	                   0x693
#define XK_Cyrillic_EN_descender	                   0x684
#define XK_Cyrillic_en_descender	                   0x694
#define XK_Cyrillic_U_straight	                       0x685
#define XK_Cyrillic_u_straight	                       0x695
#define XK_Cyrillic_U_straight_bar	                   0x686
#define XK_Cyrillic_u_straight_bar	                   0x696
#define XK_Cyrillic_HA_descender	                   0x687
#define XK_Cyrillic_ha_descender	                   0x697
#define XK_Cyrillic_CHE_descender	                   0x688
#define XK_Cyrillic_che_descender	                   0x698
#define XK_Cyrillic_CHE_vertstroke	                   0x689
#define XK_Cyrillic_che_vertstroke	                   0x699
#define XK_Cyrillic_SHHA	                           0x68a
#define XK_Cyrillic_shha	                           0x69a

#define XK_Cyrillic_SCHWA	                           0x68c
#define XK_Cyrillic_schwa	                           0x69c
#define XK_Cyrillic_I_macron		                   0x68d
#define XK_Cyrillic_i_macron		                   0x69d
#define XK_Cyrillic_O_bar	                           0x68e
#define XK_Cyrillic_o_bar	                           0x69e
#define XK_Cyrillic_U_macron		                   0x68f
#define XK_Cyrillic_u_macron		                   0x69f

#define XK_Serbian_dje                                 0x6a1
#define XK_Macedonia_gje                               0x6a2
#define XK_Cyrillic_io                                 0x6a3
#define XK_Ukrainian_ie                                0x6a4
#define XK_Ukranian_je                                 0x6a4  /* deprecated */
#define XK_Macedonia_dse                               0x6a5
#define XK_Ukrainian_i                                 0x6a6
#define XK_Ukranian_i                                  0x6a6  /* deprecated */
#define XK_Ukrainian_yi                                0x6a7
#define XK_Ukranian_yi                                 0x6a7  /* deprecated */
#define XK_Cyrillic_je                                 0x6a8
#define XK_Serbian_je                                  0x6a8  /* deprecated */
#define XK_Cyrillic_lje                                0x6a9
#define XK_Serbian_lje                                 0x6a9  /* deprecated */
#define XK_Cyrillic_nje                                0x6aa
#define XK_Serbian_nje                                 0x6aa  /* deprecated */
#define XK_Serbian_tshe                                0x6ab
#define XK_Macedonia_kje                               0x6ac
#define XK_Ukrainian_ghe_with_upturn                   0x6ad
#define XK_Byelorussian_shortu                         0x6ae
#define XK_Cyrillic_dzhe                               0x6af
#define XK_Serbian_dze                                 0x6af  /* deprecated */
#define XK_numerosign                                  0x6b0
#define XK_Serbian_DJE                                 0x6b1
#define XK_Macedonia_GJE                               0x6b2
#define XK_Cyrillic_IO                                 0x6b3
#define XK_Ukrainian_IE                                0x6b4
#define XK_Ukranian_JE                                 0x6b4  /* deprecated */
#define XK_Macedonia_DSE                               0x6b5
#define XK_Ukrainian_I                                 0x6b6
#define XK_Ukranian_I                                  0x6b6  /* deprecated */
#define XK_Ukrainian_YI                                0x6b7
#define XK_Ukranian_YI                                 0x6b7  /* deprecated */
#define XK_Cyrillic_JE                                 0x6b8
#define XK_Serbian_JE                                  0x6b8  /* deprecated */
#define XK_Cyrillic_LJE                                0x6b9
#define XK_Serbian_LJE                                 0x6b9  /* deprecated */
#define XK_Cyrillic_NJE                                0x6ba
#define XK_Serbian_NJE                                 0x6ba  /* deprecated */
#define XK_Serbian_TSHE                                0x6bb
#define XK_Macedonia_KJE                               0x6bc
#define XK_Ukrainian_GHE_WITH_UPTURN                   0x6bd
#define XK_Byelorussian_SHORTU                         0x6be
#define XK_Cyrillic_DZHE                               0x6bf
#define XK_Serbian_DZE                                 0x6bf  /* deprecated */
#define XK_Cyrillic_yu                                 0x6c0
#define XK_Cyrillic_a                                  0x6c1
#define XK_Cyrillic_be                                 0x6c2
#define XK_Cyrillic_tse                                0x6c3
#define XK_Cyrillic_de                                 0x6c4
#define XK_Cyrillic_ie                                 0x6c5
#define XK_Cyrillic_ef                                 0x6c6
#define XK_Cyrillic_ghe                                0x6c7
#define XK_Cyrillic_ha                                 0x6c8
#define XK_Cyrillic_i                                  0x6c9
#define XK_Cyrillic_shorti                             0x6ca
#define XK_Cyrillic_ka                                 0x6cb
#define XK_Cyrillic_el                                 0x6cc
#define XK_Cyrillic_em                                 0x6cd
#define XK_Cyrillic_en                                 0x6ce
#define XK_Cyrillic_o                                  0x6cf
#define XK_Cyrillic_pe                                 0x6d0
#define XK_Cyrillic_ya                                 0x6d1
#define XK_Cyrillic_er                                 0x6d2
#define XK_Cyrillic_es                                 0x6d3
#define XK_Cyrillic_te                                 0x6d4
#define XK_Cyrillic_u                                  0x6d5
#define XK_Cyrillic_zhe                                0x6d6
#define XK_Cyrillic_ve                                 0x6d7
#define XK_Cyrillic_softsign                           0x6d8
#define XK_Cyrillic_yeru                               0x6d9
#define XK_Cyrillic_ze                                 0x6da
#define XK_Cyrillic_sha                                0x6db
#define XK_Cyrillic_e                                  0x6dc
#define XK_Cyrillic_shcha                              0x6dd
#define XK_Cyrillic_che                                0x6de
#define XK_Cyrillic_hardsign                           0x6df
#define XK_Cyrillic_YU                                 0x6e0
#define XK_Cyrillic_A                                  0x6e1
#define XK_Cyrillic_BE                                 0x6e2
#define XK_Cyrillic_TSE                                0x6e3
#define XK_Cyrillic_DE                                 0x6e4
#define XK_Cyrillic_IE                                 0x6e5
#define XK_Cyrillic_EF                                 0x6e6
#define XK_Cyrillic_GHE                                0x6e7
#define XK_Cyrillic_HA                                 0x6e8
#define XK_Cyrillic_I                                  0x6e9
#define XK_Cyrillic_SHORTI                             0x6ea
#define XK_Cyrillic_KA                                 0x6eb
#define XK_Cyrillic_EL                                 0x6ec
#define XK_Cyrillic_EM                                 0x6ed
#define XK_Cyrillic_EN                                 0x6ee
#define XK_Cyrillic_O                                  0x6ef
#define XK_Cyrillic_PE                                 0x6f0
#define XK_Cyrillic_YA                                 0x6f1
#define XK_Cyrillic_ER                                 0x6f2
#define XK_Cyrillic_ES                                 0x6f3
#define XK_Cyrillic_TE                                 0x6f4
#define XK_Cyrillic_U                                  0x6f5
#define XK_Cyrillic_ZHE                                0x6f6
#define XK_Cyrillic_VE                                 0x6f7
#define XK_Cyrillic_SOFTSIGN                           0x6f8
#define XK_Cyrillic_YERU                               0x6f9
#define XK_Cyrillic_ZE                                 0x6fa
#define XK_Cyrillic_SHA                                0x6fb
#define XK_Cyrillic_E                                  0x6fc
#define XK_Cyrillic_SHCHA                              0x6fd
#define XK_Cyrillic_CHE                                0x6fe
#define XK_Cyrillic_HARDSIGN                           0x6ff
#endif /* XK_CYRILLIC */

/*
 * Greek
 * Byte 3 = 7
 */

#define XK_GREEK
#ifdef XK_GREEK
#define XK_Greek_ALPHAaccent                           0x7a1
#define XK_Greek_EPSILONaccent                         0x7a2
#define XK_Greek_ETAaccent                             0x7a3
#define XK_Greek_IOTAaccent                            0x7a4
#define XK_Greek_IOTAdieresis                          0x7a5
#define XK_Greek_IOTAdiaeresis         XK_Greek_IOTAdieresis /* old typo */
#define XK_Greek_OMICRONaccent                         0x7a7
#define XK_Greek_UPSILONaccent                         0x7a8
#define XK_Greek_UPSILONdieresis                       0x7a9
#define XK_Greek_OMEGAaccent                           0x7ab
#define XK_Greek_accentdieresis                        0x7ae
#define XK_Greek_horizbar                              0x7af
#define XK_Greek_alphaaccent                           0x7b1
#define XK_Greek_epsilonaccent                         0x7b2
#define XK_Greek_etaaccent                             0x7b3
#define XK_Greek_iotaaccent                            0x7b4
#define XK_Greek_iotadieresis                          0x7b5
#define XK_Greek_iotaaccentdieresis                    0x7b6
#define XK_Greek_omicronaccent                         0x7b7
#define XK_Greek_upsilonaccent                         0x7b8
#define XK_Greek_upsilondieresis                       0x7b9
#define XK_Greek_upsilonaccentdieresis                 0x7ba
#define XK_Greek_omegaaccent                           0x7bb
#define XK_Greek_ALPHA                                 0x7c1
#define XK_Greek_BETA                                  0x7c2
#define XK_Greek_GAMMA                                 0x7c3
#define XK_Greek_DELTA                                 0x7c4
#define XK_Greek_EPSILON                               0x7c5
#define XK_Greek_ZETA                                  0x7c6
#define XK_Greek_ETA                                   0x7c7
#define XK_Greek_THETA                                 0x7c8
#define XK_Greek_IOTA                                  0x7c9
#define XK_Greek_KAPPA                                 0x7ca
#define XK_Greek_LAMDA                                 0x7cb
#define XK_Greek_LAMBDA                                0x7cb
#define XK_Greek_MU                                    0x7cc
#define XK_Greek_NU                                    0x7cd
#define XK_Greek_XI                                    0x7ce
#define XK_Greek_OMICRON                               0x7cf
#define XK_Greek_PI                                    0x7d0
#define XK_Greek_RHO                                   0x7d1
#define XK_Greek_SIGMA                                 0x7d2
#define XK_Greek_TAU                                   0x7d4
#define XK_Greek_UPSILON                               0x7d5
#define XK_Greek_PHI                                   0x7d6
#define XK_Greek_CHI                                   0x7d7
#define XK_Greek_PSI                                   0x7d8
#define XK_Greek_OMEGA                                 0x7d9
#define XK_Greek_alpha                                 0x7e1
#define XK_Greek_beta                                  0x7e2
#define XK_Greek_gamma                                 0x7e3
#define XK_Greek_delta                                 0x7e4
#define XK_Greek_epsilon                               0x7e5
#define XK_Greek_zeta                                  0x7e6
#define XK_Greek_eta                                   0x7e7
#define XK_Greek_theta                                 0x7e8
#define XK_Greek_iota                                  0x7e9
#define XK_Greek_kappa                                 0x7ea
#define XK_Greek_lamda                                 0x7eb
#define XK_Greek_lambda                                0x7eb
#define XK_Greek_mu                                    0x7ec
#define XK_Greek_nu                                    0x7ed
#define XK_Greek_xi                                    0x7ee
#define XK_Greek_omicron                               0x7ef
#define XK_Greek_pi                                    0x7f0
#define XK_Greek_rho                                   0x7f1
#define XK_Greek_sigma                                 0x7f2
#define XK_Greek_finalsmallsigma                       0x7f3
#define XK_Greek_tau                                   0x7f4
#define XK_Greek_upsilon                               0x7f5
#define XK_Greek_phi                                   0x7f6
#define XK_Greek_chi                                   0x7f7
#define XK_Greek_psi                                   0x7f8
#define XK_Greek_omega                                 0x7f9
#define XK_Greek_switch         0xFF7E  /* Alias for mode_switch */
#endif /* XK_GREEK */

/*
 * Technical
 * Byte 3 = 8
 */

#define XK_TECHNICAL
#ifdef XK_TECHNICAL
#define XK_leftradical                                 0x8a1
#define XK_topleftradical                              0x8a2
#define XK_horizconnector                              0x8a3
#define XK_topintegral                                 0x8a4
#define XK_botintegral                                 0x8a5
#define XK_vertconnector                               0x8a6
#define XK_topleftsqbracket                            0x8a7
#define XK_botleftsqbracket                            0x8a8
#define XK_toprightsqbracket                           0x8a9
#define XK_botrightsqbracket                           0x8aa
#define XK_topleftparens                               0x8ab
#define XK_botleftparens                               0x8ac
#define XK_toprightparens                              0x8ad
#define XK_botrightparens                              0x8ae
#define XK_leftmiddlecurlybrace                        0x8af
#define XK_rightmiddlecurlybrace                       0x8b0
#define XK_topleftsummation                            0x8b1
#define XK_botleftsummation                            0x8b2
#define XK_topvertsummationconnector                   0x8b3
#define XK_botvertsummationconnector                   0x8b4
#define XK_toprightsummation                           0x8b5
#define XK_botrightsummation                           0x8b6
#define XK_rightmiddlesummation                        0x8b7
#define XK_lessthanequal                               0x8bc
#define XK_notequal                                    0x8bd
#define XK_greaterthanequal                            0x8be
#define XK_integral                                    0x8bf
#define XK_therefore                                   0x8c0
#define XK_variation                                   0x8c1
#define XK_infinity                                    0x8c2
#define XK_nabla                                       0x8c5
#define XK_approximate                                 0x8c8
#define XK_similarequal                                0x8c9
#define XK_ifonlyif                                    0x8cd
#define XK_implies                                     0x8ce
#define XK_identical                                   0x8cf
#define XK_radical                                     0x8d6
#define XK_includedin                                  0x8da
#define XK_includes                                    0x8db
#define XK_intersection                                0x8dc
#define XK_union                                       0x8dd
#define XK_logicaland                                  0x8de
#define XK_logicalor                                   0x8df
#define XK_partialderivative                           0x8ef
#define XK_function                                    0x8f6
#define XK_leftarrow                                   0x8fb
#define XK_uparrow                                     0x8fc
#define XK_rightarrow                                  0x8fd
#define XK_downarrow                                   0x8fe
#endif /* XK_TECHNICAL */

/*
 *  Special
 *  Byte 3 = 9
 */

#define XK_SPECIAL
#ifdef XK_SPECIAL
#define XK_blank                                       0x9df
#define XK_soliddiamond                                0x9e0
#define XK_checkerboard                                0x9e1
#define XK_ht                                          0x9e2
#define XK_ff                                          0x9e3
#define XK_cr                                          0x9e4
#define XK_lf                                          0x9e5
#define XK_nl                                          0x9e8
#define XK_vt                                          0x9e9
#define XK_lowrightcorner                              0x9ea
#define XK_uprightcorner                               0x9eb
#define XK_upleftcorner                                0x9ec
#define XK_lowleftcorner                               0x9ed
#define XK_crossinglines                               0x9ee
#define XK_horizlinescan1                              0x9ef
#define XK_horizlinescan3                              0x9f0
#define XK_horizlinescan5                              0x9f1
#define XK_horizlinescan7                              0x9f2
#define XK_horizlinescan9                              0x9f3
#define XK_leftt                                       0x9f4
#define XK_rightt                                      0x9f5
#define XK_bott                                        0x9f6
#define XK_topt                                        0x9f7
#define XK_vertbar                                     0x9f8
#endif /* XK_SPECIAL */

/*
 *  Publishing
 *  Byte 3 = a
 */

#define XK_PUBLISHING
#ifdef XK_PUBLISHING
#define XK_emspace                                     0xaa1
#define XK_enspace                                     0xaa2
#define XK_em3space                                    0xaa3
#define XK_em4space                                    0xaa4
#define XK_digitspace                                  0xaa5
#define XK_punctspace                                  0xaa6
#define XK_thinspace                                   0xaa7
#define XK_hairspace                                   0xaa8
#define XK_emdash                                      0xaa9
#define XK_endash                                      0xaaa
#define XK_signifblank                                 0xaac
#define XK_ellipsis                                    0xaae
#define XK_doubbaselinedot                             0xaaf
#define XK_onethird                                    0xab0
#define XK_twothirds                                   0xab1
#define XK_onefifth                                    0xab2
#define XK_twofifths                                   0xab3
#define XK_threefifths                                 0xab4
#define XK_fourfifths                                  0xab5
#define XK_onesixth                                    0xab6
#define XK_fivesixths                                  0xab7
#define XK_careof                                      0xab8
#define XK_figdash                                     0xabb
#define XK_leftanglebracket                            0xabc
#define XK_decimalpoint                                0xabd
#define XK_rightanglebracket                           0xabe
#define XK_marker                                      0xabf
#define XK_oneeighth                                   0xac3
#define XK_threeeighths                                0xac4
#define XK_fiveeighths                                 0xac5
#define XK_seveneighths                                0xac6
#define XK_trademark                                   0xac9
#define XK_signaturemark                               0xaca
#define XK_trademarkincircle                           0xacb
#define XK_leftopentriangle                            0xacc
#define XK_rightopentriangle                           0xacd
#define XK_emopencircle                                0xace
#define XK_emopenrectangle                             0xacf
#define XK_leftsinglequotemark                         0xad0
#define XK_rightsinglequotemark                        0xad1
#define XK_leftdoublequotemark                         0xad2
#define XK_rightdoublequotemark                        0xad3
#define XK_prescription                                0xad4
#define XK_minutes                                     0xad6
#define XK_seconds                                     0xad7
#define XK_latincross                                  0xad9
#define XK_hexagram                                    0xada
#define XK_filledrectbullet                            0xadb
#define XK_filledlefttribullet                         0xadc
#define XK_filledrighttribullet                        0xadd
#define XK_emfilledcircle                              0xade
#define XK_emfilledrect                                0xadf
#define XK_enopencircbullet                            0xae0
#define XK_enopensquarebullet                          0xae1
#define XK_openrectbullet                              0xae2
#define XK_opentribulletup                             0xae3
#define XK_opentribulletdown                           0xae4
#define XK_openstar                                    0xae5
#define XK_enfilledcircbullet                          0xae6
#define XK_enfilledsqbullet                            0xae7
#define XK_filledtribulletup                           0xae8
#define XK_filledtribulletdown                         0xae9
#define XK_leftpointer                                 0xaea
#define XK_rightpointer                                0xaeb
#define XK_club                                        0xaec
#define XK_diamond                                     0xaed
#define XK_heart                                       0xaee
#define XK_maltesecross                                0xaf0
#define XK_dagger                                      0xaf1
#define XK_doubledagger                                0xaf2
#define XK_checkmark                                   0xaf3
#define XK_ballotcross                                 0xaf4
#define XK_musicalsharp                                0xaf5
#define XK_musicalflat                                 0xaf6
#define XK_malesymbol                                  0xaf7
#define XK_femalesymbol                                0xaf8
#define XK_telephone                                   0xaf9
#define XK_telephonerecorder                           0xafa
#define XK_phonographcopyright                         0xafb
#define XK_caret                                       0xafc
#define XK_singlelowquotemark                          0xafd
#define XK_doublelowquotemark                          0xafe
#define XK_cursor                                      0xaff
#endif /* XK_PUBLISHING */

/*
 *  APL
 *  Byte 3 = b
 */

#define XK_APL
#ifdef XK_APL
#define XK_leftcaret                                   0xba3
#define XK_rightcaret                                  0xba6
#define XK_downcaret                                   0xba8
#define XK_upcaret                                     0xba9
#define XK_overbar                                     0xbc0
#define XK_downtack                                    0xbc2
#define XK_upshoe                                      0xbc3
#define XK_downstile                                   0xbc4
#define XK_underbar                                    0xbc6
#define XK_jot                                         0xbca
#define XK_quad                                        0xbcc
#define XK_uptack                                      0xbce
#define XK_circle                                      0xbcf
#define XK_upstile                                     0xbd3
#define XK_downshoe                                    0xbd6
#define XK_rightshoe                                   0xbd8
#define XK_leftshoe                                    0xbda
#define XK_lefttack                                    0xbdc
#define XK_righttack                                   0xbfc
#endif /* XK_APL */

/*
 * Hebrew
 * Byte 3 = c
 */

#define XK_HEBREW
#ifdef XK_HEBREW
#define XK_hebrew_doublelowline                        0xcdf
#define XK_hebrew_aleph                                0xce0
#define XK_hebrew_bet                                  0xce1
#define XK_hebrew_beth                                 0xce1  /* deprecated */
#define XK_hebrew_gimel                                0xce2
#define XK_hebrew_gimmel                               0xce2  /* deprecated */
#define XK_hebrew_dalet                                0xce3
#define XK_hebrew_daleth                               0xce3  /* deprecated */
#define XK_hebrew_he                                   0xce4
#define XK_hebrew_waw                                  0xce5
#define XK_hebrew_zain                                 0xce6
#define XK_hebrew_zayin                                0xce6  /* deprecated */
#define XK_hebrew_chet                                 0xce7
#define XK_hebrew_het                                  0xce7  /* deprecated */
#define XK_hebrew_tet                                  0xce8
#define XK_hebrew_teth                                 0xce8  /* deprecated */
#define XK_hebrew_yod                                  0xce9
#define XK_hebrew_finalkaph                            0xcea
#define XK_hebrew_kaph                                 0xceb
#define XK_hebrew_lamed                                0xcec
#define XK_hebrew_finalmem                             0xced
#define XK_hebrew_mem                                  0xcee
#define XK_hebrew_finalnun                             0xcef
#define XK_hebrew_nun                                  0xcf0
#define XK_hebrew_samech                               0xcf1
#define XK_hebrew_samekh                               0xcf1  /* deprecated */
#define XK_hebrew_ayin                                 0xcf2
#define XK_hebrew_finalpe                              0xcf3
#define XK_hebrew_pe                                   0xcf4
#define XK_hebrew_finalzade                            0xcf5
#define XK_hebrew_finalzadi                            0xcf5  /* deprecated */
#define XK_hebrew_zade                                 0xcf6
#define XK_hebrew_zadi                                 0xcf6  /* deprecated */
#define XK_hebrew_qoph                                 0xcf7
#define XK_hebrew_kuf                                  0xcf7  /* deprecated */
#define XK_hebrew_resh                                 0xcf8
#define XK_hebrew_shin                                 0xcf9
#define XK_hebrew_taw                                  0xcfa
#define XK_hebrew_taf                                  0xcfa  /* deprecated */
#define XK_Hebrew_switch        0xFF7E  /* Alias for mode_switch */
#endif /* XK_HEBREW */

/*
 * Thai
 * Byte 3 = d
 */

#define XK_THAI
#ifdef XK_THAI
#define XK_Thai_kokai					0xda1
#define XK_Thai_khokhai					0xda2
#define XK_Thai_khokhuat				0xda3
#define XK_Thai_khokhwai				0xda4
#define XK_Thai_khokhon					0xda5
#define XK_Thai_khorakhang			        0xda6
#define XK_Thai_ngongu					0xda7
#define XK_Thai_chochan					0xda8
#define XK_Thai_choching				0xda9
#define XK_Thai_chochang				0xdaa
#define XK_Thai_soso					0xdab
#define XK_Thai_chochoe					0xdac
#define XK_Thai_yoying					0xdad
#define XK_Thai_dochada					0xdae
#define XK_Thai_topatak					0xdaf
#define XK_Thai_thothan					0xdb0
#define XK_Thai_thonangmontho			        0xdb1
#define XK_Thai_thophuthao			        0xdb2
#define XK_Thai_nonen					0xdb3
#define XK_Thai_dodek					0xdb4
#define XK_Thai_totao					0xdb5
#define XK_Thai_thothung				0xdb6
#define XK_Thai_thothahan				0xdb7
#define XK_Thai_thothong	 			0xdb8
#define XK_Thai_nonu					0xdb9
#define XK_Thai_bobaimai				0xdba
#define XK_Thai_popla					0xdbb
#define XK_Thai_phophung				0xdbc
#define XK_Thai_fofa					0xdbd
#define XK_Thai_phophan					0xdbe
#define XK_Thai_fofan					0xdbf
#define XK_Thai_phosamphao			        0xdc0
#define XK_Thai_moma					0xdc1
#define XK_Thai_yoyak					0xdc2
#define XK_Thai_rorua					0xdc3
#define XK_Thai_ru					0xdc4
#define XK_Thai_loling					0xdc5
#define XK_Thai_lu					0xdc6
#define XK_Thai_wowaen					0xdc7
#define XK_Thai_sosala					0xdc8
#define XK_Thai_sorusi					0xdc9
#define XK_Thai_sosua					0xdca
#define XK_Thai_hohip					0xdcb
#define XK_Thai_lochula					0xdcc
#define XK_Thai_oang					0xdcd
#define XK_Thai_honokhuk				0xdce
#define XK_Thai_paiyannoi				0xdcf
#define XK_Thai_saraa					0xdd0
#define XK_Thai_maihanakat				0xdd1
#define XK_Thai_saraaa					0xdd2
#define XK_Thai_saraam					0xdd3
#define XK_Thai_sarai					0xdd4
#define XK_Thai_saraii					0xdd5
#define XK_Thai_saraue					0xdd6
#define XK_Thai_sarauee					0xdd7
#define XK_Thai_sarau					0xdd8
#define XK_Thai_sarauu					0xdd9
#define XK_Thai_phinthu					0xdda
#define XK_Thai_maihanakat_maitho   			0xdde
#define XK_Thai_baht					0xddf
#define XK_Thai_sarae					0xde0
#define XK_Thai_saraae					0xde1
#define XK_Thai_sarao					0xde2
#define XK_Thai_saraaimaimuan				0xde3
#define XK_Thai_saraaimaimalai				0xde4
#define XK_Thai_lakkhangyao				0xde5
#define XK_Thai_maiyamok				0xde6
#define XK_Thai_maitaikhu				0xde7
#define XK_Thai_maiek					0xde8
#define XK_Thai_maitho					0xde9
#define XK_Thai_maitri					0xdea
#define XK_Thai_maichattawa				0xdeb
#define XK_Thai_thanthakhat				0xdec
#define XK_Thai_nikhahit				0xded
#define XK_Thai_leksun					0xdf0
#define XK_Thai_leknung					0xdf1
#define XK_Thai_leksong					0xdf2
#define XK_Thai_leksam					0xdf3
#define XK_Thai_leksi					0xdf4
#define XK_Thai_lekha					0xdf5
#define XK_Thai_lekhok					0xdf6
#define XK_Thai_lekchet					0xdf7
#define XK_Thai_lekpaet					0xdf8
#define XK_Thai_lekkao					0xdf9
#endif /* XK_THAI */

/*
 *   Korean
 *   Byte 3 = e
 */

#define XK_KOREAN
#ifdef XK_KOREAN

#define XK_Hangul		0xff31    /* Hangul start/stop(toggle) */
#define XK_Hangul_Start		0xff32    /* Hangul start */
#define XK_Hangul_End		0xff33    /* Hangul end, English start */
#define XK_Hangul_Hanja		0xff34    /* Start Hangul->Hanja Conversion */
#define XK_Hangul_Jamo		0xff35    /* Hangul Jamo mode */
#define XK_Hangul_Romaja	0xff36    /* Hangul Romaja mode */
#define XK_Hangul_Codeinput	0xff37    /* Hangul code input mode */
#define XK_Hangul_Jeonja	0xff38    /* Jeonja mode */
#define XK_Hangul_Banja		0xff39    /* Banja mode */
#define XK_Hangul_PreHanja	0xff3a    /* Pre Hanja conversion */
#define XK_Hangul_PostHanja	0xff3b    /* Post Hanja conversion */
#define XK_Hangul_SingleCandidate	0xff3c    /* Single candidate */
#define XK_Hangul_MultipleCandidate	0xff3d    /* Multiple candidate */
#define XK_Hangul_PreviousCandidate	0xff3e    /* Previous candidate */
#define XK_Hangul_Special	0xff3f    /* Special symbols */
#define XK_Hangul_switch	0xFF7E    /* Alias for mode_switch */

/* Hangul Consonant Characters */
#define XK_Hangul_Kiyeog				0xea1
#define XK_Hangul_SsangKiyeog				0xea2
#define XK_Hangul_KiyeogSios				0xea3
#define XK_Hangul_Nieun					0xea4
#define XK_Hangul_NieunJieuj				0xea5
#define XK_Hangul_NieunHieuh				0xea6
#define XK_Hangul_Dikeud				0xea7
#define XK_Hangul_SsangDikeud				0xea8
#define XK_Hangul_Rieul					0xea9
#define XK_Hangul_RieulKiyeog				0xeaa
#define XK_Hangul_RieulMieum				0xeab
#define XK_Hangul_RieulPieub				0xeac
#define XK_Hangul_RieulSios				0xead
#define XK_Hangul_RieulTieut				0xeae
#define XK_Hangul_RieulPhieuf				0xeaf
#define XK_Hangul_RieulHieuh				0xeb0
#define XK_Hangul_Mieum					0xeb1
#define XK_Hangul_Pieub					0xeb2
#define XK_Hangul_SsangPieub				0xeb3
#define XK_Hangul_PieubSios				0xeb4
#define XK_Hangul_Sios					0xeb5
#define XK_Hangul_SsangSios				0xeb6
#define XK_Hangul_Ieung					0xeb7
#define XK_Hangul_Jieuj					0xeb8
#define XK_Hangul_SsangJieuj				0xeb9
#define XK_Hangul_Cieuc					0xeba
#define XK_Hangul_Khieuq				0xebb
#define XK_Hangul_Tieut					0xebc
#define XK_Hangul_Phieuf				0xebd
#define XK_Hangul_Hieuh					0xebe

/* Hangul Vowel Characters */
#define XK_Hangul_A					0xebf
#define XK_Hangul_AE					0xec0
#define XK_Hangul_YA					0xec1
#define XK_Hangul_YAE					0xec2
#define XK_Hangul_EO					0xec3
#define XK_Hangul_E					0xec4
#define XK_Hangul_YEO					0xec5
#define XK_Hangul_YE					0xec6
#define XK_Hangul_O					0xec7
#define XK_Hangul_WA					0xec8
#define XK_Hangul_WAE					0xec9
#define XK_Hangul_OE					0xeca
#define XK_Hangul_YO					0xecb
#define XK_Hangul_U					0xecc
#define XK_Hangul_WEO					0xecd
#define XK_Hangul_WE					0xece
#define XK_Hangul_WI					0xecf
#define XK_Hangul_YU					0xed0
#define XK_Hangul_EU					0xed1
#define XK_Hangul_YI					0xed2
#define XK_Hangul_I					0xed3

/* Hangul syllable-final (JongSeong) Characters */
#define XK_Hangul_J_Kiyeog				0xed4
#define XK_Hangul_J_SsangKiyeog				0xed5
#define XK_Hangul_J_KiyeogSios				0xed6
#define XK_Hangul_J_Nieun				0xed7
#define XK_Hangul_J_NieunJieuj				0xed8
#define XK_Hangul_J_NieunHieuh				0xed9
#define XK_Hangul_J_Dikeud				0xeda
#define XK_Hangul_J_Rieul				0xedb
#define XK_Hangul_J_RieulKiyeog				0xedc
#define XK_Hangul_J_RieulMieum				0xedd
#define XK_Hangul_J_RieulPieub				0xede
#define XK_Hangul_J_RieulSios				0xedf
#define XK_Hangul_J_RieulTieut				0xee0
#define XK_Hangul_J_RieulPhieuf				0xee1
#define XK_Hangul_J_RieulHieuh				0xee2
#define XK_Hangul_J_Mieum				0xee3
#define XK_Hangul_J_Pieub				0xee4
#define XK_Hangul_J_PieubSios				0xee5
#define XK_Hangul_J_Sios				0xee6
#define XK_Hangul_J_SsangSios				0xee7
#define XK_Hangul_J_Ieung				0xee8
#define XK_Hangul_J_Jieuj				0xee9
#define XK_Hangul_J_Cieuc				0xeea
#define XK_Hangul_J_Khieuq				0xeeb
#define XK_Hangul_J_Tieut				0xeec
#define XK_Hangul_J_Phieuf				0xeed
#define XK_Hangul_J_Hieuh				0xeee

/* Ancient Hangul Consonant Characters */
#define XK_Hangul_RieulYeorinHieuh			0xeef
#define XK_Hangul_SunkyeongeumMieum			0xef0
#define XK_Hangul_SunkyeongeumPieub			0xef1
#define XK_Hangul_PanSios				0xef2
#define XK_Hangul_KkogjiDalrinIeung			0xef3
#define XK_Hangul_SunkyeongeumPhieuf			0xef4
#define XK_Hangul_YeorinHieuh				0xef5

/* Ancient Hangul Vowel Characters */
#define XK_Hangul_AraeA					0xef6
#define XK_Hangul_AraeAE				0xef7

/* Ancient Hangul syllable-final (JongSeong) Characters */
#define XK_Hangul_J_PanSios				0xef8
#define XK_Hangul_J_KkogjiDalrinIeung			0xef9
#define XK_Hangul_J_YeorinHieuh				0xefa

/* Korean currency symbol */
#define XK_Korean_Won					0xeff

#endif /* XK_KOREAN */

/*
 *   Armenian
 *   Byte 3 = 0x14
 */

#define XK_ARMENIAN
#ifdef XK_ARMENIAN
#define XK_Armenian_eternity				0x14a1
#define XK_Armenian_ligature_ew				0x14a2
#define XK_Armenian_full_stop				0x14a3
#define XK_Armenian_verjaket				0x14a3
#define XK_Armenian_parenright				0x14a4
#define XK_Armenian_parenleft				0x14a5
#define XK_Armenian_guillemotright			0x14a6
#define XK_Armenian_guillemotleft			0x14a7
#define XK_Armenian_em_dash				0x14a8
#define XK_Armenian_dot					0x14a9
#define XK_Armenian_mijaket				0x14a9
#define XK_Armenian_separation_mark			0x14aa
#define XK_Armenian_but					0x14aa
#define XK_Armenian_comma				0x14ab
#define XK_Armenian_en_dash				0x14ac
#define XK_Armenian_hyphen				0x14ad
#define XK_Armenian_yentamna				0x14ad
#define XK_Armenian_ellipsis				0x14ae
#define XK_Armenian_exclam				0x14af
#define XK_Armenian_amanak				0x14af
#define XK_Armenian_accent				0x14b0
#define XK_Armenian_shesht				0x14b0
#define XK_Armenian_question				0x14b1
#define XK_Armenian_paruyk				0x14b1
#define XK_Armenian_AYB					0x14b2
#define XK_Armenian_ayb					0x14b3
#define XK_Armenian_BEN					0x14b4
#define XK_Armenian_ben					0x14b5
#define XK_Armenian_GIM					0x14b6
#define XK_Armenian_gim					0x14b7
#define XK_Armenian_DA					0x14b8
#define XK_Armenian_da					0x14b9
#define XK_Armenian_YECH				0x14ba
#define XK_Armenian_yech				0x14bb
#define XK_Armenian_ZA					0x14bc
#define XK_Armenian_za					0x14bd
#define XK_Armenian_E					0x14be
#define XK_Armenian_e					0x14bf
#define XK_Armenian_AT					0x14c0
#define XK_Armenian_at					0x14c1
#define XK_Armenian_TO					0x14c2
#define XK_Armenian_to					0x14c3
#define XK_Armenian_ZHE					0x14c4
#define XK_Armenian_zhe					0x14c5
#define XK_Armenian_INI					0x14c6
#define XK_Armenian_ini					0x14c7
#define XK_Armenian_LYUN				0x14c8
#define XK_Armenian_lyun				0x14c9
#define XK_Armenian_KHE					0x14ca
#define XK_Armenian_khe					0x14cb
#define XK_Armenian_TSA					0x14cc
#define XK_Armenian_tsa					0x14cd
#define XK_Armenian_KEN					0x14ce
#define XK_Armenian_ken					0x14cf
#define XK_Armenian_HO					0x14d0
#define XK_Armenian_ho					0x14d1
#define XK_Armenian_DZA					0x14d2
#define XK_Armenian_dza					0x14d3
#define XK_Armenian_GHAT				0x14d4
#define XK_Armenian_ghat				0x14d5
#define XK_Armenian_TCHE				0x14d6
#define XK_Armenian_tche				0x14d7
#define XK_Armenian_MEN					0x14d8
#define XK_Armenian_men					0x14d9
#define XK_Armenian_HI					0x14da
#define XK_Armenian_hi					0x14db
#define XK_Armenian_NU					0x14dc
#define XK_Armenian_nu					0x14dd
#define XK_Armenian_SHA					0x14de
#define XK_Armenian_sha					0x14df
#define XK_Armenian_VO					0x14e0
#define XK_Armenian_vo					0x14e1
#define XK_Armenian_CHA					0x14e2
#define XK_Armenian_cha					0x14e3
#define XK_Armenian_PE					0x14e4
#define XK_Armenian_pe					0x14e5
#define XK_Armenian_JE					0x14e6
#define XK_Armenian_je					0x14e7
#define XK_Armenian_RA					0x14e8
#define XK_Armenian_ra					0x14e9
#define XK_Armenian_SE					0x14ea
#define XK_Armenian_se					0x14eb
#define XK_Armenian_VEV					0x14ec
#define XK_Armenian_vev					0x14ed
#define XK_Armenian_TYUN				0x14ee
#define XK_Armenian_tyun				0x14ef
#define XK_Armenian_RE					0x14f0
#define XK_Armenian_re					0x14f1
#define XK_Armenian_TSO					0x14f2
#define XK_Armenian_tso					0x14f3
#define XK_Armenian_VYUN				0x14f4
#define XK_Armenian_vyun				0x14f5
#define XK_Armenian_PYUR				0x14f6
#define XK_Armenian_pyur				0x14f7
#define XK_Armenian_KE					0x14f8
#define XK_Armenian_ke					0x14f9
#define XK_Armenian_O					0x14fa
#define XK_Armenian_o					0x14fb
#define XK_Armenian_FE					0x14fc
#define XK_Armenian_fe					0x14fd
#define XK_Armenian_apostrophe				0x14fe
#define XK_Armenian_section_sign			0x14ff
#endif /* XK_ARMENIAN */

/*
 *   Georgian
 *   Byte 3 = 0x15
 */

#define XK_GEORGIAN
#ifdef XK_GEORGIAN
#define XK_Georgian_an					0x15d0
#define XK_Georgian_ban					0x15d1
#define XK_Georgian_gan					0x15d2
#define XK_Georgian_don					0x15d3
#define XK_Georgian_en					0x15d4
#define XK_Georgian_vin					0x15d5
#define XK_Georgian_zen					0x15d6
#define XK_Georgian_tan					0x15d7
#define XK_Georgian_in					0x15d8
#define XK_Georgian_kan					0x15d9
#define XK_Georgian_las					0x15da
#define XK_Georgian_man					0x15db
#define XK_Georgian_nar					0x15dc
#define XK_Georgian_on					0x15dd
#define XK_Georgian_par					0x15de
#define XK_Georgian_zhar				0x15df
#define XK_Georgian_rae					0x15e0
#define XK_Georgian_san					0x15e1
#define XK_Georgian_tar					0x15e2
#define XK_Georgian_un					0x15e3
#define XK_Georgian_phar				0x15e4
#define XK_Georgian_khar				0x15e5
#define XK_Georgian_ghan				0x15e6
#define XK_Georgian_qar					0x15e7
#define XK_Georgian_shin				0x15e8
#define XK_Georgian_chin				0x15e9
#define XK_Georgian_can					0x15ea
#define XK_Georgian_jil					0x15eb
#define XK_Georgian_cil					0x15ec
#define XK_Georgian_char				0x15ed
#define XK_Georgian_xan					0x15ee
#define XK_Georgian_jhan				0x15ef
#define XK_Georgian_hae					0x15f0
#define XK_Georgian_he					0x15f1
#define XK_Georgian_hie					0x15f2
#define XK_Georgian_we					0x15f3
#define XK_Georgian_har					0x15f4
#define XK_Georgian_hoe					0x15f5
#define XK_Georgian_fi					0x15f6
#endif /* XK_GEORGIAN */

/*
 * Azeri (and other Turkic or Caucasian languages of ex-USSR)
 * Byte 3 = 0x16
 */

#define XK_CAUCASUS
#ifdef XK_CAUCASUS
/* latin */
#define XK_Ccedillaabovedot	0x16a2
#define XK_Xabovedot		0x16a3
#define XK_Qabovedot		0x16a5
#define	XK_Ibreve		0x16a6
#define XK_IE			0x16a7
#define XK_UO			0x16a8
#define XK_Zstroke		0x16a9
#define	XK_Gcaron		0x16aa
#define	XK_Obarred		0x16af
#define XK_ccedillaabovedot	0x16b2
#define XK_xabovedot		0x16b3
#define	XK_Ocaron		0x16b4
#define XK_qabovedot		0x16b5
#define	XK_ibreve		0x16b6
#define XK_ie			0x16b7
#define XK_uo			0x16b8
#define XK_zstroke		0x16b9
#define	XK_gcaron		0x16ba
#define	XK_ocaron		0x16bd
#define	XK_obarred		0x16bf
#define XK_SCHWA		0x16c6
#define XK_schwa		0x16f6
/* those are not really Caucasus, but I put them here for now */
/* For Inupiak */
#define XK_Lbelowdot		0x16d1
#define XK_Lstrokebelowdot	0x16d2
#define XK_lbelowdot		0x16e1
#define XK_lstrokebelowdot	0x16e2
/* For Guarani */
#define XK_Gtilde		0x16d3
#define XK_gtilde		0x16e3
#endif /* XK_CAUCASUS */

/*
 *   Vietnamese
 *   Byte 3 = 0x1e
 */

#define XK_VIETNAMESE
#ifdef XK_VIETNAMESE
#define XK_Abelowdot					0x1ea0
#define XK_abelowdot					0x1ea1
#define XK_Ahook					0x1ea2
#define XK_ahook					0x1ea3
#define XK_Acircumflexacute				0x1ea4
#define XK_acircumflexacute				0x1ea5
#define XK_Acircumflexgrave				0x1ea6
#define XK_acircumflexgrave				0x1ea7
#define XK_Acircumflexhook				0x1ea8
#define XK_acircumflexhook				0x1ea9
#define XK_Acircumflextilde				0x1eaa
#define XK_acircumflextilde				0x1eab
#define XK_Acircumflexbelowdot				0x1eac
#define XK_acircumflexbelowdot				0x1ead
#define XK_Abreveacute					0x1eae
#define XK_abreveacute					0x1eaf
#define XK_Abrevegrave					0x1eb0
#define XK_abrevegrave					0x1eb1
#define XK_Abrevehook					0x1eb2
#define XK_abrevehook					0x1eb3
#define XK_Abrevetilde					0x1eb4
#define XK_abrevetilde					0x1eb5
#define XK_Abrevebelowdot				0x1eb6
#define XK_abrevebelowdot				0x1eb7
#define XK_Ebelowdot					0x1eb8
#define XK_ebelowdot					0x1eb9
#define XK_Ehook					0x1eba
#define XK_ehook					0x1ebb
#define XK_Etilde					0x1ebc
#define XK_etilde					0x1ebd
#define XK_Ecircumflexacute				0x1ebe
#define XK_ecircumflexacute				0x1ebf
#define XK_Ecircumflexgrave				0x1ec0
#define XK_ecircumflexgrave				0x1ec1
#define XK_Ecircumflexhook				0x1ec2
#define XK_ecircumflexhook				0x1ec3
#define XK_Ecircumflextilde				0x1ec4
#define XK_ecircumflextilde				0x1ec5
#define XK_Ecircumflexbelowdot				0x1ec6
#define XK_ecircumflexbelowdot				0x1ec7
#define XK_Ihook					0x1ec8
#define XK_ihook					0x1ec9
#define XK_Ibelowdot					0x1eca
#define XK_ibelowdot					0x1ecb
#define XK_Obelowdot					0x1ecc
#define XK_obelowdot					0x1ecd
#define XK_Ohook					0x1ece
#define XK_ohook					0x1ecf
#define XK_Ocircumflexacute				0x1ed0
#define XK_ocircumflexacute				0x1ed1
#define XK_Ocircumflexgrave				0x1ed2
#define XK_ocircumflexgrave				0x1ed3
#define XK_Ocircumflexhook				0x1ed4
#define XK_ocircumflexhook				0x1ed5
#define XK_Ocircumflextilde				0x1ed6
#define XK_ocircumflextilde				0x1ed7
#define XK_Ocircumflexbelowdot				0x1ed8
#define XK_ocircumflexbelowdot				0x1ed9
#define XK_Ohornacute					0x1eda
#define XK_ohornacute					0x1edb
#define XK_Ohorngrave					0x1edc
#define XK_ohorngrave					0x1edd
#define XK_Ohornhook					0x1ede
#define XK_ohornhook					0x1edf
#define XK_Ohorntilde					0x1ee0
#define XK_ohorntilde					0x1ee1
#define XK_Ohornbelowdot				0x1ee2
#define XK_ohornbelowdot				0x1ee3
#define XK_Ubelowdot					0x1ee4
#define XK_ubelowdot					0x1ee5
#define XK_Uhook					0x1ee6
#define XK_uhook					0x1ee7
#define XK_Uhornacute					0x1ee8
#define XK_uhornacute					0x1ee9
#define XK_Uhorngrave					0x1eea
#define XK_uhorngrave					0x1eeb
#define XK_Uhornhook					0x1eec
#define XK_uhornhook					0x1eed
#define XK_Uhorntilde					0x1eee
#define XK_uhorntilde					0x1eef
#define XK_Uhornbelowdot				0x1ef0
#define XK_uhornbelowdot				0x1ef1
#define XK_Ybelowdot					0x1ef4
#define XK_ybelowdot					0x1ef5
#define XK_Yhook					0x1ef6
#define XK_yhook					0x1ef7
#define XK_Ytilde					0x1ef8
#define XK_ytilde					0x1ef9
#define XK_Ohorn					0x1efa /* U+01a0 */
#define XK_ohorn					0x1efb /* U+01a1 */
#define XK_Uhorn					0x1efc /* U+01af */
#define XK_uhorn					0x1efd /* U+01b0 */

#define XK_combining_tilde				0x1e9f /* U+0303 */
#define XK_combining_grave				0x1ef2 /* U+0300 */
#define XK_combining_acute				0x1ef3 /* U+0301 */
#define XK_combining_hook				0x1efe /* U+0309 */
#define XK_combining_belowdot				0x1eff /* U+0323 */
#endif /* XK_VIETNAMESE */

#define XK_CURRENCY
#ifdef XK_CURRENCY
#define XK_EcuSign					0x20a0
#define XK_ColonSign					0x20a1
#define XK_CruzeiroSign					0x20a2
#define XK_FFrancSign					0x20a3
#define XK_LiraSign					0x20a4
#define XK_MillSign					0x20a5
#define XK_NairaSign					0x20a6
#define XK_PesetaSign					0x20a7
#define XK_RupeeSign					0x20a8
#define XK_WonSign					0x20a9
#define XK_NewSheqelSign				0x20aa
#define XK_DongSign					0x20ab
#define XK_EuroSign					0x20ac
#endif
