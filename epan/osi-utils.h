/* osi-utils.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __OSI_UTILS_H__
#define __OSI_UTILS_H__

/* OSI Global defines, common for all OSI protocols */

#define MAX_NSAP_LEN          30
#define MAX_SYSTEMID_LEN      15
#define MAX_AREA_LEN          30

#define RFC1237_NSAP_LEN      20
#define RFC1237_FULLAREA_LEN  13
#define RFC1237_SYSTEMID_LEN   6
#define RFC1237_SELECTOR_LEN   1

#define RFC1237_IDI_LEN        2
#define RFC1237_AFI_LEN        1
#define RFC1237_DFI_LEN        1
#define RFC1237_ORG_LEN        3
#define RFC1237_AA_LEN         3
#define RFC1237_RSVD_LEN       2
#define RFC1237_RD_LEN         2
#define RFC1237_AREA_LEN       3	/* XXX - this not the length of the Area field in RFC 1237; what is it? */

/*
 * NSAP AFI values.
 * See ISO/IEC 8348 (2001-10)/X.213 (10/2001) Annex A.
 *
 * Individual values.
 */
#define NSAP_IDI_IANA_ICP_DEC        0x34 /* IANA ICP, decimal */
#define NSAP_IDI_IANA_ICP_BIN        0x35 /* IANA ICP, binary */
#define NSAP_IDI_X_121_DEC_FSD_NZ    0x36 /* X.121, decimal, IDI first significant digit non-zero */
#define NSAP_IDI_X_121_BIN_FSD_NZ    0x37 /* X.121, binary, IDI first significant digit non-zero */
#define NSAP_IDI_ISO_DCC_DEC         0x38 /* ISO DCC, decimal */
#define NSAP_IDI_ISO_DCC_BIN         0x39 /* ISO DCC, binary */
#define NSAP_IDI_F_69_DEC_FSD_NZ     0x40 /* F.69, decimal, IDI first significant digit non-zero */
#define NSAP_IDI_F_69_BIN_FSD_NZ     0x41 /* F.69, binary, IDI first significant digit non-zero */
#define NSAP_IDI_E_163_DEC_FSD_NZ    0x42 /* E.163, decimal, IDI first significant digit non-zero */
#define NSAP_IDI_E_163_BIN_FSD_NZ    0x43 /* E.163, binary, IDI first significant digit non-zero */
#define NSAP_IDI_E_164_DEC_FSD_NZ    0x44 /* E.163, decimal, IDI first significant digit non-zero */
#define NSAP_IDI_E_164_BIN_FSD_NZ    0x45 /* E.163, binary, IDI first significant digit non-zero */
#define NSAP_IDI_ISO_6523_ICD_DEC    0x46 /* ISO 6523-ICD, decimal */
#define NSAP_IDI_ISO_6523_ICD_BIN    0x47 /* ISO 6523-ICD, binary */
//#define NSAP_IDI_GOSIP2            0x47
#define NSAP_IDI_LOCAL_DEC           0x48 /* Local, decimal */
#define NSAP_IDI_LOCAL_BIN           0x49 /* Local, binary */
#define NSAP_IDI_LOCAL_ISO_646_CHAR  0x50 /* Local, ISO/IEC 646 character */
#define NSAP_IDI_LOCAL_NATIONAL_CHAR 0x51 /* Local, national character */
#define NSAP_IDI_X_121_DEC_FSD_Z     0x52 /* X.121, decimal, IDI first significant digit zero */
#define NSAP_IDI_X_121_BIN_FSD_Z     0x53 /* X.121, binary, IDI first significant digit zero */
#define NSAP_IDI_F_69_DEC_FSD_Z      0x54 /* F.69, decimal, IDI first significant digit zero */
#define NSAP_IDI_F_69_BIN_FSD_Z      0x55 /* F.69, binary, IDI first significant digit zero */
#define NSAP_IDI_E_163_DEC_FSD_Z     0x56 /* E.163, decimal, IDI first significant digit zero */
#define NSAP_IDI_E_163_BIN_FSD_Z     0x57 /* E.163, binary, IDI first significant digit zero */
#define NSAP_IDI_E_164_DEC_FSD_Z     0x58 /* E.163, decimal, IDI first significant digit zero */
#define NSAP_IDI_E_164_BIN_FSD_Z     0x59 /* E.163, binary, IDI first significant digit zero */
#define NSAP_IDI_ITU_T_IND_DEC       0x76 /* ITU-T IND, decimal */
#define NSAP_IDI_ITU_T_IND_BIN       0x77 /* ITU-T IND, binary */

/*
 * Group values.
 */
#define NSAP_IDI_IANA_ICP_DEC_GROUP        0xB8 /* IANA ICP, decimal */
#define NSAP_IDI_IANA_ICP_BIN_GROUP        0xB9 /* IANA ICP, binary */
#define NSAP_IDI_X_121_DEC_FSD_NZ_GROUP    0xBA /* X.121, decimal */
#define NSAP_IDI_X_121_BIN_FSD_NZ_GROUP    0xBB /* X.121, binary */
#define NSAP_IDI_ISO_DCC_DEC_GROUP         0xBC /* ISO DCC, decimal */
#define NSAP_IDI_ISO_DCC_BIN_GROUP         0xBD /* ISO DCC, binary */
#define NSAP_IDI_F_69_DEC_FSD_NZ_GROUP     0xBE /* F.69, decimal */
#define NSAP_IDI_F_69_BIN_FSD_NZ_GROUP     0xBF /* F.69, binary */
#define NSAP_IDI_E_163_DEC_FSD_NZ_GROUP    0xC0 /* E.163, decimal */
#define NSAP_IDI_E_163_BIN_FSD_NZ_GROUP    0xC1 /* E.163, binary */
#define NSAP_IDI_E_164_DEC_FSD_NZ_GROUP    0xC2 /* E.163, decimal */
#define NSAP_IDI_E_164_BIN_FSD_NZ_GROUP    0xC3 /* E.163, binary */
#define NSAP_IDI_ISO_6523_ICD_DEC_GROUP    0xC4 /* ISO 6523-ICD, decimal */
#define NSAP_IDI_ISO_6523_ICD_BIN_GROUP    0xC5 /* ISO 6523-ICD, binary */
#define NSAP_IDI_LOCAL_DEC_GROUP           0xC6 /* Local, decimal */
#define NSAP_IDI_LOCAL_BIN_GROUP           0xC7 /* Local, binary */
#define NSAP_IDI_LOCAL_ISO_646_CHAR_GROUP  0xC8 /* Local, ISO/IEC 646 character */
#define NSAP_IDI_LOCAL_NATIONAL_CHAR_GROUP 0xC9 /* Local, national character */
#define NSAP_IDI_X_121_DEC_FSD_Z_GROUP     0xCA /* X.121, decimal, IDI first significant digit zero */
#define NSAP_IDI_X_121_BIN_FSD_Z_GROUP     0xCB /* X.121, binary, IDI first significant digit zero */
#define NSAP_IDI_F_69_DEC_FSD_Z_GROUP      0xCC /* F.69, decimal, IDI first significant digit zero */
#define NSAP_IDI_F_69_BIN_FSD_Z_GROUP      0xCD /* F.69, binary, IDI first significant digit zero */
#define NSAP_IDI_E_163_DEC_FSD_Z_GROUP     0xCE /* E.163, decimal, IDI first significant digit zero */
#define NSAP_IDI_E_163_BIN_FSD_Z_GROUP     0xCF /* E.163, binary, IDI first significant digit zero */
#define NSAP_IDI_E_164_DEC_FSD_Z_GROUP     0xD0 /* E.163, decimal, IDI first significant digit zero */
#define NSAP_IDI_E_164_BIN_FSD_Z_GROUP     0xD1 /* E.163, binary, IDI first significant digit zero */
#define NSAP_IDI_ITU_T_IND_DEC_GROUP       0xE2 /* ITU-T IND, decimal */
#define NSAP_IDI_ITU_T_IND_BIN_GROUP       0xE3 /* ITU-T IND, binary */

gchar*     print_nsap_net ( tvbuff_t *, const gint, int );
gchar*     print_area     ( tvbuff_t *, const gint, int );
gchar*     print_system_id(wmem_allocator_t *, const guint8 *, int );
gchar*     tvb_print_system_id( tvbuff_t *, const gint, int );
void       print_system_id_buf( const guint8 *, int, gchar *, int);
gchar*     print_address_prefix( tvbuff_t *, const gint, int );

int        get_osi_address_type(void);
void       register_osi_address_type(void);

#endif /* __OSI_UTILS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
