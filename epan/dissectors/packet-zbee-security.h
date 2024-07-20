/* packet-zbee-security.h
 * Dissector helper routines for encrypted ZigBee frames.
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ZBEE_SECURITY_H
#define PACKET_ZBEE_SECURITY_H

/*  Structure containing the fields stored in the Aux Header */
typedef struct{
    /*  The fields of the Aux Header */
    uint8_t     control; /* needed to decrypt */
    uint32_t    counter; /* needed to decrypt */
    uint64_t    src64;   /* needed to decrypt */
    uint8_t     key_seqno;

    uint8_t     level;
    uint8_t     key_id;  /* needed to decrypt */
    bool        nonce;
} zbee_security_packet;

/* Bit masks for the Security Control Field. */
#define ZBEE_SEC_CONTROL_LEVEL          0x07
#define ZBEE_SEC_CONTROL_KEY            0x18
#define ZBEE_SEC_CONTROL_NONCE          0x20
#define ZBEE_SEC_CONTROL_VERIFIED_FC    0x40

/* ZigBee security levels. */
#define ZBEE_SEC_NONE                   0x00
#define ZBEE_SEC_MIC32                  0x01
#define ZBEE_SEC_MIC64                  0x02
#define ZBEE_SEC_MIC128                 0x03
#define ZBEE_SEC_ENC                    0x04
#define ZBEE_SEC_ENC_MIC32              0x05
#define ZBEE_SEC_ENC_MIC64              0x06
#define ZBEE_SEC_ENC_MIC128             0x07

/* ZigBee Key Types */
#define ZBEE_SEC_KEY_LINK               0x00
#define ZBEE_SEC_KEY_NWK                0x01
#define ZBEE_SEC_KEY_TRANSPORT          0x02
#define ZBEE_SEC_KEY_LOAD               0x03

/* ZigBee Security Constants. */
#define ZBEE_SEC_CONST_L                2
#define ZBEE_SEC_CONST_NONCE_LEN        (ZBEE_SEC_CONST_BLOCKSIZE-ZBEE_SEC_CONST_L-1)
#define ZBEE_SEC_CONST_BLOCKSIZE        16

/* CCM* Flags */
#define ZBEE_SEC_CCM_FLAG_L             0x01    /* 3-bit encoding of (L-1). */
#define ZBEE_SEC_CCM_FLAG_M(m)          ((((m-2)/2) & 0x7)<<3)  /* 3-bit encoding of (M-2)/2 shifted 3 bits. */
#define ZBEE_SEC_CCM_FLAG_ADATA(l_a)    ((l_a>0)?0x40:0x00)     /* Adata flag. */

/* Program Constants */
#define ZBEE_SEC_PC_KEY             0

/* Init routine for the Security dissectors. */
extern void     zbee_security_register  (module_t *module, int proto);

/* Security Dissector Routine. */
extern tvbuff_t *dissect_zbee_secure(tvbuff_t *, packet_info *, proto_tree *, unsigned);
extern bool zbee_sec_ccm_decrypt(const char *, const char *, const char *, const char *, char *, unsigned, unsigned, unsigned);

/* nwk key ring update */
extern void zbee_sec_add_key_to_keyring(packet_info *, const uint8_t *);

#endif /* PACKET_ZBEE_SECURITY_H */

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
