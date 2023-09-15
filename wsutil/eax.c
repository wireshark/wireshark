/* eax.c
 * Encryption and decryption routines implementing the EAX' encryption mode
 * Copyright 2010, Edward J. Beroset, edward.j.beroset@us.elster.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include "eax.h"
#include <stdlib.h>
#include <string.h>
/* Use libgcrypt for cipher libraries. */
#include <gcrypt.h>

typedef struct {
    uint8_t L[EAX_SIZEOF_KEY];
    uint8_t D[EAX_SIZEOF_KEY];
    uint8_t Q[EAX_SIZEOF_KEY];
} eax_s;

static eax_s instance;

/* these are defined as macros so they'll be easy to redo in assembly if desired */
#define BLK_CPY(dst, src) { memcpy(dst, src, EAX_SIZEOF_KEY); }
#define BLK_XOR(dst, src) { int z; for (z=0; z < EAX_SIZEOF_KEY; z++) dst[z] ^= src[z]; }
static void Dbl(uint8_t *out, const uint8_t *in);
static void CTR(const uint8_t *ws, uint8_t *pK, uint8_t *pN, uint16_t SizeN);
static void CMAC(uint8_t *pK, uint8_t *ws, const uint8_t *pN, uint16_t SizeN);
static void dCMAC(uint8_t *pK, uint8_t *ws, const uint8_t *pN, uint16_t SizeN, const uint8_t *pC, uint16_t SizeC);
void AesEncrypt(unsigned char msg[EAX_SIZEOF_KEY], unsigned char key[EAX_SIZEOF_KEY]);

/*!
 Decrypts cleartext data using EAX' mode (see ANSI Standard C12.22-2008).

 @param[in]     pN      pointer to cleartext (canonified form)
 @param[in]     pK      pointer to secret key
 @param[in,out] pC      pointer to ciphertext
 @param[in]     SizeN   byte length of cleartext (pN) buffer
 @param[in]     SizeK   byte length of secret key (pK)
 @param[in]     SizeC   byte length of ciphertext (pC) buffer
 @param[in]     pMac    four-byte Message Authentication Code
 @param[in]     Mode    EAX_MODE_CLEARTEXT_AUTH or EAX_MODE_CIPHERTEXT_AUTH
 @return                true if message has been authenticated; false if not
                        authenticated, invalid Mode or error
 */
bool Eax_Decrypt(uint8_t *pN, uint8_t *pK, uint8_t *pC,
                     uint32_t SizeN, uint32_t SizeK, uint32_t SizeC, MAC_T *pMac,
                     uint8_t Mode)
{
    uint8_t wsn[EAX_SIZEOF_KEY];
    uint8_t wsc[EAX_SIZEOF_KEY];
    int i;

    /* key size must match this implementation */
    if (SizeK != EAX_SIZEOF_KEY)
        return false;

    /* the key is new */
    for (i = 0; i < EAX_SIZEOF_KEY; i++)
        instance.L[i] = 0;
    AesEncrypt(instance.L, pK);
    Dbl(instance.D, instance.L);
    Dbl(instance.Q, instance.D);
    /* the key is set up */
    /* first copy the nonce into our working space */
    BLK_CPY(wsn, instance.D);
    if (Mode == EAX_MODE_CLEARTEXT_AUTH) {
        dCMAC(pK, wsn, pN, SizeN, pC, SizeC);
    } else {
        CMAC(pK, wsn, pN, SizeN);
    }
    /*
     *  In authentication mode the inputs are: pN, pK (and associated sizes),
     *  the result is the 4 byte MAC.
     */
    if (Mode == EAX_MODE_CLEARTEXT_AUTH)
    {
        return (memcmp(pMac, &wsn[EAX_SIZEOF_KEY-sizeof(*pMac)], sizeof(*pMac)) ? false : true);

    }

    /*
     * In cipher mode the inputs are: pN, pK, pP (and associated sizes),
     * the results are pC (and its size) along with the 4 byte MAC.
     */
    else if (Mode == EAX_MODE_CIPHERTEXT_AUTH)
    {
        if (SizeC == 0)
            return (memcmp(pMac, &wsn[EAX_SIZEOF_KEY-sizeof(*pMac)], sizeof(*pMac)) ? false : true);
        {
            /* first copy the nonce into our working space */
            BLK_CPY(wsc, instance.Q);
            CMAC(pK, wsc, pC, SizeC);
            BLK_XOR(wsc, wsn);
        }
        if (memcmp(pMac, &wsc[EAX_SIZEOF_KEY-sizeof(*pMac)], sizeof(*pMac)) == 0)
        {
            CTR(wsn, pK, pC, SizeC);
            return true;
        }
    }
    return false;
}

/* set up D or Q from L */
static void Dbl(uint8_t *out, const uint8_t *in)
{
    int i;
    uint8_t carry = 0;

    /* this might be a lot more efficient in assembly language */
    for (i=0; i < EAX_SIZEOF_KEY; i++)
    {
        out[i] = ( in[i] << 1 ) | carry;
        carry = (in[i] & 0x80) ? 1 : 0;
    }
    if (carry)
        out[0] ^= 0x87;
}

static void CMAC(uint8_t *pK, uint8_t *ws, const uint8_t *pN, uint16_t SizeN)
{
    dCMAC(pK, ws, pN, SizeN, NULL, 0);
}

static void dCMAC(uint8_t *pK, uint8_t *ws, const uint8_t *pN, uint16_t SizeN, const uint8_t *pC, uint16_t SizeC)
{
    gcry_cipher_hd_t cipher_hd;
    uint8_t *work;
    uint8_t *ptr;
    uint16_t SizeT = SizeN + SizeC;
    uint16_t worksize = SizeT;

    /* worksize must be an integral multiple of 16 */
    if (SizeT & 0xf)  {
        worksize += 0x10 - (worksize & 0xf);
    }
    work = (uint8_t *)g_malloc(worksize);
    if (work == NULL) {
        return;
    }
    memcpy(work, pN, SizeN);
    if (pC != NULL) {
        memcpy(&work[SizeN], pC, SizeC);
    }
    /*
     * pad the data if necessary, and XOR Q or D, depending on
     * whether data was padded or not
     */
    if (worksize != SizeT) {
        work[SizeT] = 0x80;
        for (ptr = &work[SizeT+1]; ptr < &work[worksize]; ptr++)
            *ptr = 0;
        ptr= &work[worksize-0x10];
        BLK_XOR(ptr, instance.Q);
    } else {
        ptr = &work[worksize-0x10];
        BLK_XOR(ptr, instance.D);
    }
    /* open the cipher */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC,0)){/* GCRY_CIPHER_CBC_MAC)) { */
        g_free(work);
        return;
    }
    if (gcry_cipher_setkey(cipher_hd, pK, EAX_SIZEOF_KEY)) {
        g_free(work);
        gcry_cipher_close(cipher_hd);
        return;
    }
    if (gcry_cipher_setiv(cipher_hd, ws, EAX_SIZEOF_KEY)) {
        g_free(work);
        gcry_cipher_close(cipher_hd);
        return;
    }
    if (gcry_cipher_encrypt(cipher_hd, work, worksize, work, worksize)) {
        g_free(work);
        gcry_cipher_close(cipher_hd);
        return;
    }
    memcpy(ws, ptr, EAX_SIZEOF_KEY);

    g_free(work);
    gcry_cipher_close(cipher_hd);
    return;
}

static void CTR(const uint8_t *ws, uint8_t *pK, uint8_t *pN, uint16_t SizeN)
{
    gcry_cipher_hd_t cipher_hd;
    uint8_t ctr[EAX_SIZEOF_KEY];

    BLK_CPY(ctr, ws);
    ctr[12] &= 0x7f;
    ctr[14] &= 0x7f;
    /* open the cipher */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)) {
        return;
    }
    if (gcry_cipher_setkey(cipher_hd, pK, EAX_SIZEOF_KEY)) {
        gcry_cipher_close(cipher_hd);
        return;
    }
    if (gcry_cipher_setctr(cipher_hd, ctr, EAX_SIZEOF_KEY)) {
        gcry_cipher_close(cipher_hd);
        return;
    }
    if (gcry_cipher_encrypt(cipher_hd, pN, SizeN, pN, SizeN)) {
        gcry_cipher_close(cipher_hd);
        return;
    }
    gcry_cipher_close(cipher_hd);
    return;
}

void AesEncrypt(unsigned char msg[EAX_SIZEOF_KEY], unsigned char key[EAX_SIZEOF_KEY])
{
    gcry_cipher_hd_t cipher_hd;

    /* open the cipher */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return;
    }
    if (gcry_cipher_setkey(cipher_hd, key, EAX_SIZEOF_KEY)) {
        gcry_cipher_close(cipher_hd);
        return;
    }
    if (gcry_cipher_encrypt(cipher_hd, msg, EAX_SIZEOF_KEY, msg, EAX_SIZEOF_KEY)) {
        gcry_cipher_close(cipher_hd);
        return;
    }
    gcry_cipher_close(cipher_hd);
    return;
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
