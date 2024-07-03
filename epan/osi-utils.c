/* osi-utils.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 * Main entrance point and common functions
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 * Ralf Schneider <Ralf.Schneider@t-online.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "tvbuff.h"
#include "osi-utils.h"
#include "address.h"
#include "address_types.h"

static void print_nsap_net_buf( const uint8_t *, int, char *, int);
static void print_area_buf ( const uint8_t *, int, char *, int);
static void print_address_prefix_buf ( const uint8_t *, int, char *, int);

/*
 * XXX - shouldn't there be a centralized routine for dissecting NSAPs?
 * See also "dissect_atm_nsap()" in epan/dissectors/packet-arp.c and
 * "dissect_nsap()" in epan/dissectors/packet-isup.c.
 */
char *
print_nsap_net( wmem_allocator_t *scope, tvbuff_t *tvb, const int offset, int length )
{
  char *cur;

  cur = (char *)wmem_alloc(scope, MAX_NSAP_LEN * 3 + 50);
  print_nsap_net_buf( tvb_get_ptr(tvb, offset, length), length, cur, MAX_NSAP_LEN * 3 + 50);
  return( cur );
}

static void
print_nsap_net_buf( const uint8_t *ad, int length, char *buf, int buf_len)
{
  char *cur;

  /* to do : NSAP / NET decoding */

  if ( (length <= 0 ) || ( length > MAX_NSAP_LEN ) ) {
    (void) g_strlcpy(buf, "<Invalid length of NSAP>", buf_len);
    return;
  }
  cur = buf;
  if ( ( length == RFC1237_NSAP_LEN ) || ( length == RFC1237_NSAP_LEN + 1 ) ) {
    print_area_buf(ad, RFC1237_FULLAREA_LEN, cur, buf_len);
    cur += strlen( cur );
    print_system_id_buf( ad + RFC1237_FULLAREA_LEN, RFC1237_SYSTEMID_LEN, cur, (int) (buf_len-(cur-buf)));
    cur += strlen( cur );
    cur += snprintf(cur, buf_len-(cur-buf), "[%02x]",
                    ad[ RFC1237_FULLAREA_LEN + RFC1237_SYSTEMID_LEN ] );
    if ( length == RFC1237_NSAP_LEN + 1 ) {
      snprintf(cur, (int) (buf_len-(cur-buf)), "-%02x", ad[ length -1 ] );
    }
  }
  else {    /* probably format as standard */
    /* XXX - this is an NSAP, not an area address/address prefix */
    print_area_buf( ad, length, buf, buf_len);
  }
} /* print_nsap */

char *
print_system_id(wmem_allocator_t* scope, const uint8_t *ad, int length )
{
  char         *cur;

  cur = (char *)wmem_alloc(scope, MAX_SYSTEMID_LEN * 3 + 5);
  print_system_id_buf(ad, length, cur, MAX_SYSTEMID_LEN * 3 + 5);
  return( cur );
}

char *
tvb_print_system_id( wmem_allocator_t *scope, tvbuff_t *tvb, const int offset, int length )
{
  return( print_system_id(scope, tvb_get_ptr(tvb, offset, length), length) );
}

void
print_system_id_buf( const uint8_t *ad, int length, char *buf, int buf_len)
{
  char         *cur;
  int           tmp;

  if ( ( length <= 0 ) || ( length > MAX_SYSTEMID_LEN ) ) {
    (void) g_strlcpy(buf, "<Invalid length of SYSTEM ID>", buf_len);
    return;
  }

  cur = buf;
  if ( ( 6 == length ) || /* System-ID */
       ( 7 == length ) || /* LAN-ID */
       ( 8 == length )) { /* LSP-ID */
    cur += snprintf(cur, buf_len, "%02x%02x.%02x%02x.%02x%02x", ad[0], ad[1],
                    ad[2], ad[3], ad[4], ad[5] );
    if ( ( 7 == length ) ||
         ( 8 == length )) {
        cur += snprintf(cur, buf_len-(cur-buf), ".%02x", ad[6] );
    }
    if ( 8 == length ) {
        snprintf(cur, buf_len-(cur-buf), "-%02x", ad[7] );
    }
  }
  else {
    tmp = 0;
    while ( tmp < length / 4 ) { /* 16 / 4 == 4 > four Octets left to print */
      cur += snprintf(cur, buf_len-(cur-buf), "%02x", ad[tmp++] );
      cur += snprintf(cur, buf_len-(cur-buf), "%02x", ad[tmp++] );
      cur += snprintf(cur, buf_len-(cur-buf), "%02x", ad[tmp++] );
      cur += snprintf(cur, buf_len-(cur-buf), "%02x.", ad[tmp++] );
    }
    if ( 1 == tmp ) {   /* Special case for Designated IS */
      cur--;
      snprintf(cur, buf_len-(cur-buf), ".%02x", ad[tmp] );
    }
    else {
      for ( ; tmp < length; ) {  /* print the rest without dot */
        cur += snprintf(cur, buf_len-(cur-buf), "%02x", ad[tmp++] );
      }
    }
  }
}

char *
print_area(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset, int length)
{
  char *cur;

  cur = (char *)wmem_alloc(scope, MAX_AREA_LEN * 3 + 20);
  print_area_buf(tvb_get_ptr(tvb, offset, length), length, cur, MAX_AREA_LEN * 3 + 20);
  return cur;
}

/*
 * Note: length is in units of half-octets.
 */
char *
print_address_prefix(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset, int length)
{
  char *cur;

  cur = (char *)wmem_alloc(scope, MAX_AREA_LEN * 3 + 20);
  print_address_prefix_buf(tvb_get_ptr(tvb, offset, (length+1)/2), length, cur, MAX_AREA_LEN * 3 + 20);
  return cur;
}

/*
 * Note: length is in units of octets.
 */
static void
print_area_buf(const uint8_t *ad, int length, char *buf, int buf_len)
{
  print_address_prefix_buf(ad, length*2, buf, buf_len);
}

/*
 * Note: length is in units of half-octets.
 */
static void
print_address_prefix_buf(const uint8_t *ad, int length, char *buf, int buf_len)
{
  char *cur;
  int  tmp  = 0;

  /* to do : all real area decoding now: NET is assumed if id len is 1 more byte
   */
  if (length <= 0 || length > MAX_AREA_LEN*2) {
    (void) g_strlcpy(buf, "<Invalid length of AREA>", buf_len);
    return;
  }

  cur = buf;
  /* Check the AFI and length. */
  if ( (  ( NSAP_IDI_ISO_DCC_BIN      == *ad )
       || ( NSAP_IDI_ISO_6523_ICD_BIN == *ad )
       )
       &&
       (  ( RFC1237_FULLAREA_LEN*2       ==  length )
       || ( (RFC1237_FULLAREA_LEN + 1)*2 ==  length )
       )
     ) {    /* AFI is good and length is long enough  */

    /* The AFI is either ISO DCC, binary or ISO 6523-ICD, binary,
     * and the area length corresponds either to the area length
     * for RFC 1237 (GOSIP) addresses or that length + 1.
     *
     * XXX - RFC 1237 doesn't mention ISO DCC, binary, as a valid
     * AFI; is that from GOSIP Version 1?  If it's ISO DCC, binary,
     * the IDI is 3 digits, i.e. 1 1/2 octets.
     */
    /* there used to be a check for (length > RFC1237_FULLAREA_LEN + 1) here,
     * in order to report an invalied length of AREA for DCC / ISO 6523 AFI,
     * but that can *never* be the case because the if() test above explicitly
     * tests for (length == RFC1237_FULLAREA_LEN) or (length == RFC1237_FULLAREA_LEN + 1)
     */

    /* Show the one-octet AFI, the two-octet IDI, the one-octet DFI, the
     * 3-octet AA, and the 2 reserved octets.
     */
    cur += snprintf(cur, buf_len-(cur-buf), "[%02x|%02x:%02x][%02x|%02x:%02x:%02x|%02x:%02x]",
                    ad[0], ad[1], ad[2], ad[3], ad[4],
                    ad[5], ad[6], ad[7], ad[8] );
    /* Show the 2-octet RD and the 2-octet Area. */
    cur += snprintf(cur, buf_len-(cur-buf), "[%02x:%02x|%02x:%02x]",
                    ad[9], ad[10],  ad[11], ad[12] );
    /* Show whatever the heck this is; it's not specified by RFC 1237,
     * but we also handle 14-octet areas.  Is it the "Designated IS"
     * stuff mentioned below?  (I didn't find anything in the IS-IS
     * spec about that.)
     */
    if ( (RFC1237_FULLAREA_LEN + 1)*2 == length )
      snprintf(cur, buf_len-(cur-buf), "-[%02x]", ad[13] );
  }
  else {
    /* This doesn't look like a full RFC 1237 IS-IS area, so all we know
     * is that the first octet is an AFI.  Print it separately from all
     * the other octets.
     */
    if ( length == RFC1237_AREA_LEN*2 ) {
      /* XXX - RFC1237_AREA_LEN, which is 3 octets, doesn't seem to
       * correspond to anything in RFC 1237.  Where did it come from?
       */
      snprintf(buf, buf_len, "%02x.%02x%02x", ad[0], ad[1], ad[2] );
      return;
    }
    if ( length == 4*2 ) {
      snprintf(buf, buf_len, "%02x%02x%02x%02x", ad[0], ad[1], ad[2], ad[3] );
      return;
    }
    while ( tmp < length / 8 ) {      /* 32/8==4 > four Octets left to print */
      cur += snprintf(cur, buf_len-(cur-buf), "%02x", ad[tmp++] );
      cur += snprintf(cur, buf_len-(cur-buf), "%02x", ad[tmp++] );
      cur += snprintf(cur, buf_len-(cur-buf), "%02x", ad[tmp++] );
      cur += snprintf(cur, buf_len-(cur-buf), "%02x.", ad[tmp++] );
    }
    if ( 2 == tmp ) {                     /* Special case for Designated IS */
      cur--;
      snprintf(cur, buf_len-(cur-buf), "-%02x", ad[tmp] );
    }
    else {
      for ( ; tmp < length / 2; ) {  /* print the rest without dot or dash */
        cur += snprintf(cur, buf_len-(cur-buf), "%02x", ad[tmp++] );
      }
      /* Odd half-octet? */
      if (length & 1) {
        /* Yes - print it (it's the upper half-octet) */
        snprintf(cur, buf_len-(cur-buf), "%x", (ad[tmp] & 0xF0)>>4 );
      }
    }
  }
} /* print_address_prefix_buf */

/******************************************************************************
 * OSI Address Type
 ******************************************************************************/
static int osi_address_type = -1;

static int osi_address_to_str(const address* addr, char *buf, int buf_len)
{
    print_nsap_net_buf((const uint8_t *)addr->data, addr->len, buf, buf_len);
    return (int)strlen(buf)+1;
}

static int osi_address_str_len(const address* addr _U_)
{
    return MAX_NSAP_LEN * 3 + 50;
}

int get_osi_address_type(void)
{
    return osi_address_type;
}

void register_osi_address_type(void)
{
    if (osi_address_type != -1)
        return;

    osi_address_type = address_type_dissector_register("AT_OSI", "OSI Address", osi_address_to_str, osi_address_str_len, NULL, NULL, NULL, NULL, NULL);
}


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
