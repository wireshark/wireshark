/* address.h
 * Definitions for structures storing addresses, and for the type of
 * variables holding port-type values
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

#ifndef __ADDRESS_H__
#define __ADDRESS_H__

#include <string.h>     /* for memcmp */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Types of addresses Wireshark knows about. */
/* If a new address type is added here, a string representation procedure should */
/* also be included in address_to_str_buf defined in to_str.c, for presentation purposes */

typedef enum {
    AT_NONE,               /* no link-layer address */
    AT_ETHER,              /* MAC (Ethernet, 802.x, FDDI) address */
    AT_IPv4,               /* IPv4 */
    AT_IPv6,               /* IPv6 */
    AT_IPX,                /* IPX */
    AT_SNA,                /* SNA */
    AT_ATALK,              /* Appletalk DDP */
    AT_VINES,              /* Banyan Vines */
    AT_OSI,                /* OSI NSAP */
    AT_ARCNET,             /* ARCNET */
    AT_FC,                 /* Fibre Channel */
    AT_SS7PC,              /* SS7 Point Code */
    AT_STRINGZ,            /* null-terminated string */
    AT_EUI64,              /* IEEE EUI-64 */
    AT_URI,                /* URI/URL/URN */
    AT_TIPC,               /* TIPC Address Zone,Subnetwork,Processor */
    AT_IB,                 /* Infiniband GID/LID */
    AT_USB,                /* USB Device address
                            * (0xffffffff represents the host) */
    AT_AX25,               /* AX.25 */
    AT_IEEE_802_15_4_SHORT,/* IEEE 802.15.4 16-bit short address */
                           /* (the long addresses are EUI-64's */
    AT_J1939,              /* J1939 */
    AT_DEVICENET           /* DeviceNet */
} address_type;

typedef struct _address {
    address_type  type;		/* type of address */
    int           hf;		/* the specific field that this addr is */
    int           len;		/* length of address, in bytes */
    const void	*data;		/* pointer to address data */
} address;

/** Initialize an address with the given values.
 *
 * @param addr [in,out] The address to initialize.
 * @param addr_type [in] Address type.
 * @param addr_len [in] The length in bytes of the address data. For example, 4 for
 *                     AT_IPv4 or sizeof(struct e_in6_addr) for AT_IPv6.
 * @param addr_data [in] Pointer to the address data.
 */
static inline void
set_address(address *addr, address_type addr_type, int addr_len, const void * addr_data) {
    addr->data = addr_data;
    addr->type = addr_type;
    addr->hf   = -1;
    addr->len  = addr_len;
}
#define	SET_ADDRESS(addr, addr_type, addr_len, addr_data) \
    set_address((addr), (addr_type), (addr_len), (addr_data))

/** Initialize an address from TVB data.
 *
 * Same as SET_ADDRESS but it takes a TVB and an offset. This is preferred
 * over passing the return value of tvb_get_ptr() to set_address().
 *
 * This calls tvb_get_ptr() (including throwing any exceptions) before
 * modifying the address.
 *
 * @param addr [in,out] The address to initialize.
 * @param addr_type [in] Address type.
 * @param tvb [in] Pointer to the TVB.
 * @param offset [in] Offset within the TVB.
 * @param addr_len [in] The length in bytes of the address data. For example, 4 for
 *                     AT_IPv4 or sizeof(struct e_in6_addr) for AT_IPv6.
 */
#define	TVB_SET_ADDRESS(addr, addr_type, tvb, offset, addr_len) \
    do {                            \
        const void *TVB_SET_ADDRESS_data = (const void *)tvb_get_ptr(tvb, offset, addr_len); \
        set_address((addr), (addr_type), (addr_len), TVB_SET_ADDRESS_data); \
    } while (0)

/** Initialize an address with the given values including an associated field.
 *
 * @param addr [in,out] The address to initialize.
 * @param addr_type [in] Address type.
 * @param addr_len [in] The length in bytes of the address data. For example, 4 for
 *                 AT_IPv4 or sizeof(struct e_in6_addr) for AT_IPv6.
 * @param addr_data [in] Pointer to the address data.
 * @param addr_hf [in] The header field index to associate with the address.
 */
static inline void
set_address_hf(address *addr, address_type addr_type, int addr_len, const void * addr_data, int addr_hf) {
    addr->data = addr_data;
    addr->type = addr_type;
    addr->hf   = addr_hf;
    addr->len  = addr_len;
}
#define	SET_ADDRESS_HF(addr, addr_type, addr_len, addr_data, addr_hf) \
    set_address_hf((addr), (addr_type), (addr_len), (addr_data), (addr_hf))

/** Initialize an address from TVB data including an associated field.
 *
 * Same as SET_ADDRESS_HF but it takes a TVB and an offset. This is preferred
 * over passing the return value of tvb_get_ptr() to set_address().
 *
 * This calls tvb_get_ptr() (including throwing any exceptions) before
 * modifying the address.
 *
 * @param addr [in,out] The address to initialize.
 * @param addr_type [in] Address type.
 * @param tvb [in] Pointer to the TVB.
 * @param offset [in] Offset within the TVB.
 * @param addr_len [in] The length in bytes of the address data. For example, 4 for
 *                     AT_IPv4 or sizeof(struct e_in6_addr) for AT_IPv6.
 * @param addr_hf [in] The header field index to associate with the address.
 */
#define	TVB_SET_ADDRESS_HF(addr, addr_type, tvb, offset, addr_len, addr_hf) \
    do {                            \
        const void *TVB_SET_ADDRESS_data = (const void *) tvb_get_ptr(tvb, offset, addr_len); \
        set_address_hf((addr), (addr_type), (addr_len), TVB_SET_ADDRESS_data, (addr_hf)); \
    } while (0)

/** Compare two addresses.
 *
 * @param addr1 [in] The first address to compare.
 * @param addr2 [in] The second address to compare.
 * @return 0 if the addresses are equal,
 *  A positive number if addr1 > addr2 in some nondefined metric,
 *  A negative number if addr1 < addr2 in some nondefined metric.
 */
static inline int
cmp_address(const address *addr1, const address *addr2) {
    if (addr1->type > addr2->type) return 1;
    if (addr1->type < addr2->type) return -1;
    if (addr1->len  > addr2->len) return 1;
    if (addr1->len  < addr2->len) return -1;
    return memcmp(addr1->data, addr2->data, addr1->len);
}
#define CMP_ADDRESS(addr1, addr2) cmp_address((addr1), (addr2))

/** Check two addresses for equality.
 *
 * Given two addresses, return "true" if they're equal, "false" otherwise.
 * Addresses are equal only if they have the same type; if the type is
 * AT_NONE, they are then equal, otherwise they must have the same
 * amount of data and the data must be the same.
 *
 * @param addr1 [in] The first address to compare.
 * @param addr2 [in] The second address to compare.
 * @return TRUE if the adresses are equal, FALSE otherwise.
 */
static inline gboolean
addresses_equal(const address *addr1, const address *addr2) {
    if (addr1->type == addr2->type
            && ( addr1->type == AT_NONE
                 || ( addr1->len == addr2->len
                      && memcmp(addr1->data, addr2->data, addr1->len) == 0
                      )
                 )
            ) return TRUE;
    return FALSE;
}
#define ADDRESSES_EQUAL(addr1, addr2) addresses_equal((addr1), (addr2))

/** Copy an address, allocating a new buffer for the address data.
 *
 * @param to [in,out] The destination address.
 * @param from [in] The source address.
 */
static inline void
copy_address(address *to, const address *from) {
    guint8 *to_data;

    to->type = from->type;
    to->len = from->len;
    to->hf = from->hf;
    to_data = (guint8 *)g_malloc(from->len);
    memcpy(to_data, from->data, from->len);
    to->data = to_data;
}
#define COPY_ADDRESS(to, from) copy_address((to), (from))

/** Perform a shallow copy of the address (both addresses point to the same
 * memory location).
 *
 * @param to [in,out] The destination address.
 * @param from [in] The source address.
 */
static inline void
copy_address_shallow(address *to, const address *from) {
    memcpy(to, from, sizeof(address));
    /*
    to->type = from->type;
    to->len = from->len;
    to->hf = from->hf;
    to->data = from->data;
    */
}
#define COPY_ADDRESS_SHALLOW(to, from) copy_address_shallow((to), (from))

/** Copy an address, allocating a new buffer for the address data
 *  using seasonal memory.
 *
 * @param to [in,out] The destination address.
 * @param from [in] The source address.
 */
#define SE_COPY_ADDRESS(to, from)     \
    do {                              \
        void *SE_COPY_ADDRESS_data; \
        copy_address_shallow((to), (from)); \
        SE_COPY_ADDRESS_data = se_alloc((from)->len); \
        memcpy(SE_COPY_ADDRESS_data, (from)->data, (from)->len); \
        (to)->data = SE_COPY_ADDRESS_data; \
    } while (0)


/** Hash an address into a hash value (which must already have been set).
 *
 * @param hash_val The existing hash value.
 * @param addr The address to add.
 * @return The new hash value.
 */
static inline guint
add_address_to_hash(guint hash_val, const address *addr) {
    const guint8 *hash_data = (const guint8 *)(addr)->data;
    int idx;

    for (idx = 0; idx < (addr)->len; idx++) {
        hash_val += hash_data[idx];
        hash_val += ( hash_val << 10 );
        hash_val ^= ( hash_val >> 6 );
    }
    return hash_val;
}
#define ADD_ADDRESS_TO_HASH(hash_val, addr) do { hash_val = add_address_to_hash(hash_val, (addr)); } while (0)

/** Hash an address into a hash value (which must already have been set).
 *  64-bit version of add_address_to_hash().
 *
 * @param hash_val The existing hash value.
 * @param addr The address to add.
 * @return The new hash value.
 */
static inline guint64
add_address_to_hash64(guint64 hash_val, const address *addr) {
    const guint8 *hash_data = (const guint8 *)(addr)->data;
    int idx;

    for (idx = 0; idx < (addr)->len; idx++) {
        hash_val += hash_data[idx];
        hash_val += ( hash_val << 10 );
        hash_val ^= ( hash_val >> 6 );
    }
    return hash_val;
}

/* Types of port numbers Wireshark knows about. */
typedef enum {
    PT_NONE,		/* no port number */
    PT_SCTP,		/* SCTP */
    PT_TCP,		/* TCP */
    PT_UDP,		/* UDP */
    PT_DCCP,		/* DCCP */
    PT_IPX,		/* IPX sockets */
    PT_NCP,		/* NCP connection */
    PT_EXCHG,		/* Fibre Channel exchange */
    PT_DDP,		/* DDP AppleTalk connection */
    PT_SBCCS,		/* FICON */
    PT_IDP,		/* XNS IDP sockets */
    PT_TIPC,		/* TIPC PORT */
    PT_USB,		/* USB endpoint 0xffff means the host */
    PT_I2C,
    PT_IBQP,		/* Infiniband QP number */
    PT_BLUETOOTH
} port_type;

/* Types of circuit IDs Wireshark knows about. */
typedef enum {
    CT_NONE,		/* no circuit type */
    CT_DLCI,		/* Frame Relay DLCI */
    CT_ISDN,		/* ISDN channel number */
    CT_X25,		/* X.25 logical channel number */
    CT_ISUP,		/* ISDN User Part CIC */
    CT_IAX2,		/* IAX2 call id */
    CT_H223,		/* H.223 logical channel number */
    CT_BICC,		/* BICC Circuit identifier */
    CT_DVBCI		/* DVB-CI session number|transport connection id */
    /* Could also have ATM VPI/VCI pairs */
} circuit_type;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ADDRESS_H__ */

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
