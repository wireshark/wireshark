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

#include "tvbuff.h"
#include "wmem/wmem.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Types of "global" addresses Wireshark knows about. */
/* Address types can be added here if there are many dissectors that use them or just
 * within a specific dissector.
 * If an address type is added here, it must be "registered" within address_types.c
 * For dissector address types, just use the address_type_dissector_register function
 * from address_types.h
 */
typedef enum {
    AT_NONE,               /* no link-layer address */
    AT_ETHER,              /* MAC (Ethernet, 802.x, FDDI) address */
    AT_IPv4,               /* IPv4 */
    AT_IPv6,               /* IPv6 */
    AT_IPX,                /* IPX */
    AT_FC,                 /* Fibre Channel */
    AT_FCWWN,              /* Fibre Channel WWN */
    AT_STRINGZ,            /* null-terminated string */
    AT_EUI64,              /* IEEE EUI-64 */
    AT_IB,                 /* Infiniband GID/LID */
    AT_AX25,               /* AX.25 */

    AT_END_OF_LIST         /* Must be last in list */
} address_type;

typedef struct _address {
    int           type;         /* type of address */
    int           len;          /* length of address, in bytes */
    const void   *data;         /* pointer to address data */

    /* private */
    void         *priv;
} address;

#define ADDRESS_INIT(type, len, data) {type, len, data, NULL}
#define ADDRESS_INIT_NONE ADDRESS_INIT(AT_NONE, 0, NULL)

static inline void
clear_address(address *addr)
{
    addr->type = AT_NONE;
    addr->len  = 0;
    addr->data = NULL;
    addr->priv = NULL;
}

/** Initialize an address with the given values.
 *
 * @param addr [in,out] The address to initialize.
 * @param addr_type [in] Address type.
 * @param addr_len [in] The length in bytes of the address data. For example, 4 for
 *                     AT_IPv4 or sizeof(struct e_in6_addr) for AT_IPv6.
 * @param addr_data [in] Pointer to the address data.
 */
static inline void
set_address(address *addr, int addr_type, int addr_len, const void *addr_data) {
    if (addr_len == 0) {
        /* Zero length must mean no data */
        g_assert(addr_data == NULL);
    } else {
        /* Must not be AT_NONE - AT_NONE must have no data */
        g_assert(addr_type != AT_NONE);
        /* Make sure we *do* have data */
        g_assert(addr_data != NULL);
    }
    addr->type = addr_type;
    addr->len  = addr_len;
    addr->data = addr_data;
    addr->priv = NULL;
}

/** Initialize an address from TVB data.
 *
 * Same as set_address but it takes a TVB and an offset. This is preferred
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
static inline void
set_address_tvb(address *addr, int addr_type, int addr_len, tvbuff_t *tvb, int offset) {
    const void *p;

    if (addr_len != 0) {
        /* Must not be AT_NONE - AT_NONE must have no data */
        g_assert(addr_type != AT_NONE);
        p = tvb_get_ptr(tvb, offset, addr_len);
    } else
        p = NULL;
    set_address(addr, addr_type, addr_len, p);
}

/** Initialize an address with the given values, allocating a new buffer
 * for the address data using wmem-scoped memory.
 *
 * @param scope [in] The lifetime of the allocated memory, e.g., wmem_packet_scope()
 * @param addr [in,out] The address to initialize.
 * @param addr_type [in] Address type.
 * @param addr_len [in] The length in bytes of the address data. For example, 4 for
 *                     AT_IPv4 or sizeof(struct e_in6_addr) for AT_IPv6.
 * @param addr_data [in] Pointer to the address data.
 */
static inline void
alloc_address_wmem(wmem_allocator_t *scope, address *addr,
                        int addr_type, int addr_len, const void *addr_data) {
    g_assert(addr);
    clear_address(addr);
    addr->type = addr_type;
    if (addr_len == 0) {
        /* Zero length must mean no data */
        g_assert(addr_data == NULL);
        /* Nothing to copy */
        return;
    }
    /* Must not be AT_NONE - AT_NONE must have no data */
    g_assert(addr_type != AT_NONE);
    /* Make sure we *do* have data to copy */
    g_assert(addr_data != NULL);
    addr->data = addr->priv = wmem_memdup(scope, addr_data, addr_len);
    addr->len = addr_len;
}

/** Allocate an address from TVB data.
 *
 * Same as alloc_address_wmem but it takes a TVB and an offset.
 *
 * @param scope [in] The lifetime of the allocated memory, e.g., wmem_packet_scope()
 * @param addr [in,out] The address to initialize.
 * @param addr_type [in] Address type.
 * @param addr_len [in] The length in bytes of the address data. For example, 4 for
 *                     AT_IPv4 or sizeof(struct e_in6_addr) for AT_IPv6.
 * @param tvb [in] Pointer to the TVB.
 * @param offset [in] Offset within the TVB.
 */
static inline void
alloc_address_tvb(wmem_allocator_t *scope, address *addr,
                    int addr_type, int addr_len,  tvbuff_t *tvb, int offset) {
    const void *p;

    p = tvb_get_ptr(tvb, offset, addr_len);
    alloc_address_wmem(scope, addr, addr_type, addr_len, p);
}

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
    if (addr1->len == 0) {
        /*
         * memcmp(NULL, NULL, 0) is *not* guaranteed to work, so
         * if both addresses are zero-length, don't compare them
         * (there's nothing to compare, so they're equal).
         */
        return 0;
    }
    return memcmp(addr1->data, addr2->data, addr1->len);
}

/** Check two addresses for equality.
 *
 * Given two addresses, return "true" if they're equal, "false" otherwise.
 * Addresses are equal only if they have the same type and length; if the
 * length is zero, they are then equal, otherwise the data must be the
 * same.
 *
 * @param addr1 [in] The first address to compare.
 * @param addr2 [in] The second address to compare.
 * @return TRUE if the adresses are equal, FALSE otherwise.
 */
static inline gboolean
addresses_equal(const address *addr1, const address *addr2) {
    /*
     * memcmp(NULL, NULL, 0) is *not* guaranteed to work, so
     * if both addresses are zero-length, don't compare them
     * (there's nothing to compare, so they're equal).
     */
    if (addr1->type == addr2->type &&
        addr1->len == addr2->len &&
        (addr1->len == 0 ||
         memcmp(addr1->data, addr2->data, addr1->len) == 0))
        return TRUE;
    return FALSE;
}

/** Check the data of two addresses for equality.
 *
 * Given two addresses, return "true" if they have the same length and,
 * their data is equal, "false" otherwise.
 * The address types are ignored. This can be used to compare custom
 * address types defined with address_type_dissector_register.
 *
 * @param addr1 [in] The first address to compare.
 * @param addr2 [in] The second address to compare.
 * @return TRUE if the adresses are equal, FALSE otherwise.
 */
static inline gboolean
addresses_data_equal(const address *addr1, const address *addr2) {
    if ( addr1->len == addr2->len
            && memcmp(addr1->data, addr2->data, addr1->len) == 0
            ) return TRUE;
    return FALSE;
}

/** Perform a shallow copy of the address (both addresses point to the same
 * memory location).
 *
 * @param to [in,out] The destination address.
 * @param from [in] The source address.
 *
 * \warning Make sure 'from' memory stays valid for the lifetime of this object.
 * Also it's strongly recommended to use this function instead of copy-assign.
 */
static inline void
copy_address_shallow(address *to, const address *from) {
    set_address(to, from->type, from->len, from->data);
}

/** Copy an address, allocating a new buffer for the address data
 *  using wmem-scoped memory.
 *
 * @param scope [in] The lifetime of the allocated memory, e.g., wmem_packet_scope()
 * @param to [in,out] The destination address.
 * @param from [in] The source address.
 */
static inline void
copy_address_wmem(wmem_allocator_t *scope, address *to, const address *from) {
    alloc_address_wmem(scope, to, from->type, from->len, from->data);
}

/** Copy an address, allocating a new buffer for the address data.
 *
 * @param to [in,out] The destination address.
 * @param from [in] The source address.
 */
static inline void
copy_address(address *to, const address *from) {
    copy_address_wmem(NULL, to, from);
}

/** Free an address allocated with wmem-scoped memory.
 *
 * @param scope [in] The lifetime of the allocated memory, e.g., wmem_packet_scope()
 * @param addr [in,out] The address whose data to free.
 */
static inline void
free_address_wmem(wmem_allocator_t *scope, address *addr) {
    /* Because many dissectors set 'type = AT_NONE' to mean clear we check for that */
    if (addr->type != AT_NONE && addr->len > 0 && addr->priv != NULL) {
        /* Make sure API use is correct */
        /* if priv is not null then data == priv */
        g_assert(addr->data == addr->priv);
        wmem_free(scope, addr->priv);
    }
    clear_address(addr);
}

/** Free an address.
 *
 * @param addr [in,out] The address whose data to free.
 */
static inline void
free_address(address *addr) {
    free_address_wmem(NULL, addr);
}

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

WS_DLL_PUBLIC guint address_to_bytes(const address *addr, guint8 *buf, guint buf_len);

/* Types of port numbers Wireshark knows about. */
typedef enum {
    PT_NONE,            /* no port number */
    PT_SCTP,            /* SCTP */
    PT_TCP,             /* TCP */
    PT_UDP,             /* UDP */
    PT_DCCP,            /* DCCP */
    PT_IPX,             /* IPX sockets */
    PT_NCP,             /* NCP connection */
    PT_EXCHG,           /* Fibre Channel exchange */
    PT_DDP,             /* DDP AppleTalk connection */
    PT_SBCCS,           /* FICON */
    PT_IDP,             /* XNS IDP sockets */
    PT_TIPC,            /* TIPC PORT */
    PT_USB,             /* USB endpoint 0xffff means the host */
    PT_I2C,
    PT_IBQP,            /* Infiniband QP number */
    PT_BLUETOOTH,
    PT_TDMOP
} port_type;

/* Types of circuit IDs Wireshark knows about. */
typedef enum {
    CT_NONE,            /* no circuit type */
    CT_DLCI,            /* Frame Relay DLCI */
    CT_ISDN,            /* ISDN channel number */
    CT_X25,             /* X.25 logical channel number */
    CT_ISUP,            /* ISDN User Part CIC */
    CT_IAX2,            /* IAX2 call id */
    CT_H223,            /* H.223 logical channel number */
    CT_BICC,            /* BICC Circuit identifier */
    CT_DVBCI,           /* DVB-CI session number|transport connection id */
    CT_ISO14443         /* ISO14443 connection between terminal and card
                           the circuit ID is always 0, there's only one
                           such connection */
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
