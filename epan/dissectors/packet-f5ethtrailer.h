/* packet-f5ethtrailer.h
 *
 * F5 Ethernet Trailer Copyright 2008-2018 F5 Networks
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* How to use the fileinfo version tap
 *
 * Captures taken on an F5 device in versions 11.2.0 and later contain an
 * initial packet that has information about how the capture was taken and
 * about the device it was taken on (tcpdump command line, platform, version,
 * etc.).  This tap allows other dissectors to obtain the version of BIG-IP
 * software (if it is available).
 *
 * There are two functions defined in this header file (f5fileinfo_tap_reset()
 * and f5fileinfo_tap_pkt()).  These functions are registered with the tap and
 * will populate a structure provided by you with the version information.
 *
 * Step 1: Define a static variable of type "struct f5fileinfo".  This is where
 * the version information will be stored.
 *   static struct f5fileinfo myver = F5FILEINFO_TAP_DATA_INIT;
 *
 * Step 2: Register with the tap listener using the macro provided in your
 * proto_reg_handoff function:
 *   F5FILEINFO_TAP_LISTEN(&myver);
 *
 * Step 3: Use the version information in other parts of your code.
 *   if(myver.ver[0] == 11) {
 *      ...
 *   }
 *
 * If you need to do something additional when you run into a version, you can
 * define the F5FILEINFO_TAP_POST_FUNC macro before including this header file
 * to be the name of a fuction to call at the end of the tap function.  This
 * function must have a prototype of
 *   static void F5FILEINFO_TAP_POST_FUNC(struct f5fileinfo_tap_data *);
 * Note that this function also gets called with version of all zeroes when the
 * tap gets reset (reload file).
 * Note that this function does not get called if the version number does not
 * change.
 * Example:
 *   #define F5FILEINFO_TAP_POST_FUNC f5info_tap_local
 *   #include <epan/dissectors/packet-f5ethtrailer.h>
 *   ...
 *   static void f5info_tap_local(struct f5fileinfo_tap_data *tap_data)
 *   {
 *       ...
 *   }
 */

#ifndef _PACKETH_F5ETHTRAILER_H_
#define _PACKETH_F5ETHTRAILER_H_

#include <glib.h>

#define F5ETH_TAP_TMM_MAX   G_MAXUINT16
#define F5ETH_TAP_TMM_BITS  16
#define F5ETH_TAP_SLOT_MAX  G_MAXUINT16
#define F5ETH_TAP_SLOT_BITS 16

/** Magic number for Ethernet trailer tap data to ensure that any tap and the dissector were both
 *  compiled from the same source.  No need to htonl this since the dissector and the tap should
 *  both be compiled on the same platform.
 *
 *  Increment this value when the struct f5eth_tap_data (below) is changed.
 */
#define F5ETH_TAP_MAGIC     0x68744521

/** Data structure to hold data returned by the f5ethtrailer tap.  Magic has to be first. */
typedef struct f5eth_tap_data {
    guint32 magic;        /**< Verify proper version of dissector */
    guint32 trailer_len;  /**< Overall length of the F5 trailer */
    /* 64 bit align */
    guint64 flow;         /**< Flow ID */
    guint64 peer_flow;    /**< Peer Flow ID */
    /* 64 bit align */
    gchar  *virtual_name; /**< Virtual server name */
    guint16 slot;         /**< The slot the handled the packet (F5ETH_TAP_TMM_MAX == unknown) */
    guint16 tmm;          /**< The tmm that handled the packet (F5ETH_TAP_sLOT_MAX == unknown) */
    guint8  noise_low:1;  /**< If the frame has low noise(1) or not(0) */
    guint8  noise_med:1;  /**< If the frame has medium noise(1) or not(0) */
    guint8  noise_high:1; /**< If the frame has high noise(1) or not(0) */
    guint8  flows_set:1;  /**< If the frame has flow/peerflow fields(1) or not(0) */
    guint8  ingress:2;    /**< Whether the packet was ingress(1), egress(0) or unknown(3) */
} f5eth_tap_data_t;

/** \brief Tap data version matches compiled version
 *
 *  @param tdata Pointer to tapdata from f5ethtrailer
 *  @return 1 if the version of the tapdata matches the compiled version of the tap. 0 otherwise.
 *
 *  Use this function to ensure that the data from the f5ethtrailer tap is the same as the
 *  structure used when your tap was compiled.  Use this to protect your tap from running against
 *  a newer/older version of the f5ethtrailer dissector.
 *
 *  For example, at the top of your tap packet function, you can use:
 *    if(check_f5eth_tap_magic(tdata) == 0) return 0;
 */
inline static int check_f5eth_tap_magic(f5eth_tap_data_t *tdata)
{
    return(tdata->magic == F5ETH_TAP_MAGIC ? 1 : 0);
} /* check_f5eth_tap_magic() */

#define F5FILEINFO_TAP_MAGIC 0x46350001

/** Data structure to hold data returned by the f5fileinfo tap. */
struct f5fileinfo_tap_data {
    guint32 magic;  /**< Just to make sure that we have the same version. */
    guint32 ver[6]; /**< Array for version and build elements. */
};

#define F5FILEINFO_TAP_DATA_INIT { 0, { 0, 0, 0, 0, 0, 0 } }

#define F5VER_KNOWN(v) ((v)->ver[0] > 0)


#define F5VER_GE_11_2(v) (((v)->ver[0] > 11) \
    || ((v)->ver[0] == 11 && (v)->ver[1] >= 2))

#define F5VER_GE_11_2_1(v) (((v)->ver[0] > 11) \
    || ((v)->ver[0] == 11 && (v)->ver[1] > 2) \
    || ((v)->ver[0] == 11 && (v)->ver[1] == 2 && (v)->ver[2] >= 1))

#define F5VER_GE_11_3(v) (((v)->ver[0] > 11) \
    || ((v)->ver[0] == 11 && (v)->ver[1] >= 3))

#define F5VER_GE_11_4(v) (((v)->ver[0] > 11) \
    || ((v)->ver[0] == 11 && (v)->ver[1] >= 4))

#define F5VER_GE_11_4_1(v) (((v)->ver[0] > 11) \
    || ((v)->ver[0] == 11 && (v)->ver[1] > 4) \
    || ((v)->ver[0] == 11 && (v)->ver[1] == 4 && (v)->ver[2] >= 1))

#define F5VER_GE_11_5(v) (((v)->ver[0] > 11) \
    || ((v)->ver[0] == 11 && (v)->ver[1] >= 5))

#define F5VER_GE_11_5_1(v) (((v)->ver[0] > 11) \
    || ((v)->ver[0] == 11 && (v)->ver[1] > 5) \
    || ((v)->ver[0] == 11 && (v)->ver[1] == 5 && (v)->ver[2] >= 1))

#define F5VER_GE_11_6(v) (((v)->ver[0] > 11) \
    || ((v)->ver[0] == 11 && (v)->ver[1] >= 6))

#define F5VER_GE_12_0(v) (((v)->ver[0] >= 12))


#ifndef F5FILEINFOTAP_SRC

#ifdef F5FILEINFO_TAP_POST_FUNC
static void F5FILEINFO_TAP_POST_FUNC(struct f5fileinfo_tap_data *);
#endif

static void f5fileinfo_tap_reset(void *p)
{
    struct f5fileinfo_tap_data *s;

    s = (struct f5fileinfo_tap_data *)p;
    s->ver[0] = 0;
    s->ver[1] = 0;
    s->ver[2] = 0;
    s->ver[3] = 0;
    s->ver[4] = 0;
    s->ver[5] = 0;
#   ifdef F5FILEINFO_TAP_POST_FUNC
        F5FILEINFO_TAP_POST_FUNC(s);
#   endif
} /* f5fileinfo_tap_reset() */

static tap_packet_status f5fileinfo_tap_pkt(
    void *tapdata,
    packet_info *pinfo _U_,
    epan_dissect_t *edt _U_,
    const void *data,
    tap_flags_t flags _U_
) {
    struct f5fileinfo_tap_data *s;
    struct f5fileinfo_tap_data *fromtap;

    s = (struct f5fileinfo_tap_data *)tapdata;
    fromtap = (struct f5fileinfo_tap_data *)data;
    if(fromtap->magic != F5FILEINFO_TAP_MAGIC) {
        /* Magic numbers do not match.  f5ethtrailer plugin was compiled from
         * different source than this plugin. */
        return(TAP_PACKET_DONT_REDRAW);
    }
    if (s->ver[0] == fromtap->ver[0] &&
        s->ver[1] == fromtap->ver[1] &&
        s->ver[2] == fromtap->ver[2] &&
        s->ver[3] == fromtap->ver[3] &&
        s->ver[4] == fromtap->ver[4] &&
        s->ver[5] == fromtap->ver[5])
    {
        return(TAP_PACKET_DONT_REDRAW);
    }
    s->ver[0] = fromtap->ver[0];
    s->ver[1] = fromtap->ver[1];
    s->ver[2] = fromtap->ver[2];
    s->ver[3] = fromtap->ver[3];
    s->ver[4] = fromtap->ver[4];
    s->ver[5] = fromtap->ver[5];
#   ifdef F5FILEINFO_TAP_POST_FUNC
        F5FILEINFO_TAP_POST_FUNC(s);
#   endif
    return(TAP_PACKET_REDRAW);
} /* f5fileinfo_tap_pkt() */


#define F5FILEINFO_TAP_LISTEN(a) \
    register_tap_listener("f5fileinfo", (a), NULL, TL_REQUIRES_NOTHING, f5fileinfo_tap_reset, f5fileinfo_tap_pkt, NULL, NULL)


#endif /* ifndef F5INFOTAP_SRC */


#endif /* ifndef _PACKETH_F5ETHTRAILER_H_ */

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