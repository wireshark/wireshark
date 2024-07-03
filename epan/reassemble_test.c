/* reassemble_test.c
 * Standalone program to test functionality of reassemble.h API
 *
 * These aren't particularly complete - they just test a few corners of
 * functionality which I was interested in. In particular, they only test the
 * fragment_add_seq_* (ie, FD_BLOCKSEQUENCE) family of routines. However,
 * hopefully they will inspire people to write additional tests, and provide a
 * useful basis on which to do so.
 *
 * reassemble_test can be run under valgrind to detect any memory leaks in the
 * Wireshark reassembly code.
 *    Specifically: code has been added to free dynamically allocated memory
 *     after each test (or at program completion) so that valgrind will report
 *     only actual memory leaks.
 *    The following command can be used to run reassemble_test under valgrind:
 *      env                               \
 *        G_DEBUG=gc-friendly             \
 *        G_SLICE=always-malloc           \
 *      valgrind --leak-check=full --show-reachable=yes ./reassemble_test
 *
 * Copyright (c) 2007 MX Telecom Ltd. <richardv@mxtelecom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "config.h"

#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <epan/reassemble.h>

#include "exceptions.h"

static int failure;
static const bool debug; /* Set to true to dump tables. */

#define ASSERT(b)           \
    if (!(b)) {             \
        failure = 1;        \
        printf("Assertion failed at line %i: %s\n", __LINE__, #b);  \
        exit(1);            \
    }

#define ASSERT_EQ(exp,act)  \
    if ((exp)!=(act)) {     \
        failure = 1;        \
        printf("Assertion failed at line %i: %s==%s (%u==%u)\n", __LINE__, #exp, #act, (unsigned)exp, (unsigned)act);  \
        exit(1);            \
    }

#define ASSERT_EQ_POINTER(exp,act)  \
    if ((exp)!=(act)) {     \
        failure = 1;        \
        printf("Assertion failed at line %i: %s==%s (%p==%p)\n", __LINE__, #exp, #act, (const void *)exp, (const void *)act);  \
        exit(1);            \
    }

#define ASSERT_NE_POINTER(exp,act)  \
    if ((exp)==(act)) {     \
        failure = 1;        \
        printf("Assertion failed at line %i: %s!=%s (%p!=%p)\n", __LINE__, #exp, #act, (const void *)exp, (const void *)act);  \
        exit(1);            \
    }

#define DATA_LEN 256

static uint8_t *data;
static tvbuff_t *tvb;
static packet_info pinfo;

/* fragment_table maps from datagram ids to fragment_head
   reassembled_table maps from <packet number,datagram id> to
   fragment_head */
static reassembly_table test_reassembly_table;

/*************************************************
 * Util fcns to display
 *   fragment_table & reassembled_table fd-chains
 ************************************************/

static struct _fd_flags {
    uint32_t flag;
    char   *flag_name;
} fd_flags[] = {
    {FD_DEFRAGMENTED         ,"DF"},
    {FD_DATALEN_SET          ,"DS"},
    {FD_SUBSET_TVB           ,"ST"},
    {FD_BLOCKSEQUENCE        ,"BS"},
    {FD_PARTIAL_REASSEMBLY   ,"PR"},
    {FD_OVERLAP              ,"OL"},
    {FD_OVERLAPCONFLICT      ,"OC"},
    {FD_MULTIPLETAILS        ,"MT"},
    {FD_TOOLONGFRAGMENT      ,"TL"},
};
#define N_FD_FLAGS array_length(fd_flags)

static void
print_fd_head(fragment_head *fd) {
    unsigned int i;

    g_assert_true(fd != NULL);
    printf("        %16p %16p %3u %3u", (void *)fd, (void *)(fd->next), fd->frame, fd->len);

    printf(" %3u %3u", fd->datalen, fd->reassembled_in);

    if (fd->tvb_data != NULL) {
        printf(" %16p", tvb_get_ptr(fd->tvb_data, 0, 1)); /* Address of first byte only... */
    } else {
        printf(" %16s", "<null tvb_data>");
    }
    for (i = 0; i < N_FD_FLAGS; i++) {
        printf(" %s", (fd->flags & fd_flags[i].flag) ? fd_flags[i].flag_name : "  ");
    }
    printf("\n");
}

static void
print_fd_item(fragment_item *fd) {
    unsigned int i;

    g_assert_true(fd != NULL);
    printf("        %16p %16p %3u %3u %3u", (void *)fd, (void *)(fd->next), fd->frame, fd->offset, fd->len);
    printf( "        ");
    if (fd->tvb_data != NULL) {
        printf(" %16p", tvb_get_ptr(fd->tvb_data, 0, 1)); /* Address of first byte only... */
    } else {
        printf(" %16s", "<null tvb_data>");
    }
    for (i = 0; i < N_FD_FLAGS; i++) {
        printf(" %s", (fd->flags & fd_flags[i].flag) ? fd_flags[i].flag_name : "  ");
    }
    printf("\n");
}

static void
print_fd_chain(fragment_head *fd_head) {
    fragment_item *fdp;

    g_assert_true(fd_head != NULL);
    print_fd_head(fd_head);
    for (fdp=fd_head->next; fdp != NULL; fdp=fdp->next) {
        print_fd_item(fdp);
    }
}

static void
print_fragment_table_chain(void *k _U_, void *v, void *ud _U_) {
#ifdef DUMP_KEYS
    fragment_key  *key     = (fragment_key*)k;
#endif
    fragment_head *fd_head = (fragment_head *)v;
#ifdef DUMP_KEYS
    printf("  --> FT: %3d 0x%08x 0x%08x\n", key->id, *(uint32_t *)(key->src.data), *(uint32_t *)(key->dst.data));
#endif
    print_fd_chain(fd_head);
}

static void
print_fragment_table(void) {
    printf("\n Fragment Table -------\n");
    g_hash_table_foreach(test_reassembly_table.fragment_table, print_fragment_table_chain, NULL);
}

static void
print_reassembled_table_chain(void *k _U_, void *v, void *ud _U_) {
#ifdef DUMP_KEYS
    reassembled_key  *key  = (reassembled_key*)k;
#endif
    fragment_head *fd_head = (fragment_head *)v;
#ifdef DUMP_KEYS
    printf("  --> RT: %5d %5d\n", key->id, key->frame);
#endif
    print_fd_chain(fd_head);
}

static void
print_reassembled_table(void) {
    printf("\n Reassembled Table ----\n");
    g_hash_table_foreach(test_reassembly_table.reassembled_table, print_reassembled_table_chain, NULL);
}

static void
print_tables(void) {
    print_fragment_table();
    print_reassembled_table();
}

/**********************************************************************************
 *
 * fragment_add_seq
 *
 *********************************************************************************/

/* Simple test case for fragment_add_seq.
 * Adds three fragments (out of order, with one for a different datagram in between),
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       1    12     1     0    60   T       5
       0    13     2     0    60   T      15
       0    12     3     2    60   F       5
       0    12     4     1    60   T      15
*/
static void
test_simple_fragment_add_seq(void)
{
    fragment_head *fd_head, *fdh0;

    printf("Starting test test_simple_fragment_add_seq\n");

    pinfo.num = 1;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, true, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* adding the same fragment again should do nothing, even with different
     * offset etc */
    pinfo.fd->visited = 1;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             0, 60, true, 0);
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.fd->visited = 0;
    pinfo.num = 2;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 15, &pinfo, 13, NULL,
                             0, 60, true, 0);
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* now we add the terminal fragment of the first datagram */
    pinfo.num = 3;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             2, 60, false, 0);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the missing fragment */
    pinfo.num = 4;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 15, &pinfo, 12, NULL,
                             1, 60, true, 0);

    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame number of fragment in assembly */
    ASSERT_EQ(170,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next);

    ASSERT_EQ(4,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+15,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,60));

    if (debug) {
        print_fragment_table();
    }

    /* what happens if we revisit the packets now? */
    fdh0 = fd_head;
    pinfo.fd->visited = 1;
    pinfo.num = 1;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, true, 0);
    /*
     * this api relies on the caller to check fd_head -> reassembled_in
     *
     * Redoing all the tests seems like overkill - just check the pointer
     */
    ASSERT_EQ_POINTER(fdh0,fd_head);

    pinfo.num = 3;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             2, 60, false, 0);
    ASSERT_EQ_POINTER(fdh0,fd_head);

    pinfo.num = 4;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 15, &pinfo, 12, NULL,
                             1, 60, true, 0);
    ASSERT_EQ_POINTER(fdh0,fd_head);

    if (debug) {
        print_fragment_table();
    }
}

/* XXX ought to have some tests for overlapping fragments */

/* This tests the functionality of fragment_set_partial_reassembly for
 * FD_BLOCKSEQUENCE reassembly.
 *
 * We add a sequence of fragments thus:
 *    seqno   frame  offset   len   (initial) more_frags
 *    -----   -----  ------   ---   --------------------
 *      0       1       10       50   false
 *      1       2        0       40   true
 *      1       3        0       40   true (a duplicate fragment)
 *      2       4       20      100   false
 *      3       5        0       40   false
 */
static void
test_fragment_add_seq_partial_reassembly(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_seq_partial_reassembly\n");

    /* generally it's probably fair to assume that we will be called with
     * more_frags=false.
     */
    pinfo.num = 1;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, false, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(1,fd_head->frame);  /* max frame in reassembly */
    ASSERT_EQ(50,fd_head->len); /* the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(1,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));

    /* now we announce that the reassembly wasn't complete after all. */
    fragment_set_partial_reassembly(&test_reassembly_table, &pinfo, 12, NULL);

    /* and add another segment. To mix things up slightly (and so that we can
     * check on the state of things), we're going to set the more_frags flag
     * here
     */
    pinfo.num = 2;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 0, &pinfo, 12, NULL,
                             1, 40, true, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(2,fd_head->frame);   /* max frame in reassembly */
    /* ASSERT_EQ(50,fd_head->len);     the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* seqno */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(FD_SUBSET_TVB,fd->flags);
    ASSERT_EQ_POINTER(tvb_get_ptr(fd_head->tvb_data,0,0),tvb_get_ptr(fd->tvb_data,0,0));
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* Another copy of the second segment.
     */
    pinfo.num = 3;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 0, &pinfo, 12, NULL,
                             1, 40, true, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);
    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);
    ASSERT_EQ(3,fd_head->frame);   /* max frame we have */
    /* ASSERT_EQ(50,fd_head->len);     the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* seqno */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(FD_SUBSET_TVB,fd->flags);
    ASSERT_EQ_POINTER(tvb_get_ptr(fd_head->tvb_data,0,0),tvb_get_ptr(fd->tvb_data,0,0));
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);



    /* have another go at wrapping things up */
    pinfo.num = 4;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 20, &pinfo, 12, NULL,
                             2, 100, false, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(190,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* seqno */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(2,fd->offset);  /* seqno */
    ASSERT_EQ(100,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data,40));
    ASSERT(!tvb_memeql(fd_head->tvb_data,90,data+20,100));


    /* do it again (this time it is more complicated, with an overlap in the
     * reassembly) */

    fragment_set_partial_reassembly(&test_reassembly_table, &pinfo, 12, NULL);

    pinfo.num = 5;
    fragment_add_seq(&test_reassembly_table, tvb, 0, &pinfo, 12, NULL,
                             3, 40, false, 0);

    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);
    ASSERT_EQ(5,fd_head->frame);   /* max frame we have */
    ASSERT_EQ(230,fd_head->len);   /* the length of data we have */
    ASSERT_EQ(3,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(5,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* seqno */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(1,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(2,fd->offset);  /* seqno */
    ASSERT_EQ(100,fd->len);   /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(5,fd->frame);
    ASSERT_EQ(3,fd->offset);  /* seqno */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data,40));
    ASSERT(!tvb_memeql(fd_head->tvb_data,90,data+20,100));
    ASSERT(!tvb_memeql(fd_head->tvb_data,190,data,40));
}

/* Test case for fragment_add_seq with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 1st one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     2    40   F      5
       0    12     4     0    50   T      10
*/
static void
test_fragment_add_seq_duplicate_first(void)
{
    fragment_head *fd_head;

    printf("Starting test test_fragment_add_seq_duplicate_first\n");

    pinfo.num = 1;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, true, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             1, 60, true, 0);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the last fragment */
    pinfo.num = 3;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             2, 40, false, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* Add the first fragment again */
    pinfo.num = 4;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, true, 0);

    /* Reassembly should have still succeeded */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(150,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(3,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next);

    ASSERT_EQ(4,fd_head->next->next->frame);
    ASSERT_EQ(0,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd_head->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next);

    ASSERT_EQ(2,fd_head->next->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}


/* Test case for fragment_add_seq with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 2nd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     1    60   T      5
       0    12     4     3    40   F      5
*/
static void
test_fragment_add_seq_duplicate_middle(void)
{
    fragment_head *fd_head;

    printf("Starting test test_fragment_add_seq_duplicate_middle\n");

    pinfo.num = 1;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, true, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             1, 60, true, 0);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Now, add the 2nd segment again (but in a different frame) */
    pinfo.num = 3;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             1, 60, true, 0);

    /* This duplicate fragment should have been ignored */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the last fragment */
    pinfo.num = 4;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             2, 40, false, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(150,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next);

    ASSERT_EQ(2,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd_head->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next->next);

    ASSERT_EQ(4,fd_head->next->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}

/* Test case for fragment_add_seq with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 3rd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     2    40   F      5
       0    12     4     2    40   F      5
*/
static void
test_fragment_add_seq_duplicate_last(void)
{
    fragment_head *fd_head;

    printf("Starting test test_fragment_add_seq_duplicate_last\n");

    pinfo.num = 1;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, true, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             1, 60, true, 0);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the last fragment */
    pinfo.num = 3;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             2, 40, false, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* Add the last fragment again */
    pinfo.num = 4;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             2, 40, false, 0);

    /* Reassembly should have still succeeded */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(150,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(3,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next);

    ASSERT_EQ(2,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next->next);

    ASSERT_EQ(4,fd_head->next->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->next->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd_head->next->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}

/* Test case for fragment_add_seq with duplicated (e.g., retransmitted) data
 * where the retransmission "conflicts" with the original transmission
 * (contents are different).
 * Adds three fragments--adding the 2nd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     1    60   T      15
       0    12     4     2    40   F      5
*/
static void
test_fragment_add_seq_duplicate_conflict(void)
{
    fragment_head *fd_head;

    printf("Starting test test_fragment_add_seq_duplicate_conflict\n");

    pinfo.num = 1;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, true, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             1, 60, true, 0);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Now, add the 2nd segment again (but in a different frame and with
     * different data)
     */
    pinfo.num = 3;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 15, &pinfo, 12, NULL,
                             1, 60, true, 0);

    /* This duplicate fragment should have been ignored */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the last fragment */
    pinfo.num = 4;
    fd_head=fragment_add_seq(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                             2, 40, false, 0);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(150,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET|FD_OVERLAP|FD_OVERLAPCONFLICT,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next);

    ASSERT_EQ(2,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP|FD_OVERLAPCONFLICT,fd_head->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next->next);

    ASSERT_EQ(4,fd_head->next->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->next->offset);  /* seqno */
    ASSERT_EQ(40,fd_head->next->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}

/**********************************************************************************
 *
 * fragment_add_seq_check
 *
 *********************************************************************************/


/* This routine is used for both fragment_add_seq_802_11 and
 * fragment_add_seq_check.
 *
 * Adds a couple of out-of-order fragments and checks their reassembly.
 */

/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    13     2     0    60   T      15
       0    12     3     2    60   F       5
       0    12     4     1    60   F      15
*/


static void
test_fragment_add_seq_check_work(fragment_head *(*fn)(reassembly_table *,
                                 tvbuff_t *, const int, const packet_info *,
                                 const uint32_t, const void *, const uint32_t,
                                 const uint32_t, const bool))
{
    fragment_head *fd_head;

    pinfo.num = 1;
    fd_head=fn(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
               0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.num = 2;
    fd_head=fn(&test_reassembly_table, tvb, 15, &pinfo, 13, NULL,
               0, 60, true);
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* add the terminal fragment of the first datagram */
    pinfo.num = 3;
    fd_head=fn(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
               2, 60, false);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the missing fragment */
    pinfo.num = 4;
    fd_head=fn(&test_reassembly_table, tvb, 15, &pinfo, 12, NULL,
               1, 60, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(3,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(170,fd_head->len); /* the length of data we have */
    ASSERT_EQ(2,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next);

    ASSERT_EQ(4,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next->next);

    ASSERT_EQ(3,fd_head->next->next->next->frame);
    ASSERT_EQ(2,fd_head->next->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+15,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,60));

    if (debug) {
        print_tables();
    }
}

/* Simple test case for fragment_add_seq_check
 */
static void
test_fragment_add_seq_check(void)
{
    printf("Starting test test_fragment_add_seq_check\n");

    test_fragment_add_seq_check_work(fragment_add_seq_check);
}


/* This tests the case that the 802.11 hack does something different for: when
 * the terminal segment in a fragmented datagram arrives first.
 */
static void
test_fragment_add_seq_check_1(void)
{
    fragment_head *fd_head;

    printf("Starting test test_fragment_add_seq_check_1\n");

    pinfo.num = 1;
    fd_head=fragment_add_seq_check(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                                   1, 50, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Now add the missing segment */
    pinfo.num = 2;
    fd_head=fragment_add_seq_check(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                                   0, 60, true);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(2,fd_head->frame);  /* max frame of fragment in structure */
    ASSERT_EQ(110,fd_head->len); /* the length of data we have */
    ASSERT_EQ(1,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(2,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(2,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next);

    ASSERT_EQ(1,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,60,data+10,50));
}

/**********************************************************************************
 *
 * fragment_add_seq_802_11
 *
 *********************************************************************************/

/* Tests the 802.11 hack.
 */
static void
test_fragment_add_seq_802_11_0(void)
{
    fragment_head *fd_head;

    printf("Starting test test_fragment_add_seq_802_11_0\n");

    /* the 802.11 hack is that some non-fragmented datagrams have non-zero
     * fragment_number; test for this. */

    pinfo.num = 1;
    fd_head=fragment_add_seq_802_11(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                                    10, 50, false);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->len);    /* unused */
    ASSERT_EQ(0,fd_head->datalen); /* unused */
    ASSERT_EQ(1,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE,fd_head->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next);
}

/* Reuse the fragment_add_seq_check testcases */
static void test_fragment_add_seq_802_11_1(void)
{
    printf("Starting test test_fragment_add_seq_802_11_1\n");
    test_fragment_add_seq_check_work(fragment_add_seq_802_11);
}

/**********************************************************************************
 *
 * fragment_add_seq_check_multiple
 *
 *********************************************************************************/

/* Test 2 partial frags from 2 diff datagrams in the same frame */
/*
   datagram #1: frame 1 + first part of frame 2
   datagram #1: last part of frame 2 + frame 3

   Is this a valid scenario ?

   The result of calling fragment_add_seq_check(&test_reassembly_table, ) for these
   fragments is a reassembled_table with:
    id, frame 1 => first_datagram;  ["reassembled in" frame 2]
    id, frame 2 => second_datagram; ["reassembled in" frame 3]
    id, frame 3 => second_datagram;

    Note that the id, frame 2 => first datagram was overwritten
     by the entry for the second datagram.
   Is this OK ? IE: When dissected/displayed
      will the reassembled datagram 1 appear with frame 2 ??
*/

/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    20   F       5
       0    12     2     0    25   T      25
       0    12     3     1    60   F       0
*/

/*
   Is this a valid scenario ?
   Is this OK ? IE: When dissected/displayed:
      Will the reassembled datagram 1 appear with frame 2 ??
*/
#if 0
static void
test_fragment_add_seq_check_multiple(void) {
    fragment_head *fd_head;

    pinfo.num = 1;
    fd_head=fragment_add_seq_check(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                                   0, 50, true);

    /* add the terminal fragment of the first datagram */
    pinfo.num = 2;
    fd_head=fragment_add_seq_check(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                                   1, 20, false);

    print_tables();

    /* Now: start a second datagram with the first fragment in frame #2 */
    pinfo.num = 2;
    fd_head=fragment_add_seq_check(&test_reassembly_table, tvb, 25, &pinfo, 12, NULL,
               0, 25, true);

    /* add the terminal fragment of the second datagram */
    pinfo.num = 3;
    fd_head=fragment_add_seq_check(&test_reassembly_table, tvb, 0, &pinfo, 12, NULL,
                                   1, 60, false);

    print_tables();
}
#endif

/**********************************************************************************
 *
 * fragment_add_seq_next
 *
 *********************************************************************************/

/* Simple test case for fragment_add_seq_next.
 * Adds a couple of fragments (with one for a different datagram in between),
 * and checks that they are reassembled correctly.
 */
static void
test_simple_fragment_add_seq_next(void)
{
    fragment_head *fd_head;

    printf("Starting test test_simple_fragment_add_seq_next\n");

    pinfo.num = 1;
    fd_head= fragment_add_seq_next(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                                  50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* adding the same fragment again should do nothing, even with different
     * offset etc */
    pinfo.fd->visited = 1;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                                  60, true);
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.fd->visited = 0;
    pinfo.num = 2;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 15, &pinfo, 13, NULL,
                                  60, true);
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);


    /* now we add the terminal fragment of the first datagram */
    pinfo.num = 3;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                                  60, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(3,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(110,fd_head->len); /* the length of data we have */
    ASSERT_EQ(1,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(3,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_BLOCKSEQUENCE|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* seqno */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next->next);

    ASSERT_EQ(3,fd_head->next->next->frame);
    ASSERT_EQ(1,fd_head->next->next->offset);  /* seqno */
    ASSERT_EQ(60,fd_head->next->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
}


#if 0
/* XXX remove this? fragment_add_seq does not have the special case for
 * fragments having truncated tvbs anymore! */
/* This tests the case where some data is missing from one of the fragments.
 * It should prevent reassembly.
 */
static void
test_missing_data_fragment_add_seq_next(void)
{
    fragment_head *fd_head;

    printf("Starting test test_missing_data_fragment_add_seq_next\n");

    /* attempt to add a fragment which is longer than the data available */
    pinfo.num = 1;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                                  DATA_LEN-9, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure. Reassembly failed so everything
     * should be null (meaning, just use the original tvb)  */
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->len); /* the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE,fd_head->flags & 0x1ff);
    ASSERT_EQ_POINTER(NULL,fd_head->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next);

    /* add another fragment (with all data present) */
    pinfo.num = 4;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                                  60, false);

    /* XXX: it's not clear that this is the right result; however it's what the
     * code does...
     */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);


    /* check what happens when we revisit the packets */
    pinfo.fd->visited = true;
    pinfo.num = 1;

    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                                  DATA_LEN-9, true);

    /* We just look in the reassembled_table for this packet. It never got put
     * there, so this always returns null.
     *
     * That's crazy, because it means that the subdissector will see the data
     * exactly once - on the first pass through the capture (well, assuming it
     * doesn't bother to check fd_head->reassembled_in); however, that's
     * what the code does...
     */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    pinfo.num = 4;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                                  60, false);
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);
}


/*
 * we're going to do something similar now, but this time it is the second
 * fragment which has something missing.
 */
static void
test_missing_data_fragment_add_seq_next_2(void)
{
    fragment_head *fd_head;

    printf("Starting test test_missing_data_fragment_add_seq_next_2\n");

    pinfo.num = 11;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 10, &pinfo, 24, NULL,
                                  50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    pinfo.num = 12;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 5, &pinfo, 24, NULL,
                                  DATA_LEN-4, false);

    /* XXX: again, i'm really dubious about this. Surely this should return all
     * the data we had, for a best-effort attempt at dissecting it?
     * And it ought to go into the reassembled table?
     */
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* check what happens when we revisit the packets */
    pinfo.fd->visited = true;
    pinfo.num = 11;

    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 10, &pinfo, 24, NULL,
                                  50, true);

    /* As before, this returns NULL because the fragment isn't in the
     * reassembled_table. At least this is a bit more consistent than before.
     */
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    pinfo.num = 12;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 5, &pinfo, 24, NULL,
                                  DATA_LEN-4, false);
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

}

/*
 * This time, our datagram only has one segment, but it has data missing.
 */
static void
test_missing_data_fragment_add_seq_next_3(void)
{
    fragment_head *fd_head;

    printf("Starting test test_missing_data_fragment_add_seq_next_3\n");

    pinfo.num = 20;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 5, &pinfo, 30, NULL,
                                  DATA_LEN-4, false);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure. */
    ASSERT_EQ(0,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(20,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE|FD_DEFRAGMENTED,fd_head->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next);

    /* revisiting the packet ought to produce the same result. */
    pinfo.fd->visited = true;

    pinfo.num = 20;
    fd_head=fragment_add_seq_next(&test_reassembly_table, tvb, 5, &pinfo, 30, NULL,
                                  DATA_LEN-4, false);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);
    ASSERT_EQ(0,fd_head->frame);  /* unused */
    ASSERT_EQ(0,fd_head->len); /* the length of data we have */
    ASSERT_EQ(0,fd_head->datalen); /* seqno of the last fragment we have */
    ASSERT_EQ(20,fd_head->reassembled_in);
    ASSERT_EQ(FD_BLOCKSEQUENCE|FD_DEFRAGMENTED,fd_head->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next);
}
#endif

/**********************************************************************************
 *
 * fragment_add
 *
 *********************************************************************************/

/* Simple test case for fragment_add.
 * Adds three fragments (out of order, with one for a different datagram in between),
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag_offset  len  more  tvb_offset
       0    12     1       0        50   T      10
       1    12     1       0        60   T       5
       0    13     2       0        60   T      15
       0    12     3     110        60   F       5
       0    12     4      50        60   T      15
*/
static void
test_simple_fragment_add(void)
{
    fragment_head *fd_head, *fdh0;
    fragment_item *fd;

    printf("Starting test test_simple_fragment_add\n");

    pinfo.num = 1;
    fd_head=fragment_add(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                         0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* adding the same fragment again should do nothing, even with different
     * offset etc */
    pinfo.fd->visited = 1;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         0, 60, true);
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.fd->visited = 0;
    pinfo.num = 2;
    fd_head=fragment_add(&test_reassembly_table, tvb, 15, &pinfo, 13, NULL,
                         0, 60, true);
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* now we add the terminal fragment of the first datagram */
    pinfo.num = 3;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         110, 60, false);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the missing fragment */
    pinfo.num = 4;
    fd_head=fragment_add(&test_reassembly_table, tvb, 15, &pinfo, 12, NULL,
                         50, 60, true);

    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame number of fragment in assembly */
    ASSERT_EQ(0,fd_head->len); /* unused in fragment_add */
    ASSERT_EQ(170,fd_head->datalen); /* total datalen of assembly */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* offset */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(50,fd->offset); /* offset */
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(110,fd->offset); /* offset */
    ASSERT_EQ(60,fd->len);     /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+15,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,60));

    if (debug) {
        print_fragment_table();
    }

    /* what happens if we revisit the packets now? */
    fdh0 = fd_head;
    pinfo.fd->visited = 1;
    pinfo.num = 1;
    fd_head=fragment_add(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                         0, 50, true);
    /*
     * this api relies on the caller to check fd_head -> reassembled_in
     *
     * Redoing all the tests seems like overkill - just check the pointer
     */
    ASSERT_EQ_POINTER(fdh0,fd_head);

    pinfo.num = 3;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         110, 60, false);
    ASSERT_EQ_POINTER(fdh0,fd_head);

    pinfo.num = 4;
    fd_head=fragment_add(&test_reassembly_table, tvb, 15, &pinfo, 12, NULL,
                         50, 60, true);
    ASSERT_EQ_POINTER(fdh0,fd_head);

    if (debug) {
        print_fragment_table();
    }
}

/* This tests the functionality of fragment_set_partial_reassembly for
 * fragment_add based reassembly.
 *
 * We add a sequence of fragments thus:
 *    seq_off   frame  tvb_off   len   (initial) more_frags
 *    -------   -----  -------   ---   --------------------
 *        0       1       10      50   false
 *       50       2        0      40   true
 *       50       3        0      40   true (a duplicate fragment)
 *       90       4       20     100   false
 *      190       5        0      40   false
 */
static void
test_fragment_add_partial_reassembly(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_partial_reassembly\n");

    /* generally it's probably fair to assume that we will be called with
     * more_frags=false.
     */
    pinfo.num = 1;
    fd_head=fragment_add(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                             0, 50, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(1,fd_head->frame);  /* max frame in reassembly */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(50,fd_head->datalen); /* the length of data we have */
    ASSERT_EQ(1,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* offset */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));

    /* now we announce that the reassembly wasn't complete after all. */
    fragment_set_partial_reassembly(&test_reassembly_table, &pinfo, 12, NULL);

    /* and add another segment. To mix things up slightly (and so that we can
     * check on the state of things), we're going to set the more_frags flag
     * here
     */
    pinfo.num = 2;
    fd_head=fragment_add(&test_reassembly_table, tvb, 0, &pinfo, 12, NULL,
                         50, 40, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(2,fd_head->frame);   /* max frame in reassembly */
    ASSERT_EQ(0,fd_head->len);     /* unused */
    /* ASSERT_EQ(0,fd_head->datalen);
     * reassembly not finished; datalen not well defined.
     * Current implemenation has it as 0, could change to 90 without issues */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(0,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* offset */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(FD_SUBSET_TVB,fd->flags);
    ASSERT_EQ_POINTER(tvb_get_ptr(fd_head->tvb_data,0,0),tvb_get_ptr(fd->tvb_data,0,0));
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset); /* offset */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* Another copy of the second segment.
     */
    pinfo.num = 3;
    fd_head=fragment_add(&test_reassembly_table, tvb, 0, &pinfo, 12, NULL,
                         50, 40, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);
    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);
    ASSERT_EQ(3,fd_head->frame);   /* max frame we have */
    ASSERT_EQ(0,fd_head->len);     /* unused */
    /* ASSERT_EQ(0,fd_head->datalen);
     * reassembly not finished; datalen not well defined.
     * Current implemenation has it as 0, could change to 90 without issues */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(0,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(FD_SUBSET_TVB,fd->flags);
    ASSERT_EQ_POINTER(tvb_get_ptr(fd_head->tvb_data,0,0),tvb_get_ptr(fd->tvb_data,0,0));
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);



    /* have another go at wrapping things up */
    pinfo.num = 4;
    fd_head=fragment_add(&test_reassembly_table, tvb, 20, &pinfo, 12, NULL,
                         90, 100, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(190,fd_head->datalen); /* the length of data we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(90,fd->offset);
    ASSERT_EQ(100,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data,40));
    ASSERT(!tvb_memeql(fd_head->tvb_data,90,data+20,100));


    /* do it again (this time it is more complicated, with an overlap in the
     * reassembly) */

    fragment_set_partial_reassembly(&test_reassembly_table, &pinfo, 12, NULL);

    pinfo.num = 5;
    fragment_add(&test_reassembly_table, tvb, 0, &pinfo, 12, NULL,
                 190, 40, false);

    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);
    ASSERT_EQ(5,fd_head->frame);   /* max frame we have */
    ASSERT_EQ(0,fd_head->len);   /* unused */
    ASSERT_EQ(230,fd_head->datalen); /* the length of data we have */
    ASSERT_EQ(5,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(90,fd->offset);
    ASSERT_EQ(100,fd->len);   /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(5,fd->frame);
    ASSERT_EQ(190,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data,40));
    ASSERT(!tvb_memeql(fd_head->tvb_data,90,data+20,100));
    ASSERT(!tvb_memeql(fd_head->tvb_data,190,data,40));
}

/* XXX: Is the proper behavior here really throwing an exception instead
 * of setting FD_OVERLAP?
 */
/* Test case for fragment_add with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 1st one twice at the end--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag_off  len  more  tvb_offset
       0    12     1        0    50   T      10
       0    12     2       50    60   T      5
       0    12     3      110    40   F      5
       0    12     4        0    50   T      10
*/
static void
test_fragment_add_duplicate_first(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_duplicate_first\n");

    pinfo.num = 1;
    fd_head=fragment_add(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                         0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         50, 60, true);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the last fragment */
    pinfo.num = 3;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         110, 40, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* Add the first fragment again */
    pinfo.num = 4;
    fd_head=fragment_add(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                         0, 50, true);

    /* Reassembly should have still succeeded */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* add the duplicate frame */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(150,fd_head->datalen);
    ASSERT_EQ(3,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;

    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}


/* Test case for fragment_add with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 2nd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag_off  len  more  tvb_offset
       0    12     1       0     50   T      10
       0    12     2      50     60   T      5
       0    12     3      50     60   T      5
       0    12     4     110     40   F      5
*/
static void
test_fragment_add_duplicate_middle(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_duplicate_middle\n");

    pinfo.num = 1;
    fd_head=fragment_add(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                         0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         50, 60, true);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Now, add the 2nd segment again (but in a different frame) */
    pinfo.num = 3;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         50, 60, true);

    /* This duplicate fragment should have been ignored */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the last fragment */
    pinfo.num = 4;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         110, 40, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(150,fd_head->datalen);
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}

/* XXX: Is the proper behavior here really throwing an exception instead
 * of setting FD_OVERLAP?
 */
/* Test case for fragment_add with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 3rd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     2    40   F      5
       0    12     4     2    40   F      5
*/
static void
test_fragment_add_duplicate_last(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_duplicate_last\n");

    pinfo.num = 1;
    fd_head=fragment_add(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                         0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         50, 60, true);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the last fragment */
    pinfo.num = 3;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         110, 40, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* Add the last fragment again */
    pinfo.num = 4;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         110, 40, false);

    /* Reassembly should have still succeeded */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(150,fd_head->datalen);
    ASSERT_EQ(3,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);

    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}

/* Test case for fragment_add with duplicated (e.g., retransmitted) data
 * where the retransmission "conflicts" with the original transmission
 * (contents are different).
 * Adds three fragments--adding the 2nd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag_off  len  more  tvb_offset
       0    12     1       0     50   T      10
       0    12     2      50     60   T      5
       0    12     3      50     60   T      15
       0    12     4     110     40   F      5
*/
static void
test_fragment_add_duplicate_conflict(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_duplicate_conflict\n");

    pinfo.num = 1;
    fd_head=fragment_add(&test_reassembly_table, tvb, 10, &pinfo, 12, NULL,
                         0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         50, 60, true);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Now, add the 2nd segment again (but in a different frame and with
     * different data)
     */
    pinfo.num = 3;
    fd_head=fragment_add(&test_reassembly_table, tvb, 15, &pinfo, 12, NULL,
                         50, 60, true);

    /* This duplicate fragment should have been ignored */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the last fragment */
    pinfo.num = 4;
    fd_head=fragment_add(&test_reassembly_table, tvb, 5, &pinfo, 12, NULL,
                         110, 40, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(150,fd_head->datalen);
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP|FD_OVERLAPCONFLICT,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP|FD_OVERLAPCONFLICT,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}

/**********************************************************************************
 *
 * fragment_add_check
 *
 *********************************************************************************/

/* Simple test case for fragment_add_check.
 * Adds three fragments (out of order, with one for a different datagram in between),
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag_offset  len  more  tvb_offset
       0    12     1       0        50   T      10
       1    12     1       0        60   T       5
       0    13     2       0        60   T      15
       0    12     3     110        60   F       5
       0    12     4      50        60   T      15
*/
static void
test_simple_fragment_add_check(void)
{
    fragment_head *fd_head, *fdh0;
    fragment_item *fd;

    printf("Starting test test_simple_fragment_add_check\n");

    pinfo.num = 1;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 10, &pinfo, 12,
                               NULL, 0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* adding the same fragment again should do nothing, even with different
     * offset etc */
    pinfo.fd->visited = 1;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 0, 60, true);
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* start another pdu (just to confuse things) */
    pinfo.fd->visited = 0;
    pinfo.num = 2;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 15, &pinfo, 13,
                               NULL, 0, 60, true);
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* now we add the terminal fragment of the first datagram */
    pinfo.num = 3;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 110, 60, false);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(2,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the missing fragment */
    pinfo.num = 4;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 15, &pinfo, 12,
                               NULL, 50, 60, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(3,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame number of fragment in assembly */
    ASSERT_EQ(0,fd_head->len); /* unused in fragment_add */
    ASSERT_EQ(170,fd_head->datalen); /* total datalen of assembly */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(60,fd->len);     /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+15,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,60));

    if (debug) {
        print_fragment_table();
    }

    /* what happens if we revisit the packets now? */
    fdh0 = fd_head;
    pinfo.fd->visited = 1;
    pinfo.num = 1;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 10, &pinfo, 12,
                               NULL, 0, 50, true);
    /*
     * this api relies on the caller to check fd_head -> reassembled_in
     *
     * Redoing all the tests seems like overkill - just check the pointer
     */
    ASSERT_EQ_POINTER(fdh0,fd_head);

    pinfo.num = 3;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 110, 60, false);
    ASSERT_EQ_POINTER(fdh0,fd_head);

    pinfo.num = 4;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 15, &pinfo, 12,
                               NULL, 50, 60, true);
    ASSERT_EQ_POINTER(fdh0,fd_head);

    if (debug) {
        print_fragment_table();
    }
}

#if 0
/* XXX: fragment_set_partial_reassembly() does not work for fragment_add_check
 * because it doesn't remove the previously completed reassembly from
 * reassembled_table (and lookup_fd_head() only looks in the fragment
 * table, not the reassembled_table) */
/* This tests the functionality of fragment_set_partial_reassembly for
 * fragment_add_check based reassembly.
 *
 * We add a sequence of fragments thus:
 *    seq_off   frame  tvb_off   len   (initial) more_frags
 *    -------   -----  -------   ---   --------------------
 *        0       1       10      50   false
 *       50       2        0      40   true
 *       50       3        0      40   true (a duplicate fragment)
 *       90       4       20     100   false
 *      190       5        0      40   false
 */
static void
test_fragment_add_check_partial_reassembly(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_check_partial_reassembly\n");

    /* generally it's probably fair to assume that we will be called with
     * more_frags=false.
     */
    pinfo.num = 1;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 10, &pinfo, 12,
                               NULL, 0, 50, false);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(1,fd_head->frame);  /* max frame in reassembly */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(50,fd_head->datalen); /* the length of data we have */
    ASSERT_EQ(1,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    ASSERT_EQ(1,fd_head->next->frame);
    ASSERT_EQ(0,fd_head->next->offset);  /* offset */
    ASSERT_EQ(50,fd_head->next->len);    /* segment length */
    ASSERT_EQ(0,fd_head->next->flags);
    ASSERT_EQ_POINTER(NULL,fd_head->next->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd_head->next->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));

    /* now we announce that the reassembly wasn't complete after all. */
    fragment_set_partial_reassembly(&test_reassembly_table, &pinfo, 12, NULL);

    /* and add another segment. To mix things up slightly (and so that we can
     * check on the state of things), we're going to set the more_frags flag
     * here
     */
    pinfo.num = 2;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 0, &pinfo, 12,
                               NULL, 50, 40, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(2,fd_head->frame);   /* max frame in reassembly */
    ASSERT_EQ(0,fd_head->len);     /* unused */
    /* ASSERT_EQ(0,fd_head->datalen);
     * reassembly not finished; datalen not well defined.
     * Current implemenation has it as 0, could change to 90 without issues */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(0,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);  /* offset */
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(FD_SUBSET_TVB,fd->flags);
    ASSERT_EQ_POINTER(tvb_get_ptr(fd_head->tvb_data,0,0),tvb_get_ptr(fd->tvb_data,0,0));
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset); /* offset */
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* Another copy of the second segment.
     */
    pinfo.num = 3;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 0, &pinfo, 12,
                               NULL, 50, 40, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ_POINTER(NULL,fd_head);
    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);
    ASSERT_EQ(3,fd_head->frame);   /* max frame we have */
    ASSERT_EQ(0,fd_head->len);     /* unused */
    /* ASSERT_EQ(0,fd_head->datalen);
     * reassembly not finished; datalen not well defined.
     * Current implemenation has it as 0, could change to 90 without issues */
    ASSERT_EQ(0,fd_head->reassembled_in);
    ASSERT_EQ(0,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(FD_SUBSET_TVB,fd->flags);
    ASSERT_EQ_POINTER(tvb_get_ptr(fd_head->tvb_data,0,0),tvb_get_ptr(fd->tvb_data,0,0));
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_NE_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);



    /* have another go at wrapping things up */
    pinfo.num = 4;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 20, &pinfo, 12,
                               NULL, 90, 100, false);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(190,fd_head->datalen); /* the length of data we have */
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(90,fd->offset);
    ASSERT_EQ(100,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data,40));
    ASSERT(!tvb_memeql(fd_head->tvb_data,90,data+20,100));


    /* do it again (this time it is more complicated, with an overlap in the
     * reassembly) */

    fragment_set_partial_reassembly(&test_reassembly_table, &pinfo, 12, NULL);

    pinfo.num = 5;
    fragment_add_check(&test_reassembly_table, tvb, 0, &pinfo, 12, NULL,
                       190, 40, false);

    fd_head=fragment_get(&test_reassembly_table, &pinfo, 12, NULL);
    ASSERT_NE_POINTER(NULL,fd_head);
    ASSERT_EQ(5,fd_head->frame);   /* max frame we have */
    ASSERT_EQ(0,fd_head->len);   /* unused */
    ASSERT_EQ(230,fd_head->datalen); /* the length of data we have */
    ASSERT_EQ(5,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd=fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(90,fd->offset);
    ASSERT_EQ(100,fd->len);   /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd=fd->next;
    ASSERT_EQ(5,fd->frame);
    ASSERT_EQ(190,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data,40));
    ASSERT(!tvb_memeql(fd_head->tvb_data,90,data+20,100));
    ASSERT(!tvb_memeql(fd_head->tvb_data,190,data,40));
}
#endif

#if 0
/* XXX: fragment_add_check moves completed reassemblies to the
 * reassembled_table, so adding a duplicated fragment after the end doesn't
 * get marked as duplicate, but starts a new reassembly. This is the correct
 * thing for very long captures where the identification field gets reused,
 * somewhat wrong when it is retransmitted data (it won't get marked as such
 * but doesn't interfere with defragmentation too much), and very wrong when
 * there is both retransmitted data and later on the identification field
 * gets reused (the dangling data will get added to the wrong reassembly.)
 *
 * Not sure what behavior to check. Possibly both behaviors should be supported,
 * perhaps being affected by how close pinfo.num is to the reassembly, though
 * that gets complicated.
 */
/* Test case for fragment_add_check with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 1st one twice at the end--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag_off  len  more  tvb_offset
       0    12     1        0    50   T      10
       0    12     2       50    60   T      5
       0    12     3      110    40   F      5
       0    12     4        0    50   T      10
*/
static void
test_fragment_add_check_duplicate_first(void)
{
    fragment_head *fd_head;
    fragment_item *fd;
    volatile bool ex_thrown;

    printf("Starting test test_fragment_add_check_duplicate_first\n");

    pinfo.num = 1;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 10, &pinfo, 12,
                               NULL, 0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 50, 60, true);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the last fragment */
    pinfo.num = 3;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 110, 40, false);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(3,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* Add the first fragment again */
    pinfo.num = 4;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 10, &pinfo, 12,
                               NULL, 0, 50, true);

    /* Reassembly should have still succeeded */
    /* XXX: Current behavior is to start a new reassembly - which is
     * the proper behavior in a long capture that reuses the id, but the
     * wrong thing when it's actually a retransmission. Should the distinction
     * be made by analyzing pinfo.num to see if it is nearby? Or is that the
     * dissector's job? */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(3,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    /*ASSERT_EQ(4,fd_head->frame);  max frame we have */
    ASSERT_EQ(3,fd_head->frame);  /* never add the duplicate frame */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(150,fd_head->datalen);
    ASSERT_EQ(3,fd_head->reassembled_in);
    /* ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags); */
    /* FD_OVERLAP doesn't get set because we hit the exception early */
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;

    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    /*
    fd = fd_head->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next); */

    fd = fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}
#endif

/* Test case for fragment_add_check with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 2nd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag_off  len  more  tvb_offset
       0    12     1       0     50   T      10
       0    12     2      50     60   T      5
       0    12     3      50     60   T      5
       0    12     4     110     40   F      5
*/
static void
test_fragment_add_check_duplicate_middle(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_check_duplicate_middle\n");

    pinfo.num = 1;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 10, &pinfo, 12,
                               NULL, 0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 50, 60, true);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Now, add the 2nd segment again (but in a different frame) */
    pinfo.num = 3;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 50, 60, true);

    /* This duplicate fragment should have been ignored */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the last fragment */
    pinfo.num = 4;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 110, 40, false);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(4,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(150,fd_head->datalen);
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}

#if 0
/* XXX: same issue as test_fragment_add_check_duplicate_first, above.
 */
/* Test case for fragment_add_check with duplicated (e.g., retransmitted) data.
 * Adds three fragments--adding the 3rd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag  len  more  tvb_offset
       0    12     1     0    50   T      10
       0    12     2     1    60   T      5
       0    12     3     2    40   F      5
       0    12     4     2    40   F      5
*/
static void
test_fragment_add_check_duplicate_last(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_check_duplicate_last\n");

    pinfo.num = 1;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 10, &pinfo, 12,
                               NULL, 0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 50, 60, true);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the last fragment */
    pinfo.num = 3;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 110, 40, false);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(3,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* Add the last fragment again */
    pinfo.num = 4;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 110, 40, false);

    /* Reassembly should have still succeeded */
    /* XXX: Current behavior is to start a new reassembly */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(3,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    /* ASSERT_EQ(4,fd_head->frame); never add the last frame again */
    ASSERT_EQ(3,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(150,fd_head->datalen);
    ASSERT_EQ(3,fd_head->reassembled_in);
    /* ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP,fd_head->flags);
     * FD_OVERLAP doesn't get set since we don't add a fragment after the
     * end but start a new assembly instead. */
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);

    /* Duplicate packet never gets added
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);
    ASSERT_EQ(FD_OVERLAP,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next); */

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}
#endif

/* Test case for fragment_add_check with duplicated (e.g., retransmitted) data
 * where the retransmission "conflicts" with the original transmission
 * (contents are different).
 * Adds three fragments--adding the 2nd one twice--
 * and checks that they are reassembled correctly.
 */
/*   visit  id  frame  frag_off  len  more  tvb_offset
       0    12     1       0     50   T      10
       0    12     2      50     60   T      5
       0    12     3      50     60   T      15
       0    12     4     110     40   F      5
*/
static void
test_fragment_add_check_duplicate_conflict(void)
{
    fragment_head *fd_head;
    fragment_item *fd;

    printf("Starting test test_fragment_add_check_duplicate_conflict\n");

    pinfo.num = 1;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 10, &pinfo, 12,
                               NULL, 0, 50, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Add the 2nd segment */
    pinfo.num = 2;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 50, 60, true);

    /* we haven't got all the fragments yet ... */
    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* Now, add the 2nd segment again (but in a different frame and with
     * different data)
     */
    pinfo.num = 3;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 15, &pinfo, 12,
                               NULL, 50, 60, true);

    ASSERT_EQ(1,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_EQ_POINTER(NULL,fd_head);

    /* finally, add the last fragment */
    pinfo.num = 4;
    fd_head=fragment_add_check(&test_reassembly_table, tvb, 5, &pinfo, 12,
                               NULL, 110, 40, false);

    ASSERT_EQ(0,g_hash_table_size(test_reassembly_table.fragment_table));
    ASSERT_EQ(4,g_hash_table_size(test_reassembly_table.reassembled_table));
    ASSERT_NE_POINTER(NULL,fd_head);

    /* check the contents of the structure */
    ASSERT_EQ(4,fd_head->frame);  /* max frame we have */
    ASSERT_EQ(0,fd_head->len); /* unused */
    ASSERT_EQ(150,fd_head->datalen);
    ASSERT_EQ(4,fd_head->reassembled_in);
    ASSERT_EQ(FD_DEFRAGMENTED|FD_DATALEN_SET|FD_OVERLAP|FD_OVERLAPCONFLICT,fd_head->flags);
    ASSERT_NE_POINTER(NULL,fd_head->tvb_data);
    ASSERT_NE_POINTER(NULL,fd_head->next);

    fd = fd_head->next;
    ASSERT_EQ(1,fd->frame);
    ASSERT_EQ(0,fd->offset);
    ASSERT_EQ(50,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(2,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(3,fd->frame);
    ASSERT_EQ(50,fd->offset);
    ASSERT_EQ(60,fd->len);    /* segment length */
    ASSERT_EQ(FD_OVERLAP|FD_OVERLAPCONFLICT,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_NE_POINTER(NULL,fd->next);

    fd = fd->next;
    ASSERT_EQ(4,fd->frame);
    ASSERT_EQ(110,fd->offset);
    ASSERT_EQ(40,fd->len);    /* segment length */
    ASSERT_EQ(0,fd->flags);
    ASSERT_EQ_POINTER(NULL,fd->tvb_data);
    ASSERT_EQ_POINTER(NULL,fd->next);

    /* test the actual reassembly */
    ASSERT(!tvb_memeql(fd_head->tvb_data,0,data+10,50));
    ASSERT(!tvb_memeql(fd_head->tvb_data,50,data+5,60));
    ASSERT(!tvb_memeql(fd_head->tvb_data,110,data+5,40));

    if (debug) {
        print_fragment_table();
    }
}
/**********************************************************************************
 *
 * main
 *
 *********************************************************************************/

int
main(int argc _U_, char **argv _U_)
{
    frame_data fd;
    static const uint8_t src[] = {1,2,3,4}, dst[] = {5,6,7,8};
    unsigned int i;
    static void (*tests[])(void) = {
        test_simple_fragment_add_seq,              /* frag table only   */
        test_fragment_add_seq_partial_reassembly,
        test_fragment_add_seq_duplicate_first,
        test_fragment_add_seq_duplicate_middle,
        test_fragment_add_seq_duplicate_last,
        test_fragment_add_seq_duplicate_conflict,
        test_fragment_add_seq_check,               /* frag + reassemble */
        test_fragment_add_seq_check_1,
        test_fragment_add_seq_802_11_0,
        test_fragment_add_seq_802_11_1,
        test_simple_fragment_add_seq_next,
#if 0
        test_missing_data_fragment_add_seq_next,
        test_missing_data_fragment_add_seq_next_2,
        test_missing_data_fragment_add_seq_next_3,
#endif
#if 0
        test_fragment_add_seq_check_multiple
#endif
        test_simple_fragment_add,              /* frag table only   */
        test_fragment_add_partial_reassembly,
        test_fragment_add_duplicate_first,
        test_fragment_add_duplicate_middle,
        test_fragment_add_duplicate_last,
        test_fragment_add_duplicate_conflict,
        test_simple_fragment_add_check,              /* frag table only   */
#if 0
        test_fragment_add_check_partial_reassembly,
        test_fragment_add_check_duplicate_first,
#endif
        test_fragment_add_check_duplicate_middle,
#if 0
        test_fragment_add_check_duplicate_last,
#endif
        test_fragment_add_check_duplicate_conflict,
    };

    /* a tvbuff for testing with */
    data = (uint8_t *)g_malloc(DATA_LEN);
    /* make sure it's full of stuff */
    for(i=0; i<DATA_LEN; i++) {
        data[i]=i & 0xFF;
    }
    tvb = tvb_new_real_data(data, DATA_LEN, DATA_LEN*2);

    /* other test stuff */
    pinfo.fd = &fd;
    fd.visited = 0;
    set_address(&pinfo.src,AT_IPv4,4,src);
    set_address(&pinfo.dst,AT_IPv4,4,dst);

    /*************************************************************************/
    for(i=0; i < array_length(tests); i++ ) {
        /* re-init the fragment tables */
        reassembly_table_init(&test_reassembly_table,
                              &addresses_reassembly_table_functions);
        ASSERT(test_reassembly_table.fragment_table != NULL);
        ASSERT(test_reassembly_table.reassembled_table != NULL);

        pinfo.fd->visited = false;

        tests[i]();

        /* Free memory used by the tables */
        reassembly_table_destroy(&test_reassembly_table);
    }

    tvb_free(tvb);
    tvb = NULL;
    g_free(data);
    data = NULL;

    printf(failure?"FAILURE\n":"SUCCESS\n");
    return failure;
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
