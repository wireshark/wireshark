/* Reorder the frames from an input dump file, and write to output dump file.
 * Martin Mathieson
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wtap.h"


/* Show command-line usage */
/* TODO: add reoder list length as an optional param? */
static void usage(void)
{
    printf("usage:  reordercap <infile> <outfile>\n");
}

/* Remember where this frame was in the file */
typedef struct FrameRecord_t {
    gint64               offset;
    guint32              length;

    struct wtap_nstime   time;

    /* List item pointers */
    struct FrameRecord_t *prev;
    struct FrameRecord_t *next;
} FrameRecord_t;

/* This is pretty big, but I don't mind waiting a few seconds */
#define MAX_REORDER_LIST_LENGTH 3000
static unsigned int g_FrameRecordCount;

/* This is the list of frames, sorted by time.  Later frames at the front, earlier
   ones at the end */
static FrameRecord_t *g_FrameListHead;
static FrameRecord_t *g_FrameListTail;


/**************************************************/
/* Debugging only                                 */

/* Enable this symbol to see debug output */
/* #define REORDER_DEBUG */

#ifdef REORDER_DEBUG
static void ReorderListDebugPrint(void)
{
    int count=0;
    FrameRecord_t *tmp = g_FrameListHead;
    printf("\n");
    while (tmp != NULL) {
        printf("%6d: offset=%6" G_GINT64_MODIFIER "u, length=%6u, time=%lu:%u",
               ++count, tmp->offset, tmp->length, tmp->time.secs, tmp->time.nsecs);

        if (tmp == g_FrameListHead) {
            printf(" (head)");
        }
        if (tmp == g_FrameListTail) {
            printf(" (tail)\n");
        }
        printf("\n");

        tmp = tmp->next;
    }
    printf("\n");
}
#else
#define ReorderListDebugPrint()
#endif

#ifdef REORDER_DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT(...)
#endif

/**************************************************/

/* Counting frames that weren't in order */
static unsigned int g_OutOfOrder = 0;


/* Is time1 later than time2? */
static gboolean isLaterTime(struct wtap_nstime time1,
                            struct wtap_nstime time2)
{
    if (time1.secs > time2.secs) {
        return TRUE;
    }
    if (time1.secs == time2.secs) {
        return (time1.nsecs > time2.nsecs);
    }
    else {
        return FALSE;
    }
}

/* Is the reorder list empty? */
static gboolean ReorderListEmpty(void)
{
    return (g_FrameRecordCount == 0);
}

/* Is the reorder list full? */
static gboolean ReorderListFull(void)
{
    return (g_FrameRecordCount >= MAX_REORDER_LIST_LENGTH);
}

/* Add a new frame to the reorder list */
/* Adding later ones to the front */
static void ReorderListAdd(gint64 offset, guint32 length,
                           struct wtap_nstime time)
{
    FrameRecord_t *tmp;
    FrameRecord_t *newFrameRecord = g_malloc(sizeof(FrameRecord_t));

    /* Populate fields */
    DEBUG_PRINT("\nAdded with offset=%06" G_GINT64_MODIFIER "u, length=%05u, secs=%lu, nsecs=%d\n",
                offset, length, time.secs, time.nsecs);
    newFrameRecord->offset = offset;
    newFrameRecord->length = length;
    newFrameRecord->time = time;

    /* We will definitely add it below, so inc counter */
    g_FrameRecordCount++;

    /* First time, this will be the head */
    if (g_FrameListHead == NULL) {
        DEBUG_PRINT("this item will be head - only item\n");
        g_FrameListHead = newFrameRecord;
        newFrameRecord->prev = NULL;
        newFrameRecord->next = NULL;
        g_FrameListTail = newFrameRecord;
        return;
    }

    /* Look for the place in the list where this item fits */
    tmp = g_FrameListHead;
    while (tmp != NULL) {
        if (isLaterTime(time, tmp->time)) {
            DEBUG_PRINT("Time was Later, writing before element\n");

            /* Insert newFrameRecord *before* tmp */

            /* Fix up prev item */
            if (tmp == g_FrameListHead) {
                /* Inserting before existing head */
                g_FrameListHead = newFrameRecord;
            }
            else {
                /* Our prev is tmps old prev */
                newFrameRecord->prev = tmp->prev;
                /* Its next points to us */
                newFrameRecord->prev->next = newFrameRecord;

                /* Inserted after another item */
                DEBUG_PRINT("*** Inc out out of order count\n");
                g_OutOfOrder++;
            }

            /* Fix up next item */
            newFrameRecord->next = tmp;
            tmp->prev = newFrameRecord;

            return;
        }

        /* Didn't find an item to insert in front of */
        if (tmp->next == NULL) {
            DEBUG_PRINT("Reached the end of the list, so insert here\n");

            /* We are the new last item */
            tmp->next = newFrameRecord;
            newFrameRecord->prev = tmp;
            newFrameRecord->next = NULL;
            g_FrameListTail = newFrameRecord;

            /* There were other items but we were earlier than them */
            DEBUG_PRINT("*** Inc out out of order count\n");
            g_OutOfOrder++;

            return;
        }
        else {
            /* Move onto the next item */
            DEBUG_PRINT("Time was earlier, move to next position\n");
            tmp = tmp->next;
        }
    }
}

/* Dump the earliest item in the reorder list to the output file, and pop it */
static void ReorderListDumpEarliest(wtap *wth, wtap_dumper *pdh)
{
    union wtap_pseudo_header pseudo_header;
    int    err;
    gchar  *errinfo;
    const struct wtap_pkthdr *phdr;
    guint8 buf[16000];
    struct wtap_pkthdr new_phdr;

    FrameRecord_t *prev_tail = g_FrameListTail;

    DEBUG_PRINT("\nDumping frame (offset=%" G_GINT64_MODIFIER "u, length=%u) (%u items in list)\n", 
                g_FrameListHead->offset, g_FrameListHead->length,
                g_FrameRecordCount);

    /* Re-read the first frame from the stored location */
    wtap_seek_read(wth,
                   g_FrameListTail->offset,
                   &pseudo_header,
                   buf,
                   g_FrameListTail->length,
                   &err,
                   &errinfo);
    DEBUG_PRINT("re-read: err is %d, buf is (%s)\n", err, buf);

    /* Get packet header */
    phdr = wtap_phdr(wth);

    /* Copy, and set length and timestamp from item. */
    memcpy((void*)&new_phdr, phdr, sizeof(struct wtap_pkthdr));
    new_phdr.len = g_FrameListTail->length;
    new_phdr.ts.secs = g_FrameListTail->time.secs;
    new_phdr.ts.nsecs = g_FrameListTail->time.nsecs;

    /* Dump frame to outfile */
    if (!wtap_dump(pdh, &new_phdr, &pseudo_header, buf, &err)) {
        printf("Error (%s) writing frame to outfile\n", wtap_strerror(err));
        exit(1);
    }

    /* Now remove this (the last/earliest) item from the list */
    if (g_FrameListTail->prev == NULL) {
        g_FrameListTail = NULL;
        g_FrameListHead = NULL;
    }
    else {
        /* 2nd last item is now last */
        g_FrameListTail->prev->next = NULL;
        g_FrameListTail = g_FrameListTail->prev;
    }

    /* And free the struct */
    g_free(prev_tail);
    g_FrameRecordCount--;

    DEBUG_PRINT("Frame written, %u remaining\n", g_FrameRecordCount);
}



/********************************************************************/
/* Main function.                                                   */
/********************************************************************/
int main(int argc, char *argv[])
{
    wtap *wth = NULL;
    wtap_dumper *pdh = NULL;
    int err;
    gchar *err_info;
    gint64 data_offset;
    const struct wtap_pkthdr *phdr;
    guint32 read_count = 0;

    /* 1st arg is infile, 2nd arg is outfile */
    char *infile;
    char *outfile;
    if (argc == 3) {
        infile = argv[1];
        outfile = argv[2];
    }
    else {
        usage();
        exit(1);
    }

    /* Open infile */
    wth = wtap_open_offline(infile, &err, &err_info, TRUE);
    if (wth == NULL) {
        printf("reorder: Can't open %s: %s\n", infile, wtap_strerror(err));
        exit(1);
    }

    DEBUG_PRINT("file_type is %u\n", wtap_file_type(wth));

    /* Open outfile (same filetype/encap as input file) */
    pdh = wtap_dump_open(outfile, wtap_file_type(wth), wtap_file_encap(wth), 65535, FALSE, &err);
    if (pdh == NULL) {
        printf("Failed to open output file: (%s) - error %s\n", outfile, wtap_strerror(err));
        exit(1);
    }


    /* Read each frame from infile */
    while (wtap_read(wth, &err, &err_info, &data_offset)) {
        read_count++;
        phdr = wtap_phdr(wth);

        /* Add it to the reordering list */
        ReorderListAdd(data_offset, phdr->len, phdr->ts);
        ReorderListDebugPrint();

        /* If/when the list gets full, dump the earliest item out */
        if (ReorderListFull()) {
            DEBUG_PRINT("List is full, dumping earliest!\n");

            /* Write out the earliest one */
            ReorderListDumpEarliest(wth, pdh);
            ReorderListDebugPrint();
        }
    }

    /* Flush out the remaining (ordered) frames */
    while (!ReorderListEmpty()) {
        ReorderListDumpEarliest(wth, pdh);
        ReorderListDebugPrint();
    }

    /* Close outfile */
    if (!wtap_dump_close(pdh, &err)) {
        printf("Error closing %s: %s\n", outfile, wtap_strerror(err));
        exit(1);
    }

    /* Write how many frames, and how many were out of order */
    printf("%u frames, %u out of order\n", read_count, g_OutOfOrder);

    /* Finally, close infile */
    wtap_fdclose(wth);

    return 0;
}

