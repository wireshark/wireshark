/* tap-iostat.c
 * iostat   2002 Ronnie Sahlberg
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include "epan/epan_dissect.h"
#include "epan/packet_info.h"
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/strutil.h>
#include "globals.h"

#define CALC_TYPE_FRAMES 0
#define CALC_TYPE_BYTES	 1
#define CALC_TYPE_FRAMES_AND_BYTES	 2
#define CALC_TYPE_COUNT	 3
#define CALC_TYPE_SUM	 4
#define CALC_TYPE_MIN	 5
#define CALC_TYPE_MAX	 6
#define CALC_TYPE_AVG	 7
#define CALC_TYPE_LOAD	 8

typedef struct {
	const char *func_name;
	int calc_type;
} calc_type_ent_t;

static calc_type_ent_t calc_type_table[] = {
	{ "FRAMES", CALC_TYPE_FRAMES },
	{ "BYTES", CALC_TYPE_BYTES },
	{ "FRAMES BYTES", CALC_TYPE_FRAMES_AND_BYTES },
	{ "COUNT", CALC_TYPE_COUNT },
	{ "SUM", CALC_TYPE_SUM },
	{ "MIN", CALC_TYPE_MIN },
	{ "MAX", CALC_TYPE_MAX },
	{ "AVG", CALC_TYPE_AVG },
	{ "LOAD", CALC_TYPE_LOAD },
	{ NULL, 0 }
};

typedef struct _io_stat_t {
	guint64 interval;	  /* The user-specified time interval (us) */
    guint invl_prec;      /* Decimal precision of the time interval (1=10s, 2=100s etc) */
	guint32 num_cols;     /* The number of columns of statistics in the table */
	struct _io_stat_item_t 
        *items;           /* Each item is a single cell in the table */   
	const char **filters; /* 'io,stat' cmd strings (e.g., "AVG(smb.time)smb.time") */
    guint64 *max_vals;    /* The max value sans the decimal or nsecs portion in each stat column */
    guint32 *max_frame;   /* The max frame number displayed in each stat column */
} io_stat_t;

typedef struct _io_stat_item_t {
	io_stat_t *parent;
    struct _io_stat_item_t *next;
	struct _io_stat_item_t *prev;
	guint64 time;		  /* Time since start of capture (us)*/
	int calc_type;        /* The statistic type */
    int colnum;           /* Column number of this stat (0 to n) */
	int hf_index;
	guint32 frames;
	guint32 num;          /* The sample size of a given statistic (only needed for AVG) */
	guint64 counter;      /* The accumulated data for the calculation of that statistic */
	gfloat float_counter;
	gdouble double_counter;
} io_stat_item_t;

#define NANOSECS_PER_SEC 1000000000

static int
iostat_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_)
{
	io_stat_t *parent;
    io_stat_item_t *mit;
	io_stat_item_t *it;
	guint64 relative_time, rt;
    nstime_t *new_time;
    GPtrArray *gp;
	guint i;
    int ftype;
    
    mit = (io_stat_item_t *) arg;
    parent = mit->parent;
	relative_time = (guint64)((pinfo->fd->rel_ts.secs*1000000) + ((pinfo->fd->rel_ts.nsecs+500)/1000));

	/* The prev item before the main one is always the last interval we saw packets for */
	it = mit->prev;

	/* XXX for the time being, just ignore all frames that are in the past.
	   should be fixed in the future but hopefully it is uncommon */
	if(relative_time < it->time){
		return FALSE;
	}

	/* If we have moved into a new interval (row), create a new io_stat_item_t struct for every interval
    *  between the last struct and this one. If an item was not found in a previous interval, an empty 
    *  struct will be created for it. */
	rt = relative_time;
	while (rt >= it->time + parent->interval) {
		it->next = (io_stat_item_t *)g_malloc(sizeof(io_stat_item_t));
		it->next->prev = it;
		it->next->next = NULL;
		it = it->next;
		mit->prev = it;

		it->time = it->prev->time + parent->interval;
		it->frames = 0;
		it->counter = 0;
		it->float_counter = 0;
		it->double_counter = 0;
		it->num = 0;
		it->calc_type = it->prev->calc_type;
		it->hf_index = it->prev->hf_index;
        it->colnum = it->prev->colnum;
	}

	/* Store info in the current structure */
	it->frames++;

    switch(it->calc_type) {
	case CALC_TYPE_FRAMES:
	case CALC_TYPE_BYTES:
	case CALC_TYPE_FRAMES_AND_BYTES:
		it->counter += pinfo->fd->pkt_len;
		break;
	case CALC_TYPE_COUNT:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			it->counter += gp->len;
		}
		break;
	case CALC_TYPE_SUM:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			guint64 val;

			for(i=0;i<gp->len;i++){
				switch(proto_registrar_get_ftype(it->hf_index)){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					it->counter += fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_UINT64:
					it->counter += fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					it->counter += fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_INT64:
					it->counter += (gint64)fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_FLOAT:
					it->float_counter += 
                        (gfloat)fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_DOUBLE:
					it->double_counter += fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_RELATIVE_TIME:
					new_time = fvalue_get(&((field_info *)gp->pdata[i])->value);
					val = (guint64)((new_time->secs * NANOSECS_PER_SEC) + new_time->nsecs);
					it->counter  +=  val;
					break;
				}
			}
		}
		break;
	case CALC_TYPE_MIN:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			guint64 val;
			gfloat float_val;
			gdouble double_val;

			ftype=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				switch(ftype){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					val = fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);
					if ((it->frames==1 && i==0) || (val < it->counter)) {
						it->counter=val;
					}
					break;
				case FT_UINT64:
					val = fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1 && i==0) || (val < it->counter)){
						it->counter=val;
					}
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val = fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1 && i==0) || ((gint32)val < (gint32)it->counter)) {
						it->counter=val;
					}
					break;
				case FT_INT64:
					val = fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1 && i==0) || ((gint64)val < (gint64)it->counter)) {
						it->counter=val;
					} 
					break;
				case FT_FLOAT:
					float_val=(gfloat)fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1 && i==0) || (float_val < it->float_counter)) {
						it->float_counter=float_val;
					}
					break;
				case FT_DOUBLE:
					double_val=fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
					if((it->frames==1 && i==0) || (double_val < it->double_counter)) {
						it->double_counter=double_val;
					} 
					break;
				case FT_RELATIVE_TIME:
					new_time = (nstime_t *)fvalue_get(&((field_info *)gp->pdata[i])->value);
					val = (guint64)new_time->secs * NANOSECS_PER_SEC + new_time->nsecs;
					if((it->frames==1 && i==0) || (val < it->counter)) {
						it->counter=val;
					}
					break;
				}
			}
		}
		break;
	case CALC_TYPE_MAX:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			guint64 val;
			gfloat float_val;
			gdouble double_val;

			ftype=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				switch(ftype){
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					val = fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);
					if(val > it->counter)
						it->counter=val;
					break;
				case FT_UINT64:
					val = fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					if(val > it->counter) 
						it->counter=val;
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val = fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
					if((gint32)val > (gint32)it->counter) 
						it->counter=val;
					break;
				case FT_INT64:
					val = fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					if ((gint64)val > (gint64)it->counter) 
						it->counter=val;
					break;
				case FT_FLOAT:
					float_val = (gfloat)fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
					if(float_val > it->float_counter)
                        it->float_counter=float_val;
					break;
				case FT_DOUBLE:
					double_val = fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
					if(double_val > it->double_counter)
                        it->double_counter=double_val;
					break;
				case FT_RELATIVE_TIME:
					new_time = (nstime_t *)fvalue_get(&((field_info *)gp->pdata[i])->value);
					val = (guint64)((new_time->secs * NANOSECS_PER_SEC) + new_time->nsecs);
					if (val>it->counter)
						it->counter=val;
                    break;
				}
			}
		}
		break;
	case CALC_TYPE_AVG:
		gp=proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if(gp){
			guint64 val;
		
			ftype=proto_registrar_get_ftype(it->hf_index);
			for(i=0;i<gp->len;i++){
				it->num++;
				switch(ftype) {
				case FT_UINT8:
				case FT_UINT16:
				case FT_UINT24:
				case FT_UINT32:
					val = fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);
					it->counter += val;
					break;
				case FT_UINT64:
				case FT_INT64:
					val = fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
					it->counter += val;
					break;
				case FT_INT8:
				case FT_INT16:
				case FT_INT24:
				case FT_INT32:
					val = fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
					it->counter += val;
					break;
				case FT_FLOAT:
					it->float_counter += (gfloat)fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_DOUBLE:
					it->double_counter += fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
					break;
				case FT_RELATIVE_TIME:
					new_time = (nstime_t *)fvalue_get(&((field_info *)gp->pdata[i])->value);
					val = (guint64)((new_time->secs * NANOSECS_PER_SEC) + new_time->nsecs);
					it->counter += val;
					break;
				}
			}
		}
		break;
	case CALC_TYPE_LOAD:
		gp = proto_get_finfo_ptr_array(edt->tree, it->hf_index);
		if (gp) {
			ftype = proto_registrar_get_ftype(it->hf_index);
			if (ftype != FT_RELATIVE_TIME) {
				fprintf(stderr,
					"\ntshark: LOAD() is only supported for relative-time fields such as smb.time\n");
				exit(10);
			}
			for(i=0;i<gp->len;i++){
				guint64 val;
				int tival;
				io_stat_item_t *pit;

				new_time = (nstime_t *)fvalue_get(&((field_info *)gp->pdata[i])->value);
				val = (guint64)((new_time->secs*1000000) + (new_time->nsecs/1000));
				tival = (int)(val % parent->interval);
				it->counter += tival;
				val -= tival;
				pit = it->prev;
				while (val > 0) {
					if (val < (guint64)parent->interval) {
						pit->counter += val;
						val = 0;
						break;
					}
					pit->counter += parent->interval;
					val -= parent->interval;
					pit = pit->prev;
				}
			}
		}
		break;
	}
  	/* Store the highest value for this item in order to determine the width of each stat column. 
    *  For real numbers we only need to know its magnitude (the value to the left of the decimal point
    *  so round it up before storing it as an integer in max_vals. For AVG of RELATIVE_TIME fields,
    *  calc the average, round it to the next second and store the seconds. For all other calc types
    *  of RELATIVE_TIME fields, store the counters without modification. 
    *  fields. */
    switch(it->calc_type) {
	    case CALC_TYPE_FRAMES:
	    case CALC_TYPE_FRAMES_AND_BYTES:
            parent->max_frame[it->colnum] = 
                MAX(parent->max_frame[it->colnum], it->frames);
            if (it->calc_type==CALC_TYPE_FRAMES_AND_BYTES)
                parent->max_vals[it->colnum] = 
                    MAX(parent->max_vals[it->colnum], it->counter);
	    
        case CALC_TYPE_BYTES:
	    case CALC_TYPE_COUNT:
	    case CALC_TYPE_LOAD:
            parent->max_vals[it->colnum] = MAX(parent->max_vals[it->colnum], it->counter);
            break;
	    case CALC_TYPE_SUM:
	    case CALC_TYPE_MIN:
	    case CALC_TYPE_MAX:
            ftype=proto_registrar_get_ftype(it->hf_index);
            switch(ftype) {
			    case FT_FLOAT:
				    parent->max_vals[it->colnum] = 
                        MAX(parent->max_vals[it->colnum], (guint64)(it->float_counter+0.5));
				    break;
			    case FT_DOUBLE:
				    parent->max_vals[it->colnum] = 
                        MAX(parent->max_vals[it->colnum],(guint64)(it->double_counter+0.5));
				    break;
			    case FT_RELATIVE_TIME:
                    parent->max_vals[it->colnum] = 
                        MAX(parent->max_vals[it->colnum], it->counter); 
				    break;			    
                default:
                    /* UINT16-64 and INT8-64 */
                    parent->max_vals[it->colnum] = 
                        MAX(parent->max_vals[it->colnum], it->counter);
                    break;
	        }
            break;
	    case CALC_TYPE_AVG:
            ftype=proto_registrar_get_ftype(it->hf_index);
            switch(ftype) {
			    case FT_FLOAT:
				    parent->max_vals[it->colnum] = 
                        MAX(parent->max_vals[it->colnum], (guint64)it->float_counter/it->num);
				    break;
			    case FT_DOUBLE:
				    parent->max_vals[it->colnum] = 
                        MAX(parent->max_vals[it->colnum],(guint64)it->double_counter/it->num);
				    break;
			    case FT_RELATIVE_TIME:
                    parent->max_vals[it->colnum] = 
                        MAX(parent->max_vals[it->colnum], ((it->counter/it->num) + 500000000) / NANOSECS_PER_SEC); 
				    break;
                default:
                    /* UINT16-64 and INT8-64 */
                    parent->max_vals[it->colnum] = 
                        MAX(parent->max_vals[it->colnum], it->counter/it->num);
                    break;
	        }
    }
    return TRUE;
}

static int 
magnitude (guint64 val, int max_w)
{
    int i, mag=0;

    for (i=0; i<max_w; i++) {
        mag++;
        if ((val /= 10)==0) 
            break;            
    }
    return(mag);
}

/*  
*  Print the calc_type_table[] function label centered in the column header. 
*/
static void
printcenter (const char *label, int lenval, int numpad)
{
    int lenlab = (int) strlen(label), len;
    const char spaces[]="      ", *spaces_ptr;

    len = (int) (strlen(spaces)) - (((lenval-lenlab) / 2) + numpad);
    if (len > 0 && len < 6) {
        spaces_ptr = &spaces[len];       
        if ((lenval-lenlab)%2==0) {
            printf("%s%s%s|", spaces_ptr, label, spaces_ptr);
        } else {
            printf("%s%s%s|", spaces_ptr-1, label, spaces_ptr);             
        }
    } else if (len > 0 && len <= 15) {
        printf("%s|", label);
    }
}

typedef struct {
    int fr;  /* Width of this FRAMES column sans padding and border chars */
    int val; /* Width of this non-FRAMES column sans padding and border chars */
} column_width;

static void
iostat_draw(void *arg)
{
	guint32 num;
    guint64 interval, duration, t, invl_end;
	int i, j, k, num_cols, num_rows, dv, dur_secs, dur_mag, invl_mag, invl_prec, tabrow_w,
	    borderlen, invl_col_w, numpad=1, namelen, len_filt, type, maxfltr_w, ftype;
    int fr_mag;    /* The magnitude of the max frame number in this column */
    int val_mag;   /* The magnitude of the max value in this column */
    gboolean last_row=FALSE;
    char *spaces, *spaces_s, *filler_s=NULL, **fmts, *fmt=NULL;
    const char *filter;
    static gchar dur_mag_s[3], invl_mag_s[3], invl_prec_s[3], fr_mag_s[3], val_mag_s[3], *invl_fmt, *full_fmt;
	io_stat_item_t *mit, **stat_cols, *item;
	io_stat_t *iot;
    column_width *col_w; 

    mit = (io_stat_item_t *)arg;
    iot = mit->parent;
    num_cols = iot->num_cols;
    col_w = (column_width *)g_malloc(sizeof(column_width) * num_cols);
    fmts = (char **)g_malloc(sizeof(char *) * num_cols);
    duration = (guint64)((cfile.elapsed_time.secs*1000000) + ((cfile.elapsed_time.nsecs+500)/1000));

    /* Store the pointer to each stat column */
    stat_cols = (io_stat_item_t **) g_malloc(sizeof(io_stat_item_t *) * num_cols);
    for (j=0; j<num_cols; j++)
        stat_cols[j] = &iot->items[j];

    /* The following prevents gross inaccuracies when the user specifies an interval that is greater
    *  than the capture duration. */
    if (iot->interval > duration || iot->interval==G_MAXINT32) {
        interval = duration;
        iot->interval = G_MAXINT32;
    } else {
        interval = iot->interval;
    }

    /* Calc the capture duration's magnitude (dur_mag) */
    dur_secs = (int)duration/1000000;
    dur_mag = magnitude((guint64)dur_secs, 5);
    g_snprintf(dur_mag_s, 3, "%u", dur_mag);  

    /* Calc the interval's magnitude */
    invl_mag = magnitude((guint64)interval/1000000, 5); 

    /* Set or get the interval precision */
    if (interval==duration) {
        /* 
        * An interval arg of 0 or an interval size exceeding the capture duration was specified.
        * Set the decimal precision of duration based on its magnitude. */
        if (dur_mag >= 2)
            invl_prec = 1;
        else if (dur_mag==1) 
            invl_prec = 3;
        else
            invl_prec = 6;

        borderlen = 30 + dur_mag + (invl_prec==0 ? 0 : invl_prec+1);
    } else {
        invl_prec = iot->invl_prec;
        borderlen = 24 + invl_mag + (invl_prec==0 ? 0 : invl_prec+1);
    }

    /* Round the duration according to invl_prec */
    dv=1000000;
    for (i=0; i<invl_prec; i++)
        dv /= 10;
    duration = duration + (5*(dv/10));
    if (iot->interval==G_MAXINT32) 
        interval = duration;

    /* Recalc the dur_mag in case rounding has increased its magnitude */
    dur_secs = (int)duration/1000000;
    dur_mag = magnitude((guint64)dur_secs, 5);

    /* Calc the width of the time interval column (incl borders and padding). */
    if (invl_prec==0) 
        invl_col_w = (2*dur_mag) + 8;
    else
        invl_col_w = (2*dur_mag) + (2*invl_prec) + 10;
    invl_col_w = MAX(invl_col_w, 12);
    borderlen = MAX(borderlen, invl_col_w);

    /* Calc the total width of each row in the stats table and build the printf format string for each
    *  column based on its field type, width, and name length.
    *  NOTE: The magnitude of all types including float and double are stored in iot->max_vals which
    *        is an *integer*. */
    tabrow_w = invl_col_w;
    for (j=0; j<num_cols; j++) {
        type = iot->items[j].calc_type;
        if (type==CALC_TYPE_FRAMES_AND_BYTES) {
            namelen = 5;
        } else {
            namelen = (int) strlen(calc_type_table[type].func_name);
        }
        if(type==CALC_TYPE_FRAMES
	    || type==CALC_TYPE_FRAMES_AND_BYTES) {

            fr_mag = magnitude(iot->max_frame[j], 15);
            fr_mag = MAX(6, fr_mag);
            col_w[j].fr = fr_mag;
            tabrow_w += col_w[j].fr + 3;
            g_snprintf(fr_mag_s, 3, "%u", fr_mag);

            if (type==CALC_TYPE_FRAMES) {
                fmt = g_strconcat(" %", fr_mag_s, "u |", NULL);                    
            } else { 
                /* CALC_TYPE_FRAMES_AND_BYTES 
                */
                val_mag = magnitude(iot->max_vals[j], 15);
                val_mag = MAX(5, val_mag);
                col_w[j].val = val_mag;
                tabrow_w += (col_w[j].val + 3);
                g_snprintf(val_mag_s, 3, "%u", val_mag);
                fmt = g_strconcat(" %", fr_mag_s, "u |", " %", val_mag_s, G_GINT64_MODIFIER, "u |", NULL);
            }
            if (fmt)
                fmts[j] = fmt;
            continue;
        }
        switch(type) {
        case CALC_TYPE_BYTES:
        case CALC_TYPE_COUNT:

            val_mag = magnitude(iot->max_vals[j], 15);
            val_mag = MAX(5, val_mag);
            col_w[j].val = val_mag;
            g_snprintf(val_mag_s, 3, "%u", val_mag);
            fmt = g_strconcat(" %", val_mag_s, G_GINT64_MODIFIER, "u |", NULL);
            break;
            
        default:
            ftype = proto_registrar_get_ftype(stat_cols[j]->hf_index);
            switch (ftype) {    
                case FT_FLOAT:
                case FT_DOUBLE:
                    val_mag = magnitude(iot->max_vals[j], 15);
                    g_snprintf(val_mag_s, 3, "%u", val_mag);
                    fmt = g_strconcat(" %", val_mag_s, ".6f |", NULL);
                    col_w[j].val = val_mag + 7;
                    break;
                case FT_RELATIVE_TIME:
                    /* Convert FT_RELATIVE_TIME field to seconds 
                    *  CALC_TYPE_LOAD was already converted in iostat_packet() ) */
                    if (type==CALC_TYPE_LOAD) {
                        iot->max_vals[j] /= interval;
                    } else {
                        iot->max_vals[j] = (iot->max_vals[j] + 500000000) / NANOSECS_PER_SEC;
                    }
                    val_mag = magnitude(iot->max_vals[j], 15);
                    g_snprintf(val_mag_s, 3, "%u", val_mag);
                    fmt = g_strconcat(" %", val_mag_s, "u.%06u |", NULL);
                    col_w[j].val = val_mag + 7;
                   break;	
                
                default:
                    val_mag = magnitude(iot->max_vals[j], 15);
                    val_mag = MAX(namelen, val_mag);
                    col_w[j].val = val_mag;
                    g_snprintf(val_mag_s, 3, "%u", val_mag);
                    
                    switch (ftype) {
                    case FT_UINT8:
                    case FT_UINT16:
		            case FT_UINT24:
		            case FT_UINT32:
		            case FT_UINT64:
                        fmt = g_strconcat(" %", val_mag_s, G_GINT64_MODIFIER, "u |", NULL);
                        break;            
                    case FT_INT8:
		            case FT_INT16:
		            case FT_INT24:
		            case FT_INT32:
		            case FT_INT64:
                        fmt = g_strconcat(" %", val_mag_s, G_GINT64_MODIFIER, "d |", NULL);
                        break;
                    }
            } /* End of ftype switch */
        } /* End of calc_type switch */
        tabrow_w += col_w[j].val + 3;
        if (fmt) 
            fmts[j] = fmt;
    } /* End of for loop (columns) */

    borderlen = MAX(borderlen, tabrow_w); 

    /* Calc the max width of the list of filters. */
    maxfltr_w = 0;
    for(j=0; j<num_cols; j++) {
        if (iot->filters[j]) {
            k = (int) (strlen(iot->filters[j]) + 11);
            maxfltr_w = MAX(maxfltr_w, k);
        } else {
            maxfltr_w = MAX(maxfltr_w, 26);
        }
    }
    /* The stat table is not wrapped (by tshark) but filter is wrapped at the width of the stats table
    *  (which currently = borderlen); however, if the filter width exceeds the table width and the
    *  table width is less than 102 bytes, set borderlen to the lesser of the max filter width and 102.
    *  The filters will wrap at the lesser of borderlen-2 and the last space in the filter. 
    *  NOTE: 102 is the typical size of a user window when the font is fixed width (e.g., COURIER 10).
    *  XXX: A pref could be added to change the max width from the default size of 102. */
    if (maxfltr_w > borderlen && borderlen < 102)
            borderlen = MIN(maxfltr_w, 102);

    /* Prevent double right border by adding a space */
    if (borderlen-tabrow_w==1)
        borderlen++; 

    /* Display the top border */
    printf("\n");
    for (i=0; i<borderlen; i++)
	    printf("=");
    
    spaces = (char*) g_malloc(borderlen+1);
    for (i=0; i<borderlen; i++) 
        spaces[i] = ' ';
    spaces[borderlen] = '\0';
    
    spaces_s = &spaces[16];
    printf("\n| IO Statistics%s|\n", spaces_s);
    spaces_s = &spaces[2];
    printf("|%s|\n", spaces_s);
   
    g_snprintf(invl_mag_s, 3, "%u", invl_mag);
    if (invl_prec > 0) {
        g_snprintf(invl_prec_s, 3, "%u", invl_prec);  
        invl_fmt = g_strconcat("%", invl_mag_s, "u.%0", invl_prec_s, "u", NULL);            
        if (interval==duration) {
            full_fmt = g_strconcat("| Interval size: ", invl_fmt, " secs (dur)%s", NULL);
            spaces_s = &spaces[30+invl_mag+invl_prec];
        } else {
            full_fmt = g_strconcat("| Interval size: ", invl_fmt, " secs%s", NULL);
            spaces_s = &spaces[24+invl_mag+invl_prec];
        }
        printf(full_fmt, (guint32)interval/1000000,
                            (guint32)((interval%1000000)/dv), spaces_s);
    } else {
        invl_fmt = g_strconcat("%", invl_mag_s, "u", NULL);
        full_fmt = g_strconcat("| Interval size: ", invl_fmt, " secs%s", NULL);
        spaces_s = &spaces[23 + invl_mag];
        printf(full_fmt, (guint32)interval/1000000, spaces_s);
    }
    g_free(invl_fmt);
    g_free(full_fmt);

    if (invl_prec > 0) 
        invl_fmt = g_strconcat("%", dur_mag_s, "u.%0", invl_prec_s, "u", NULL);
    else 
        invl_fmt = g_strconcat("%", dur_mag_s, "u", NULL);
    
    /* Display the list of filters and their column numbers vertically */
    printf("|\n| Col");
    for(j=0; j<num_cols; j++){
        printf((j==0 ? "%2u: " : "|    %2u: "), j+1);
        if (!iot->filters[j] || (iot->filters[j]==0)) { 
            /* 
            * An empty (no filter) comma field was specified */
            spaces_s = &spaces[16 + 10];
            printf("Frames and bytes%s|\n", spaces_s);
        } else {
            filter = iot->filters[j];
            len_filt = (int) strlen(filter);
            
            /* If the width of the widest filter exceeds the width of the stat table, borderlen has
            *  been set to 102 bytes above and filters wider than 102 will wrap at 91 bytes. */
            if (len_filt+11 <= borderlen) {
                printf("%s", filter);
                if (len_filt+11 <= borderlen) {
                    spaces_s = &spaces[len_filt + 10];
                    printf("%s", spaces_s);
                }
                printf("|\n");
            } else {
                gchar *sfilter1, *sfilter2;
                const gchar *pos;
                gsize len;
                int next_start, max_w=borderlen-11;
                
                do {
                    if (len_filt > max_w) {
                        sfilter1 = g_strndup( (gchar *) filter, (gsize) max_w);
                        /* 
                        * Find the pos of the last space in sfilter1. If a space is found, set
                        * sfilter2 to the string prior to that space and print it; otherwise, wrap
                        * the filter at max_w. */
                        pos = g_strrstr(sfilter1, " ");
                        if (pos) {
                            len = (gsize)(pos-sfilter1);
                            next_start = (int) len+1;
                        } else {
                            len = (gsize) strlen(sfilter1);
                            next_start = (int)len;
                        }
                        sfilter2 = g_strndup(sfilter1, len);
                        printf("%s%s|\n", sfilter2, &spaces[len+10]);
                        g_free(sfilter1);
                        g_free(sfilter2);

                        printf("|        ");
                        filter = &filter[next_start];
                        len_filt = (int) strlen(filter);
                    } else {
                        printf("%s%s|\n", filter, &spaces[((int)strlen(filter))+10]);
                        break;
                    }
                } while (1); 
            }
        }
	}

    printf("|-");
	for(i=0;i<borderlen-3;i++){
		printf("-");
	}
	printf("|\n");

    /* Display spaces above "Interval (s)" label */
    spaces_s = &spaces[borderlen-(invl_col_w-2)];
    printf("|%s|", spaces_s);

    /* Display column number headers */
	for(j=0; j<num_cols; j++) {
        item = stat_cols[j];
		if(item->calc_type==CALC_TYPE_FRAMES_AND_BYTES)
            spaces_s = &spaces[borderlen - (col_w[j].fr + col_w[j].val)] - 3; 
        else if (item->calc_type==CALC_TYPE_FRAMES)
            spaces_s = &spaces[borderlen - col_w[j].fr]; 
        else
            spaces_s = &spaces[borderlen - col_w[j].val]; 

        printf("%-2u%s|", j+1, spaces_s);
	}
    if (tabrow_w < borderlen) {
        filler_s = &spaces[tabrow_w+1];
        printf("%s|", filler_s);
    }
    
	printf("\n| Interval");
    spaces_s = &spaces[borderlen-(invl_col_w-11)];
    printf("%s|", spaces_s);

    /* Display the stat label in each column */
    for(j=0; j<num_cols; j++) {
        type = stat_cols[j]->calc_type;
        if(type==CALC_TYPE_FRAMES) {
            printcenter (calc_type_table[type].func_name, col_w[j].fr, numpad);
        } else if (type==CALC_TYPE_FRAMES_AND_BYTES) {
            printcenter ("Frames", col_w[j].fr, numpad);
            printcenter ("Bytes", col_w[j].val, numpad);
        } else {
            printcenter (calc_type_table[type].func_name, col_w[j].val, numpad);
	    }
	}
    if (filler_s)
        printf("%s|", filler_s);
    printf("\n|-");

	for(i=0; i<tabrow_w-3; i++)
		printf("-");
    printf("|");

    if (tabrow_w < borderlen)
        printf("%s|", &spaces[tabrow_w+1]);

	printf("\n");
	t=0;
    full_fmt = g_strconcat("| ", invl_fmt, " <> ", invl_fmt, " |", NULL);
    num_rows = (int)(duration/interval) + (((duration%interval+500000)/1000000) > 0 ? 1 : 0);

    /* Display the table values.
    * The outer loop is for time interval rows and the inner loop is for stat column items.*/
    for (i=0; i<num_rows; i++) {

        if (i==num_rows-1)
            last_row = TRUE;

        /* Display the interval for this row */
        if (!last_row) {
            invl_end = t + interval;
        } else {
            invl_end = duration;
        }
        if (invl_prec==0) {
            printf(full_fmt, (guint32)(t/1000000),
                             (guint32)(invl_end/1000000));
        } else {
            printf(full_fmt, (guint32)(t/1000000),
                             (guint32)(t%1000000) / dv,
                             (guint32) (invl_end/1000000),
                             (guint32)((invl_end%1000000) / dv));
        }

        /* Display all the stat values in this row */
        for (j=0; j<num_cols; j++) {
            /*
            * Point to the list for this stat (column). */
            item = stat_cols[j];
            /* 
            * Point to the item in the current row (time interval i) within this list. */            
            for (k=0; k<i; k++)
                if (item && item->next)
                    item = item->next;
                else
                    item = NULL;
            fmt = fmts[j];

            if (item) {
                switch(item->calc_type) {
                    case CALC_TYPE_FRAMES:
                        printf(fmt, item->frames);
                        break;
                    case CALC_TYPE_BYTES:
			        case CALC_TYPE_COUNT:
                        printf(fmt, item->counter);
                        break;
                    case CALC_TYPE_FRAMES_AND_BYTES:
                        printf(fmt, item->frames, item->counter);
                        break;

                    case CALC_TYPE_SUM:
			        case CALC_TYPE_MIN:
			        case CALC_TYPE_MAX:
                        ftype = proto_registrar_get_ftype(stat_cols[j]->hf_index);
				        switch(ftype){
				        case FT_FLOAT:
					        printf(fmt, item->float_counter);
					        break;
				        case FT_DOUBLE:
					        printf(fmt, item->double_counter);
					        break;
				        case FT_RELATIVE_TIME:
					        item->counter = (item->counter + 500) / 1000;
					        printf(fmt, (int)(item->counter/1000000), (int)(item->counter%1000000));
					        break;
                        default:
                            printf(fmt, item->counter);
					        break;
				        }
				        break;

			        case CALC_TYPE_AVG:
                        num = item->num;
				        if(num==0)
					        num=1;
                        ftype = proto_registrar_get_ftype(stat_cols[j]->hf_index);
				        switch(ftype){
				        case FT_FLOAT:
					        printf(fmt, item->float_counter/num);
					        break;
				        case FT_DOUBLE:
					        printf(fmt, item->double_counter/num);
					        break;
				        case FT_RELATIVE_TIME:
					        item->counter = ((item->counter/num) + 500) / 1000;
					        printf(fmt,
						        (int)(item->counter/1000000), (int)(item->counter%1000000));
					        break;
                        default:
                            printf(fmt, item->counter/num);
					        break;
				        }
				        break;

			        case CALC_TYPE_LOAD:
                        ftype = proto_registrar_get_ftype(stat_cols[j]->hf_index);
				        switch(ftype){
				        case FT_RELATIVE_TIME:
                            if (!last_row) {
                                printf(fmt,
                                    (int) (item->counter/interval), 
                                    (int)((item->counter%interval)*1000000 / interval));                        
                            } else {
                                printf(fmt,
                                    (int) (item->counter/(invl_end-t)),
                                    (int)((item->counter%(invl_end-t))*1000000 / (invl_end-t)));
                            }
					        break;
				        }
				        break;
			    }
                if (last_row)
                    if (fmt)
                        g_free(fmt);

		    } else {
                printf(fmt, (guint64)0);
            }
        }
        if (filler_s)
            printf("%s|", filler_s);
        printf("\n");
        t += interval;
       
    }
	for(i=0;i<borderlen;i++){
		printf("=");
	}
    printf("\n");
    g_free(invl_fmt);
    g_free(col_w);
    g_free(full_fmt);
    g_free(spaces);
}


static void
register_io_tap(io_stat_t *io, int i, const char *filter)
{
	GString *error_string;
	const char *flt;
	int j;
	size_t namelen;
	const char *p, *parenp;
	char *field;
	header_field_info *hfi;

	io->items[i].prev=&io->items[i];
	io->items[i].next=NULL;
	io->items[i].parent=io;
	io->items[i].time=0;
	io->items[i].calc_type=CALC_TYPE_FRAMES_AND_BYTES;
	io->items[i].frames=0;
	io->items[i].counter=0;
	io->items[i].num=0;

	io->filters[i]=filter;
	flt=filter;

	field=NULL;
	hfi=NULL;
	for(j=0; calc_type_table[j].func_name; j++){
		namelen=strlen(calc_type_table[j].func_name);
		if(filter && strncmp(filter, calc_type_table[j].func_name, namelen) == 0) {
			io->items[i].calc_type=calc_type_table[j].calc_type;
            io->items[i].colnum = i;
			if(*(filter+namelen)=='(') {
				p=filter+namelen+1;
				parenp=strchr(p, ')');
				if(!parenp){
					fprintf(stderr, 
                        "\ntshark: Closing parenthesis missing from calculated expression.\n");
					exit(10);
				}

				if(io->items[i].calc_type==CALC_TYPE_FRAMES || io->items[i].calc_type==CALC_TYPE_BYTES){
					if(parenp!=p) {
						fprintf(stderr, 
                            "\ntshark: %s does not require or allow a field name within the parens.\n",
							calc_type_table[j].func_name);
						exit(10);
					}
				} else {
					if(parenp==p) {
							/* bail out if a field name was not specified */
							fprintf(stderr, "\ntshark: You didn't specify a field name for %s(*).\n",
								calc_type_table[j].func_name);
							exit(10);
					}
				}

				field = (char *) g_malloc(parenp-p+1);
				memcpy(field, p, parenp-p);
				field[parenp-p] = '\0';
				flt=parenp + 1;
				if (io->items[i].calc_type==CALC_TYPE_FRAMES || io->items[i].calc_type==CALC_TYPE_BYTES)
					break;
				hfi=proto_registrar_get_byname(field);
				if(!hfi){
					fprintf(stderr, "\ntshark: There is no field named '%s'.\n",
						field);
					g_free(field);
					exit(10);
				}

				io->items[i].hf_index=hfi->id;
				break;
			}
		} else {
			if (io->items[i].calc_type==CALC_TYPE_FRAMES || io->items[i].calc_type==CALC_TYPE_BYTES)
				flt="";
            io->items[i].colnum = i;
		}
	}
	if(hfi && !(io->items[i].calc_type==CALC_TYPE_BYTES ||
			    io->items[i].calc_type==CALC_TYPE_FRAMES ||
			    io->items[i].calc_type==CALC_TYPE_FRAMES_AND_BYTES)){
		/* check that the type is compatible */
		switch(hfi->type){
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_UINT64:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
		case FT_INT64:
			/* these types support all calculations */
			break;
		case FT_FLOAT:
		case FT_DOUBLE:
			/* these types only support SUM, COUNT, MAX, MIN, AVG */
			switch(io->items[i].calc_type){
			case CALC_TYPE_SUM:
			case CALC_TYPE_COUNT:
			case CALC_TYPE_MAX:
			case CALC_TYPE_MIN:
			case CALC_TYPE_AVG:
				break;
			default:
				fprintf(stderr,
					"\ntshark: %s is a float field, so %s(*) calculations are not supported on it.",
					field,
					calc_type_table[j].func_name);
				exit(10);
			}
			break;
		case FT_RELATIVE_TIME:
			/* this type only supports SUM, COUNT, MAX, MIN, AVG, LOAD */
			switch(io->items[i].calc_type){
			case CALC_TYPE_SUM:
			case CALC_TYPE_COUNT:
			case CALC_TYPE_MAX:
			case CALC_TYPE_MIN:
			case CALC_TYPE_AVG:
			case CALC_TYPE_LOAD:
				break;
			default:
				fprintf(stderr,
					"\ntshark: %s is a relative-time field, so %s(*) calculations are not supported on it.",
				    field,
				    calc_type_table[j].func_name);
				exit(10);
			}
			break;
		default:
			/*
			 * XXX - support all operations on floating-point
			 * numbers?
			 */
			if(io->items[i].calc_type!=CALC_TYPE_COUNT){
				fprintf(stderr,
					"\ntshark: %s doesn't have integral values, so %s(*) "
                    "calculations are not supported on it.\n",
				    field,
				    calc_type_table[j].func_name);
				exit(10);
			}
			break;
		}
		g_free(field);
	}

	error_string=register_tap_listener("frame", &io->items[i], flt, TL_REQUIRES_PROTO_TREE, NULL,
                                       iostat_packet, i?NULL:iostat_draw);
	if(error_string){
		g_free(io->items);
		g_free(io);
		fprintf(stderr, "\ntshark: Couldn't register io,stat tap: %s\n",
		    error_string->str);
		g_string_free(error_string, TRUE);
		exit(1);
	}
}

static void
iostat_init(const char *optarg, void* userdata _U_)
{
	gdouble interval_float;
	guint32 idx=0, i;
	io_stat_t *io;
    const gchar *filters=NULL, *str, *pos;

	if (sscanf(optarg, "io,stat,%lf,%n", &interval_float, (int *)&idx)==0) {
		fprintf(stderr, "\ntshark: invalid \"-z io,stat,<interval>[,<filter>]\" argument\n");
		exit(1);
	}
	
    io = (io_stat_t *) g_malloc(sizeof(io_stat_t));

	/* If interval is 0, calculate statistics over the whole file by setting the interval to
    *  G_MAXINT32 */
	if (interval_float==0) {
		io->interval = G_MAXINT32;
        io->invl_prec = 0;
	} else {
		/* Set interval to the number of us rounded to the nearest integer */
		io->interval = (gint64)(interval_float*1000000.0+0.5);
        /*
        * Determine what interval precision the user has specified */
        io->invl_prec = 6;
        for (i=10; i<10000000; i*=10) { 
            if (io->interval%i > 0)
                break;
            io->invl_prec--;
        }
	}
    if (io->interval < 1){
		fprintf(stderr,
			"\ntshark: \"-z\" interval must be >=0.000001 seconds or \"0\" for the entire capture duration.\n");
		exit(10);
	}

    /* Find how many ',' separated filters we have */
    io->num_cols = 1;

    if (idx) {
        filters = optarg + idx;
        if (strlen(filters) > 0 ) {
            str = filters;
	        while((str = strchr(str, ','))) {
		        io->num_cols++;
		        str++;
            }
        }
	} else {
		filters=NULL;
	}

	io->items = (io_stat_item_t *) g_malloc(sizeof(io_stat_item_t) * io->num_cols);
	io->filters = g_malloc(sizeof(char *) * io->num_cols);
    io->max_vals = (guint64 *) g_malloc(sizeof(guint64) * io->num_cols);
    io->max_frame = (guint32 *) g_malloc(sizeof(guint32) * io->num_cols);

    for (i=0; i<io->num_cols; i++) {
        io->max_vals[i] = 0;
        io->max_frame[i] = 0;
    } 

    /* Register a tap listener for each filter */
    if((!filters) || (filters[0]==0)) {
        register_io_tap(io, 0, NULL);
    } else {
        gchar *filter;
		i = 0;
		str = filters;
		do {
			pos = (gchar*) strchr(str, ',');
			if(pos==str){
				register_io_tap(io, i, NULL);
			} else if (pos==NULL) {
				str = (char*) g_strstrip((gchar*)str);
                filter = g_strdup((gchar*) str);
                if (*filter)
				    register_io_tap(io, i, filter);
                else
                    register_io_tap(io, i, NULL);
			} else {
				filter = g_malloc((pos-str)+1);
				g_strlcpy( filter, str, (gsize) ((pos-str)+1));
                filter = g_strstrip(filter);
                register_io_tap(io, i, (char *) filter);
			}
			str = pos+1;
			i++;
		} while(pos);
	}
}

void
register_tap_listener_iostat(void)
{
	register_stat_cmd_arg("io,stat,", iostat_init, NULL);
}
