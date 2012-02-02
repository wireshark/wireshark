/* capture_stop_conditions.c
 * Implementation for 'stop condition handler'.
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

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdarg.h>
#include "conditions.h"
#include "capture_stop_conditions.h"

/* predefined classes function prototypes */
static condition* _cnd_constr_timeout(condition*, va_list);
static void _cnd_destr_timeout(condition*);
static gboolean _cnd_eval_timeout(condition*, va_list);
static void _cnd_reset_timeout(condition*);

static condition* _cnd_constr_capturesize(condition*, va_list);
static void _cnd_destr_capturesize(condition*);
static gboolean _cnd_eval_capturesize(condition*, va_list);
static void _cnd_reset_capturesize(condition*);

void init_capture_stop_conditions(void){
  cnd_register_class(CND_CLASS_TIMEOUT,
                     _cnd_constr_timeout,
                     _cnd_destr_timeout,
                     _cnd_eval_timeout,
                     _cnd_reset_timeout);
  cnd_register_class(CND_CLASS_CAPTURESIZE,
                     _cnd_constr_capturesize,
                     _cnd_destr_capturesize,
                     _cnd_eval_capturesize,
                     _cnd_reset_capturesize);
} /* END init_capture_stop_conditions() */

void cleanup_capture_stop_conditions(void){
  cnd_unregister_class(CND_CLASS_TIMEOUT);
  cnd_unregister_class(CND_CLASS_CAPTURESIZE);
} /* END cleanup_capture_stop_conditions() */

/*****************************************************************************/
/* Predefined condition 'timeout'.                                           */

/* class id */
const char* CND_CLASS_TIMEOUT = "cnd_class_timeout";

/* structure that contains user supplied data for this condition */
typedef struct _cnd_timeout_dat{
  time_t start_time;
  gint32 timeout_s;
}cnd_timeout_dat;

/*
 * Constructs new condition for timeout check. This function is invoked by
 * 'cnd_new()' in order to perform class specific initialization.
 *
 * parameter: cnd - Pointer to condition passed by 'cnd_new()'.
 *            ap  - Pointer to user supplied arguments list for this
 *                  constructor.
 * returns:   Pointer to condition - Construction was successful.
 *            NULL                 - Construction failed.
 */
static condition* _cnd_constr_timeout(condition* cnd, va_list ap){
  cnd_timeout_dat *data = NULL;
  /* allocate memory */
  if((data = (cnd_timeout_dat*)g_malloc(sizeof(cnd_timeout_dat))) == NULL)
    return NULL;
  /* initialize user data */
  data->start_time = time(NULL);
  data->timeout_s = va_arg(ap, gint32);
  cnd_set_user_data(cnd, (void*)data);
  return cnd;
} /* END _cnd_constr_timeout() */

/*
 * Destroys condition for timeout check. This function is invoked by
 * 'cnd_delete()' in order to perform class specific clean up.
 *
 * parameter: cnd - Pointer to condition passed by 'cnd_delete()'.
 */
static void _cnd_destr_timeout(condition* cnd){
  /* free memory */
  g_free(cnd_get_user_data(cnd));
} /* END _cnd_destr_timeout() */

/*
 * Condition handler for timeout condition. This function is invoked by
 * 'cnd_eval()' in order to perform class specific condition checks.
 *
 * parameter: cnd - The inititalized timeout condition.
 *            ap  - Pointer to user supplied arguments list for this
 *                  handler.
 * returns:   TRUE  - Condition is true.
 *            FALSE - Condition is false.
 */
static gboolean _cnd_eval_timeout(condition* cnd, va_list ap _U_){
  cnd_timeout_dat* data = (cnd_timeout_dat*)cnd_get_user_data(cnd);
  gint32 elapsed_time;
  /* check timeout here */
  if(data->timeout_s == 0) return FALSE; /* 0 == infinite */
  elapsed_time = (gint32) (time(NULL) - data->start_time);
  if(elapsed_time >= data->timeout_s) return TRUE;
  return FALSE;
} /* END _cnd_eval_timeout()*/

/*
 * Call this function to reset this condition to its initial state, i.e. the
 * state it was in right after creation.
 *
 * parameter: cnd - Pointer to an initialized condition.
 */
static void _cnd_reset_timeout(condition *cnd){
  ((cnd_timeout_dat*)cnd_get_user_data(cnd))->start_time = time(NULL);
} /* END _cnd_reset_timeout() */


/*****************************************************************************/
/* Predefined condition 'max. capturesize'.                                  */

/* class id */
const char* CND_CLASS_CAPTURESIZE = "cnd_class_capturesize";

/* structure that contains user supplied data for this condition */
typedef struct _cnd_capturesize_dat{
  long max_capture_size;
}cnd_capturesize_dat;

/*
 * Constructs new condition for capturesize check. This function is invoked by
 * 'cnd_new()' in order to perform class specific initialization.
 *
 * parameter: cnd - Pointer to condition passed by 'cnd_new()'.
 *            ap  - Pointer to user supplied arguments list for this
 *                  constructor.
 * returns:   Pointer to condition - Construction was successful.
 *            NULL                 - Construction failed.
 */
static condition* _cnd_constr_capturesize(condition* cnd, va_list ap){
  cnd_capturesize_dat *data = NULL;
  /* allocate memory */
  if((data = (cnd_capturesize_dat*)g_malloc(sizeof(cnd_capturesize_dat))) == NULL)
    return NULL;
  /* initialize user data */
  data->max_capture_size = va_arg(ap, long);
  cnd_set_user_data(cnd, (void*)data);
  return cnd;
} /* END _cnd_constr_capturesize() */

/*
 * Destroys condition for capturesize check. This function is invoked by
 * 'cnd_delete()' in order to perform class specific clean up.
 *
 * parameter: cnd - Pointer to condition passed by 'cnd_delete()'.
 */
static void _cnd_destr_capturesize(condition* cnd){
  /* free memory */
  g_free(cnd_get_user_data(cnd));
} /* END _cnd_destr_capturesize() */

/*
 * Condition handler for capturesize condition. This function is invoked by
 * 'cnd_eval()' in order to perform class specific condition checks.
 *
 * parameter: cnd - The inititalized capturesize condition.
 *            ap  - Pointer to user supplied arguments list for this
 *                  handler.
 * returns:   TRUE  - Condition is true.
 *            FALSE - Condition is false.
 */
static gboolean _cnd_eval_capturesize(condition* cnd, va_list ap){
  cnd_capturesize_dat* data = (cnd_capturesize_dat*)cnd_get_user_data(cnd);
  /* check capturesize here */
  if(data->max_capture_size == 0) return FALSE; /* 0 == infinite */
  if(va_arg(ap, long) >= data->max_capture_size){
    return TRUE;
  }
  return FALSE;
} /* END _cnd_eval_capturesize() */

/*
 * Call this function to reset this condition to its initial state, i.e. the
 * state it was in right after creation.
 *
 * parameter: cnd - Pointer to an initialized condition.
 */
static void _cnd_reset_capturesize(condition *cnd _U_){
} /* END _cnd_reset_capturesize() */
