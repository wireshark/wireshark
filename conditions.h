/* conditions.h
 * Header for condition handler.
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

#ifndef CONDITIONS_H
#define CONDITIONS_H

#include <stdarg.h>

#include <glib.h>

/* forward declaration for type 'condition' */
typedef struct condition condition;

/* condition evaluation handler type */
typedef gboolean (*_cnd_eval)(condition *, va_list);

/* condition reset handler type */
typedef void (*_cnd_reset)(condition *);

/* condition class constructor type */
typedef condition *(*_cnd_constr)(condition *, va_list);

/* condition class destructor type */
typedef void (*_cnd_destr)(condition *);

/*
 * Conditions must be created with this function. They can be created for
 * registered classes only.
 *
 * parameter: const char * - Identification of a registered condition class.
 *            ...          - Any number of class specific initial values.
 * returns:   Pointer to a initialized condition of the particular class on
 *            success or NULL on failure.
 */
condition *cnd_new(const char *, ...);

/*
 * Conditions must be deleted with this function when not used anymore.
 *
 * parameter: condition * - Pointer to a condition created with 'cnd_new()'.
 * returns:   -
 */
void cnd_delete(condition *);

/*
 * Call this function to check whether or not a particular condition is true.
 *
 * parameter: condition * - Pointer to an initialized condition.
 *            ...         - Any number of condition specific arguments.
 * returns:   TRUE  - Condition is true.
 *            FALSE - Condition is false.
 */
gboolean cnd_eval(condition *, ...);

/*
 * Call this function to reset this condition to its initial state, i.e. the
 * state it was in right after creation.
 *
 * parameter: condition * - Pointer to an initialized condition.
 * returns:   -
 */
void cnd_reset(condition *);

/*
 * Register a new conditon class.
 * New conditions of this class can be created by calling 'cnd_new()' and
 * supplying the appropriate class id.
 *
 * parameter: const char * - The class id.
 *            _cnd_constr  - User supplied constructor function for this
 *                           class.
 *            _cnd_destr   - User supplied destructor function for this
 *                           class.
 *            _cnd_eval    - User supplied evaluation handler function for this
                             class.
 *            _cnd_reset   - User supplied reset handler for this class.
 * returns:   TRUE  - Success.
 *            FALSE - Failure.
 */
gboolean cnd_register_class(const char *,
                            _cnd_constr,
                            _cnd_destr,
                            _cnd_eval,
                            _cnd_reset);

/*
 * Unregister a previously registered conditon class. After unregistration
 * of a class it is no longer possible to create conditions of this kind by
 * calling 'cnd_new()'.
 *
 * parameter: const char * - An identification for this condition class.
 * returns:   -
 */
void cnd_unregister_class(const char *);

/*
 * This function returns the user data of the condition.
 *
 * parameter: condition * - Pointer to an initialized condition.
 * returns:   void *      - Pointer to user data of this condition.
 */
void* cnd_get_user_data(condition*);

/*
 * This function sets the user data of the condition.
 *
 * parameter: condition * - Pointer to an initialized condition.
 *            void *      - Pointer to user specified data structure.
 * returns:   -
 */
void cnd_set_user_data(condition *, void *);

#endif /* CONDITIONS_H */
