/* Standalone program to test functionality of exceptions.
 *
 * $Id$
 *
 * Copyright (c) 2004 MX Telecom Ltd. <richardv@mxtelecom.com>
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
 *
 */

#include <stdio.h>
#include <glib.h>
#include <config.h>
#include "exceptions.h"

gboolean failed = FALSE;

void
run_tests(void)
{
    volatile unsigned int ex_thrown, finally_called;

    /* check that the right catch, and the finally, are called, on exception */
    ex_thrown = finally_called = 0;
    TRY {
        THROW(BoundsError);
    }
    CATCH(BoundsError) {
        ex_thrown++;
    }
    CATCH(ReportedBoundsError) {
        printf("01: Caught wrong exception: ReportedBoundsError\n");
        failed = TRUE;
    }
    CATCH_ALL {
        printf("01: Caught wrong exception: %lu\n", exc->except_id.except_code);
        failed = TRUE;
    }
    FINALLY {
        finally_called ++;
    }
    ENDTRY;

    if (ex_thrown != 1) {
        printf("01: %u BoundsErrors (not 1) on caught exception\n", ex_thrown);
        failed = TRUE;
    }

    if (finally_called != 1) {
        printf("01: FINALLY called %u times (not 1) on caught exception\n", finally_called);
        failed = TRUE;
    }


    /* check that no catch at all is called when there is no exn */
    ex_thrown = finally_called = 0;
    TRY {
    }
    CATCH(BoundsError) {
        printf("02: Caught wrong exception: BoundsError\n");
        failed = TRUE;
    }
    CATCH(ReportedBoundsError) {
        printf("02: Caught wrong exception: ReportedBoundsError\n");
        failed = TRUE;
    }
    CATCH_ALL {
        printf("02: Caught wrong exception: %lu\n", exc->except_id.except_code);
        failed = TRUE;
    }
    FINALLY {
        finally_called ++;
    }
    ENDTRY;

    if (finally_called != 1) {
        printf("02: FINALLY called %u times (not 1) on no exception\n", finally_called);
        failed = TRUE;
    }


    /* check that finally is called on an uncaught exception */
    ex_thrown = finally_called = 0;
    TRY {
        TRY {
            THROW(BoundsError);
        }
        FINALLY {
            finally_called ++;
        }
        ENDTRY;
    }
    CATCH(BoundsError) {
        ex_thrown++;
    }
    ENDTRY;

    if (finally_called != 1) {
        printf("03: FINALLY called %u times (not 1) on uncaught exception\n", finally_called);
        failed = TRUE;
    }

    if (ex_thrown != 1) {
        printf("03: %u BoundsErrors (not 1) on uncaught exception\n", ex_thrown);
        failed = TRUE;
    }


    /* check that finally is called on an rethrown exception */
    ex_thrown = finally_called = 0;
    TRY {
        TRY {
            THROW(BoundsError);
        }
        CATCH_ALL {
            ex_thrown += 10;
            RETHROW;
        }
        FINALLY {
            finally_called += 10;
        }
        ENDTRY;
    }
    CATCH(BoundsError) {
        ex_thrown ++;
    }
    FINALLY {
        finally_called ++;
    }
    ENDTRY;

    if (finally_called != 11) {
        printf("04: finally_called = %u (not 11) on rethrown exception\n", finally_called);
        failed = TRUE;
    }

    if (ex_thrown != 11) {
        printf("04: %u BoundsErrors (not 11) on rethrown exception\n", ex_thrown);
        failed = TRUE;
    }


    /* check that finally is called on an exception thrown from a CATCH block */
    ex_thrown = finally_called = 0;
    TRY {
        TRY {
            THROW(BoundsError);
        }
        CATCH_ALL {
            if(ex_thrown > 0) {
                printf("05: Looping exception\n");
                failed = TRUE;
            } else {
                ex_thrown += 10;
                THROW(BoundsError);
            }
        }
        FINALLY {
            finally_called += 10;
        }
        ENDTRY;
    }
    CATCH(BoundsError) {
        ex_thrown ++;
    }
    FINALLY {
        finally_called ++;
    }
    ENDTRY;

    if (finally_called != 11) {
        printf("05: finally_called = %u (not 11) on exception thrown from CATCH\n", finally_called);
        failed = TRUE;
    }

    if (ex_thrown != 11) {
        printf("05: %u BoundsErrors (not 11) on exception thrown from CATCH\n", ex_thrown);
        failed = TRUE;
    }

    if(failed == FALSE )
        printf("success\n");
}

int main(void)
{
    except_init();
    run_tests();
    except_deinit();
    exit(failed?1:0);
}
