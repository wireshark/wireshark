/* Standalone program to test functionality of exceptions.
 *
 * Copyright (c) 2004 MX Telecom Ltd. <richardv@mxtelecom.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include <config.h>

#include <stdio.h>
#include <glib.h>
#include "exceptions.h"

bool failed;

static void
finally_called_uncaught_exception(volatile unsigned int* called)
{
    TRY {
        THROW(BoundsError);
    }
    FINALLY {
        (*called)++;
    }
    ENDTRY;
}

static void
finally_called_rethrown_exception(volatile unsigned int* thrown, volatile unsigned int* called)
{
    TRY {
        THROW(BoundsError);
    }
    CATCH_ALL {
        (*thrown) += 10;
        RETHROW;
    }
    FINALLY {
        (*called) += 10;
    }
    ENDTRY;
}

static void
finally_called_exception_from_catch(volatile unsigned int* thrown, volatile unsigned int* called)
{
    TRY {
        THROW(BoundsError);
    }
    CATCH_ALL {
        if((*thrown) > 0) {
            printf("05: Looping exception\n");
            failed = true;
        } else {
            (*thrown) += 10;
            THROW(BoundsError);
        }
    }
    FINALLY {
        (*called) += 10;
    }
    ENDTRY;
}

static void
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
    CATCH(FragmentBoundsError) {
        printf("01: Caught wrong exception: FragmentBoundsError\n");
        failed = true;
    }
    CATCH(ReportedBoundsError) {
        printf("01: Caught wrong exception: ReportedBoundsError\n");
        failed = true;
    }
    CATCH_ALL {
        printf("01: Caught wrong exception: %lu\n", exc->except_id.except_code);
        failed = true;
    }
    FINALLY {
        finally_called ++;
    }
    ENDTRY;

    if (ex_thrown != 1) {
        printf("01: %u BoundsErrors (not 1) on caught exception\n", ex_thrown);
        failed = true;
    }

    if (finally_called != 1) {
        printf("01: FINALLY called %u times (not 1) on caught exception\n", finally_called);
        failed = true;
    }


    /* check that no catch at all is called when there is no exn */
    ex_thrown = finally_called = 0;
    TRY {
    }
    CATCH(BoundsError) {
        printf("02: Caught wrong exception: BoundsError\n");
        failed = true;
    }
    CATCH(FragmentBoundsError) {
        printf("02: Caught wrong exception: FragmentBoundsError\n");
        failed = true;
    }
    CATCH(ReportedBoundsError) {
        printf("02: Caught wrong exception: ReportedBoundsError\n");
        failed = true;
    }
    CATCH_ALL {
        printf("02: Caught wrong exception: %lu\n", exc->except_id.except_code);
        failed = true;
    }
    FINALLY {
        finally_called ++;
    }
    ENDTRY;

    if (finally_called != 1) {
        printf("02: FINALLY called %u times (not 1) on no exception\n", finally_called);
        failed = true;
    }

    /* check that finally is called on an uncaught exception */
    ex_thrown = finally_called = 0;
    TRY {
        finally_called_uncaught_exception(&finally_called);
    }
    CATCH(BoundsError) {
        ex_thrown++;
    }
    ENDTRY;

    if (finally_called != 1) {
        printf("03: FINALLY called %u times (not 1) on uncaught exception\n", finally_called);
        failed = true;
    }

    if (ex_thrown != 1) {
        printf("03: %u BoundsErrors (not 1) on uncaught exception\n", ex_thrown);
        failed = true;
    }


    /* check that finally is called on an rethrown exception */
    ex_thrown = finally_called = 0;
    TRY {
        finally_called_rethrown_exception(&ex_thrown, &finally_called);
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
        failed = true;
    }

    if (ex_thrown != 11) {
        printf("04: %u BoundsErrors (not 11) on rethrown exception\n", ex_thrown);
        failed = true;
    }


    /* check that finally is called on an exception thrown from a CATCH block */
    ex_thrown = finally_called = 0;
    TRY {
        finally_called_exception_from_catch(&ex_thrown, &finally_called);
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
        failed = true;
    }

    if (ex_thrown != 11) {
        printf("05: %u BoundsErrors (not 11) on exception thrown from CATCH\n", ex_thrown);
        failed = true;
    }

    if(failed == false )
        printf("success\n");
}

int main(void)
{
    except_init();
    run_tests();
    except_deinit();
    exit(failed?1:0);
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
