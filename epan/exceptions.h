#ifndef __EXCEPTIONS_H__
#define __EXCEPTIONS_H__

#ifndef XCEPT_H
#include "except.h"
#endif

/* Ethereal has only one exception group, to make these macros simple */
#define XCEPT_GROUP_ETHEREAL 1

/* Ethereal's exceptions */

/**
    Index is out of range.
    An attempt was made to read past the end of a buffer.
    This generally means that the capture was done with a "slice"
    length or "snapshot" length less than the maximum packet size,
    and a link-layer packet was cut short by that, so not all of the
    data in the link-layer packet was available.
**/
#define BoundsError		1	

/**
    Index is beyond reported length (not cap_len) 
    An attempt was made to read past the logical end of a buffer. This
    differs from a BoundsError in that the parent protocol established a
    limit past which this dissector should not process in the buffer and that
    limit was execeeded.
    This generally means that the packet is invalid, i.e. whatever
    code constructed the packet and put it on the wire didn't put enough
    data into it.  It is therefore currently reported as a "Malformed
    packet".
    However, it also happens in some cases where the packet was fragmented
    and the fragments weren't reassembled.  We need to add another length
    field to a tvbuff, so that "length of the packet from the link layer"
    and "length of the packet were it fully reassembled" are different,
    and going past the first of those without going past the second would
    throw a different exception, which would be reported as an "Unreassembled
    packet" rather than a "Malformed packet".
**/
#define ReportedBoundsError	2

/**
    During dfilter parsing 
**/
#define TypeError		3

/**
    A bug was detected in a dissector.

    DO NOT throw this with THROW(); that means that no details about
    the dissector error will be reported.  (Instead, the message will
    blame you for not providing details.)

    Instead, use the DISSECTOR_ASSERT(), etc. macros in epan/proto.h.
**/
#define DissectorError		4	

/**
    Index is out of range.
    An attempt was made to read past the end of a buffer.
    This error is specific to SCSI data transfers where for some CDBs
    it is normal that the data PDU might be short.
    I.e. ReportLuns initially called with allocation_length=8, just enough
    to get the "size" of lun list back after which the initiator will
    reissue the command with an allocation_length that is big enough.
**/
#define ScsiBoundsError		5	


/* Usage:
 *
 * TRY {
 * 	code;
 * }
 *
 * CATCH(exception) {
 * 	code;
 * }
 *
 * CATCH2(exception1, exception2) {
 * 	code;
 * }
 *
 * CATCH_ALL {
 * 	code;
 * }
 *
 * FINALLY {
 * 	code;
 * }
 *
 * ENDTRY;
 *
 * ********* Never use 'goto' or 'return' inside the TRY, CATCH, CATCH_ALL,
 * ********* or FINALLY blocks. Execution must proceed through ENDTRY before
 * ********* branching out.
 *
 * This is really something like:
 *
 * {
 * 	caught = FALSE:
 * 	x = setjmp();
 * 	if (x == 0) {
 * 		<TRY code>
 * 	}
 * 	if (!caught && x == 1) {
 * 		caught = TRUE;
 * 		<CATCH(1) code>
 * 	}
 * 	if (!caught && x == 2) {
 * 		caught = TRUE;
 * 		<CATCH(2) code>
 * 	}
 * 	if (!caught && (x == 3 || x == 4)) {
 * 		caught = TRUE;
 * 		<CATCH2(3,4) code>
 * 	}
 * 	if (!caught && x != 0) {
 *		caught = TRUE;
 * 		<CATCH_ALL code>
 * 	}
 * 	<FINALLY code>
 * 	if(!caught) {
 *      	RETHROW(x)
 * 	}
 * }<ENDTRY tag>
 *
 * All CATCH's must precede a CATCH_ALL.
 * FINALLY must occur after any CATCH or CATCH_ALL.
 * ENDTRY marks the end of the TRY code.
 * TRY and ENDTRY are the mandatory parts of a TRY block.
 * CATCH, CATCH_ALL, and FINALLY are all optional (although
 * you'll probably use at least one, otherwise why "TRY"?)
 *
 * GET_MESSAGE	returns string ptr to exception message
 * 		when exception is thrown via THROW_MESSAGE()
 *
 * To throw/raise an exception.
 *
 * THROW(exception)
 * RETHROW				rethrow the caught exception
 *
 * A cleanup callback is a function called in case an exception occurs
 * and is not caught. It should be used to free any dynamically-allocated data.
 * A pop or call_and_pop should occur at the same statement-nesting level
 * as the push.
 *
 * CLEANUP_CB_PUSH(func, data)
 * CLEANUP_CB_POP
 * CLEANUP_CB_CALL_AND_POP
 */

/* we do up to three passes through the bit of code after except_try_push(),
 * and except_state is used to keep track of where we are.
 */
#define EXCEPT_CAUGHT   1 /* exception has been caught, no need to rethrow at
                           * END_TRY */

#define EXCEPT_RETHROWN 2 /* the exception was rethrown from a CATCH
                           * block. Don't reenter the CATCH blocks, but do
                           * execute FINALLY and rethrow at END_TRY */

#define EXCEPT_FINALLY  4 /* we've entered the FINALLY block - don't allow
                           * RETHROW, and don't reenter FINALLY if a
                           * different exception is thrown */

#define TRY \
{\
	except_t *exc; \
	volatile int except_state = 0; \
	static const except_id_t catch_spec[] = { \
		{ XCEPT_GROUP_ETHEREAL, XCEPT_CODE_ANY } }; \
	except_try_push(catch_spec, 1, &exc); \
	                                               \
    	if(except_state & EXCEPT_CAUGHT)               \
            except_state |= EXCEPT_RETHROWN;           \
	except_state &= ~EXCEPT_CAUGHT;                \
	                                               \
	if (except_state == 0 && exc == 0)             \
		/* user's code goes here */

#define ENDTRY \
	/* rethrow the exception if necessary */ \
	if(!(except_state&EXCEPT_CAUGHT) && exc != 0)  \
	    except_rethrow(exc);                 \
	except_try_pop();\
}

/* the (except_state |= EXCEPT_CAUGHT) in the below is a way of setting
 * except_state before the user's code, without disrupting the user's code if
 * it's a one-liner.
 */
#define CATCH(x) \
	if (except_state == 0 && exc != 0 && exc->except_id.except_code == (x) && \
	    (except_state |= EXCEPT_CAUGHT))                                      \
		/* user's code goes here */

#define CATCH2(x,y) \
	if (except_state == 0 && exc != 0 && \
	    (exc->except_id.except_code == (x) || exc->except_id.except_code == (y)) && \
	    (except_state|=EXCEPT_CAUGHT))                                             \
		/* user's code goes here */

#define CATCH_ALL \
	if (except_state == 0 && exc != 0 && \
	    (except_state|=EXCEPT_CAUGHT))                                             \
		/* user's code goes here */


#define FINALLY \
	if( !(except_state & EXCEPT_FINALLY) && (except_state|=EXCEPT_FINALLY)) \
		/* user's code goes here */

#define THROW(x) \
	except_throw(XCEPT_GROUP_ETHEREAL, (x), NULL)

#define THROW_MESSAGE(x, y) \
	except_throw(XCEPT_GROUP_ETHEREAL, (x), (y))

#define GET_MESSAGE			except_message(exc)

#define RETHROW                                     \
    {                                               \
        /* check we're in a catch block */          \
        g_assert(except_state == EXCEPT_CAUGHT);    \
	/* we can't use except_rethrow here, as that pops a catch block \
	 * off the stack, and we don't want to do that, because we want to \
	 * excecute the FINALLY {} block first.     \
	 * except_throw doesn't provide an interface to rethrow an existing \
	 * exception; however, longjmping back to except_try_push() has the \
	 * desired effect.			    \
	 *					    \
	 * Note also that THROW and RETHROW should provide much the same \
	 * functionality in terms of which blocks to enter, so any messing \ 
	 * about with except_state in here would indicate that THROW is \
	 * doing the wrong thing.                   \
	 */					    \
        longjmp(except_ch.except_jmp,1);            \
    }

#define EXCEPT_CODE			except_code(exc)

/* Register cleanup functions in case an exception is thrown and not caught.
 * From the Kazlib documentation, with modifications for use with the
 * Ethereal-specific macros:
 *
 * CLEANUP_PUSH(func, arg)
 *
 *  The call to CLEANUP_PUSH shall be matched with a call to
 *  CLEANUP_CALL_AND_POP or CLEANUP_POP which must occur in the same
 *  statement block at the same level of nesting. This requirement allows
 *  an implementation to provide a CLEANUP_PUSH macro which opens up a
 *  statement block and a CLEANUP_POP which closes the statement block.
 *  The space for the registered pointers can then be efficiently
 *  allocated from automatic storage.
 *
 *  The CLEANUP_PUSH macro registers a cleanup handler that will be
 *  called if an exception subsequently occurs before the matching
 *  CLEANUP_[CALL_AND_]POP is executed, and is not intercepted and
 *  handled by a try-catch region that is nested between the two.
 *
 *  The first argument to CLEANUP_PUSH is a pointer to the cleanup
 *  handler, a function that returns nothing and takes a single
 *  argument of type void*. The second argument is a void* value that
 *  is registered along with the handler.  This value is what is passed
 *  to the registered handler, should it be called.
 *
 *  Cleanup handlers are called in the reverse order of their nesting:
 *  inner handlers are called before outer handlers.
 *
 *  The program shall not leave the cleanup region between
 *  the call to the macro CLEANUP_PUSH and the matching call to
 *  CLEANUP_[CALL_AND_]POP by means other than throwing an exception,
 *  or calling CLEANUP_[CALL_AND_]POP.
 *
 *  Within the call to the cleanup handler, it is possible that new
 *  exceptions may happen.  Such exceptions must be handled before the
 *  cleanup handler terminates. If the call to the cleanup handler is
 *  terminated by an exception, the behavior is undefined. The exception
 *  which triggered the cleanup is not yet caught; thus the program
 *  would be effectively trying to replace an exception with one that
 *  isn't in a well-defined state.
 *
 *
 * CLEANUP_POP and CLEANUP_CALL_AND_POP
 *
 *  A call to the CLEANUP_POP or CLEANUP_CALL_AND_POP macro shall match
 *  each call to CLEANUP_PUSH which shall be in the same statement block
 *  at the same nesting level.  It shall match the most recent such a
 *  call that is not matched by a previous CLEANUP_[CALL_AND_]POP at
 *  the same level.
 *
 *  These macros causes the registered cleanup handler to be removed. If
 *  CLEANUP_CALL_AND_POP is called, the cleanup handler is called.
 *  In that case, the registered context pointer is passed to the cleanup
 *  handler. If CLEANUP_POP is called, the cleanup handler is not called.
 *
 *  The program shall not leave the region between the call to the
 *  macro CLEANUP_PUSH and the matching call to CLEANUP_[CALL_AND_]POP
 *  other than by throwing an exception, or by executing the
 *  CLEANUP_CALL_AND_POP.
 *
 */


#define CLEANUP_PUSH(f,a)		except_cleanup_push((f),(a))
#define CLEANUP_POP			except_cleanup_pop(0)
#define CLEANUP_CALL_AND_POP		except_cleanup_pop(1)

#endif /* __EXCEPTIONS_H__ */
