#ifndef __EXCEPTIONS_H__
#define __EXCEPTIONS_H__

#ifndef XCEPT_H
#include "except.h"
#endif

/* Ethereal has only one exception group, to make these macros simple */
#define XCEPT_GROUP_ETHEREAL 1

/* Ethereal's exceptions */
#define BoundsError		1	/* Index is out of range */
#define ReportedBoundsError	2	/* Index is beyond reported length (not cap_len) */
#define TypeError		3	/* During dfilter parsing */

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
 * 	x = setjmp()
 * 	if (x == 0) {
 * 		<TRY code>
 * 	}
 * 	else if (x == 1) {
 * 		<CATCH(1) code>
 * 	}
 * 	else if (x == 2) {
 * 		<CATCH(2) code>
 * 	}
 * 	else if (x == 3 || x == 4) {
 * 		<CATCH2(3,4) code>
 * 	}
 * 	else {
 * 		<CATCH_ALL code> {
 * 	}
 * 	<FINALLY code>
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



#define TRY \
{\
	except_t *exc; \
	static const except_id_t catch_spec[] = { \
		{ XCEPT_GROUP_ETHEREAL, XCEPT_CODE_ANY } }; \
	except_try_push(catch_spec, 1, &exc); \
	if (exc == 0) { \
		/* user's code goes here */

#define ENDTRY \
	} \
	except_try_pop();\
}

#define CATCH(x) \
	} \
	else if (exc->except_id.except_code == (x)) { \
		/* user's code goes here */

#define CATCH2(x,y) \
	} \
	else if (exc->except_id.except_code == (x) || exc->except_id.except_code == (y)) { \
		/* user's code goes here */

#define CATCH_ALL \
	} \
	else { \
		/* user's code goes here */

#define FINALLY \
	} \
	{ \
		/* user's code goes here */

#define THROW(x) \
	except_throw(XCEPT_GROUP_ETHEREAL, (x), "XCEPT_GROUP_ETHEREAL")

#define THROW_MESSAGE(x, y) \
	except_throw(XCEPT_GROUP_ETHEREAL, (x), (y))

#define GET_MESSAGE			except_message(exc)

#define RETHROW				except_rethrow(exc)

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
