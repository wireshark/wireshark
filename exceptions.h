#ifndef __EXCEPTIONS_H__
#define __EXCEPTIONS_H__

#ifndef XCEPT_H
#include "except.h"
#endif

/* Ethereal has only one exception group, to make these macros simple */
#define XCEPT_GROUP_ETHEREAL 1

/* Ethereal's exceptions */
#define BoundsError		1	/* Index is out of range */

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
	int caught = 0; \
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
		caught = 1;
		/* user's code goes here */


#define CATCH_ALL \
	} \
	else { \
		caught = 1;
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

#define CLEANUP_CB_PUSH(x,y)		except_cleanup_push((x),(y)
#define CLEANUP_CB_POP			except_cleanup_push(0)
#define CLEANUP_CB_CALL_AND_POP		except_cleanup_push(1)

#endif /* __EXCEPTIONS_H__ */
