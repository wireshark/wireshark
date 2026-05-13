/*
 * Portable Exception Handling for ANSI C.
 * Copyright (C) 1999 Kaz Kylheku <kaz@ashi.footprints.net>
 *
 * Free Software License:
 *
 * All rights are reserved by the author, with the following exceptions:
 * Permission is granted to freely reproduce and distribute this software,
 * possibly in exchange for a fee, provided that this copyright notice appears
 * intact. Permission is also granted to adapt this software to produce
 * derivative works, as long as the modified versions carry this copyright
 * notice and additional notices stating that the work has been modified.
 * This source code may be translated into executable form and incorporated
 * into proprietary software; there is no requirement for such software to
 * contain a copyright notice related to this source.
 *
 */

/**
 * @file
 * Portable Exception Handling for ANSI C.<BR>
 * Modified to support throwing an exception with a null message pointer,
 * and to have the message not be const (as we generate messages with
 * "ws_strdup_printf()", which means they need to be freed; using
 * a null message means that we don't have to use a special string
 * for exceptions with no message, and don't have to worry about
 * not freeing that).
 */
#pragma once
#include <glib.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include "ws_symbol_export.h"
#include "ws_attributes.h"

#define XCEPT_GROUP_ANY 0
#define XCEPT_CODE_ANY  0
#define XCEPT_BAD_ALLOC 1

#ifdef __cplusplus
extern "C" {
#endif

enum { except_no_call, except_call };

typedef struct {
    unsigned long except_group;
    unsigned long except_code;
} except_id_t;

typedef struct {
    except_id_t volatile except_id;
    const char *volatile except_message;
    void *volatile except_dyndata;
} except_t;

struct except_cleanup {
    void (*except_func)(void *);
    void *except_context;
};

struct except_catch {
    const except_id_t *except_id;
    size_t except_size;
    except_t except_obj;
    jmp_buf except_jmp;
};

enum except_stacktype {
    XCEPT_CLEANUP, XCEPT_CATCHER
};

/**
 * @brief Represents a node in the exception handling stack.
 *
 * This structure is used to manage exception frames during execution.
 * Each node corresponds to either a catch or cleanup handler and links
 * to the next node in the stack.
 */
struct except_stacknode {
    struct except_stacknode *except_down; /**< Pointer to the next node in the exception stack. */
    enum except_stacktype except_type;    /**< Type of exception frame (e.g., catch or cleanup). */
    union {
        struct except_catch *except_catcher;   /**< Pointer to catch handler data. */
        struct except_cleanup *except_cleanup; /**< Pointer to cleanup handler data. */
    } except_info;
};

/* private functions made external so they can be used in macros */

/**
 * @brief Set up a cleanup handler for exception handling.
 */
WS_DLL_PUBLIC void except_setup_clean(struct except_stacknode *,
        struct except_cleanup *, void (*)(void *), void *);

/**
 * @brief Set up a try block for exception handling.
 */
WS_DLL_PUBLIC void except_setup_try(struct except_stacknode *,
        struct except_catch *, const except_id_t [], size_t);

/**
 * @brief Pop the top node from the exception stack.
 * @return struct except_stacknode* Pointer to the popped node from the exception stack.
 */
WS_DLL_PUBLIC struct except_stacknode *except_pop(void);

/* public interface functions */
/**
 * @brief Initialize the exception handling system.
 *
 * @return int 0 on success, -1 on failure.
 */
WS_DLL_PUBLIC int except_init(void);

/**
 * @brief Deinitialize the exception handling system.
 */
WS_DLL_PUBLIC void except_deinit(void);

/**
 * @brief Rethrow an exception.
 *
 * @param except Pointer to the exception object.
 */
WS_DLL_PUBLIC WS_NORETURN void except_rethrow(except_t * except);

/**
 * @brief Throw an exception with a message and optional data.
 * @param group The exception group identifier.
 * @param code The exception code identifier.
 * @param msg The message associated with the exception.
 */
WS_DLL_PUBLIC WS_NORETURN void except_throw(long group, long code, const char *msg);

/**
 * @brief Throw an exception with a detailed message and data.
 *
 * @param group The exception group identifier.
 * @param code The exception code.
 * @param msg The exception message.
 * @param data Additional data associated with the exception.
 */
WS_DLL_PUBLIC WS_NORETURN void except_throwd(long group, long code, const char *msg, void *data);

/**
 * @brief Throw an exception with a formatted message.
 *
 * @param group The exception group identifier.
 * @param code The exception code identifier.
 * @param fmt The format string for the exception message.
 * @param vl The variable argument list for the format string.
 */
WS_DLL_PUBLIC WS_NORETURN void except_vthrowf(long group, long code, const char *fmt, va_list vl);

/**
 * @brief Throws an exception with a formatted message.
 *
 * @param group The exception group.
 * @param code The exception code.
 * @param fmt The format string for the exception message.
 */
WS_DLL_PUBLIC WS_NORETURN void except_throwf(long group, long code, const char *fmt, ...)
    G_GNUC_PRINTF(3, 4);

/**
 * @brief Sets the unhandled exception catcher.
 * @param new_catcher The function to be called when an unhandled exception occurs.
 * @return Pointer to the previous unhandled exception catcher.
 */
WS_DLL_PUBLIC void (*except_unhandled_catcher(void (*new_catcher)(except_t *)))(except_t *);

/**
 * @brief Retrieves exception code from an exception object.
 * @param ex Pointer to the exception object.
 * @return The exception code.
 */
extern unsigned long except_code(except_t *ex);

/**
 * @brief Retrieves exception group from an exception object.
 * @param ex Pointer to the exception object.
 * @return The exception group.
 */
extern unsigned long except_group(except_t *ex);

/**
 * @brief Retrieves exception message from an exception object.
 * @param ex Pointer to the exception object.
 * @return The exception message.
 */
extern const char *except_message(except_t *ex);

/**
 * @brief Retrieves exception data from an exception object.
 * @param ex Pointer to the exception object.
 * @return The exception data.
 */
extern void *except_data(except_t *ex);

/**
 * @brief Take data from an exception object.
 *
 * @param ex Pointer to the exception object.
 * @return The data that was stored in the exception object, or NULL if no data was stored.
 */
WS_DLL_PUBLIC void *except_take_data(except_t * ex);

/**
 * @brief Sets custom memory allocation and deallocation functions for exception handling.
 *
 * @param alloc Pointer to a function that allocates memory.
 * @param dealloc Pointer to a function that frees memory.
 */
WS_DLL_PUBLIC void except_set_allocator(void *(*alloc)(size_t), void (*dealloc)(void *));

/**
 * @brief Allocates memory for an exception object.
 *
 * @param size The size of the memory to allocate.
 * @return Pointer to the allocated memory.
 */
WS_DLL_PUBLIC void *except_alloc(size_t size);

/**
 * @brief Frees memory allocated for an exception node.
 *
 * @param ptr Pointer to the memory to be freed.
 */
WS_DLL_PUBLIC void except_free(void * ptr);

/* Functions to be used in a last resort when things go badly wrong; e.g.,
 * Lua uses setjmp and longjmp for its own error handling, and Lua errors
 * can longjmp past the ENDTRY so that the function that created the current
 * top node has exited and the node (and the jmp_buf) is no longer valid
 * (having been created on the stack) so we can't run the handlers or even
 * traverse the exception stack. It's better to do this than crash.  */

/**
 * @brief Get the top node from the exception stack.
 *
 * @return const struct except_stacknode* Pointer to the top node in the exception stack.
 */
const struct except_stacknode *except_get_top(void);

/**
 * @brief Set the top node of an exception stack.
 *
 * @param node Pointer to the new top node of the exception stack.
 */
void except_set_top(struct except_stacknode *node);

#define except_code(E) ((E)->except_id.except_code)
#define except_group(E) ((E)->except_id.except_group)
#define except_message(E) ((E)->except_message)
#define except_data(E) ((E)->except_dyndata)

#ifdef __cplusplus
}
#endif

/*
 * void except_cleanup_push(void (*)(void *), void *);
 * void except_cleanup_pop(int);
 * void except_checked_cleanup_pop(void (*)(void *), int);
 * void except_try_push(const except_id_t [], size_t, except_t **);
 * void except_try_pop(void);
 */

#define except_cleanup_push(F, C)                               \
    {                                                           \
        struct except_stacknode except_sn;                      \
        struct except_cleanup except_cl;                        \
        except_setup_clean(&except_sn, &except_cl, F, C)

#define except_cleanup_pop(E)                                   \
        except_pop();                                           \
        if (E)                                                  \
            except_cl.except_func(except_cl.except_context);    \
    }

#define except_checked_cleanup_pop(F, E)                        \
            except_pop();                                       \
        assert (except_cl.except_func == (F));                  \
        if (E)                                                  \
            except_cl.except_func(except_cl.except_context);    \
    }


/* --- Variants to allow nesting of except_cleanup_push w/o "shadowing" variables */
#define except_cleanup_push_pfx(pfx, F, C)                      \
    {                                                           \
        struct except_stacknode pfx##_except_sn;                \
        struct except_cleanup pfx##_except_cl;                  \
        except_setup_clean(&pfx##_except_sn, &pfx##_except_cl, F, C)

#define except_cleanup_pop_pfx(pfx, E)                          \
        except_pop();                                           \
        if (E)                                                  \
            pfx##_except_cl.except_func(pfx##_except_cl.except_context);\
    }

#define except_checked_cleanup_pop_pfx(pfx, F, E)               \
            except_pop();                                       \
        assert (pfx##_except_cl.except_func == (F));            \
        if (E)                                                  \
            pfx##_except_cl.except_func(pfx##_except_cl.except_context);\
    }
/* ---------- */


#define except_try_push(ID, NUM, PPE)                           \
     {                                                          \
        struct except_stacknode except_sn;                      \
        struct except_catch except_ch;                          \
        except_setup_try(&except_sn, &except_ch, ID, NUM);      \
        if (setjmp(except_ch.except_jmp))                       \
            *(PPE) = &except_ch.except_obj;                     \
        else                                                    \
            *(PPE) = 0

#define except_try_pop()                                        \
        except_free(except_ch.except_obj.except_dyndata);       \
        except_pop();                                           \
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
