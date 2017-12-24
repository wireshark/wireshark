/*
* Provide some functions that are not present in older
* GLIB versions (down to 2.22)
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0+
*/
#include "config.h"

#include <glib.h>

#include "glib-compat.h"
#if !GLIB_CHECK_VERSION(2, 28, 0)
/**
* g_slist_free_full:
* @list: a pointer to a #GSList
* @free_func: the function to be called to free each element's data
*
* Convenience method, which frees all the memory used by a #GSList, and
* calls the specified destroy function on every element's data.
*
* Since: 2.28
**/
void
g_slist_free_full(GSList         *list,
    GDestroyNotify  free_func)
{
    g_slist_foreach(list, (GFunc)free_func, NULL);
    g_slist_free(list);
}

/**
* g_list_free_full:
* @list: a pointer to a #GList
* @free_func: the function to be called to free each element's data
*
* Convenience method, which frees all the memory used by a #GList,
* and calls @free_func on every element's data.
*
* Since: 2.28
*/
void
g_list_free_full(GList          *list,
    GDestroyNotify  free_func)
{
    g_list_foreach(list, (GFunc)free_func, NULL);
    g_list_free(list);
}

/**
* g_get_monotonic_time:
*
* Queries the system monotonic time.  Returns value in microseconds.
*
* Since: 2.28
*/
gint64 g_get_monotonic_time (void)
{
    GTimeVal result;
    g_get_current_time(&result);
    return result.tv_sec*1000000 + result.tv_usec;
}

#endif /* GLIB_CHECK_VERSION(2, 28, 0)*/

#if !GLIB_CHECK_VERSION(2, 30, 0)
/**
* g_ptr_array_new_full:
* @reserved_size: number of pointers preallocated
* @element_free_func: (allow-none): A function to free elements with
*     destroy @array or %NULL
*
* Creates a new #GPtrArray with @reserved_size pointers preallocated
* and a reference count of 1. This avoids frequent reallocation, if
* you are going to add many pointers to the array. Note however that
* the size of the array is still 0. It also set @element_free_func
* for freeing each element when the array is destroyed either via
* g_ptr_array_unref(), when g_ptr_array_free() is called with
* @free_segment set to %TRUE or when removing elements.
*
* Returns: A new #GPtrArray
*
* Since: 2.30
*/
GPtrArray*
g_ptr_array_new_full(guint          reserved_size,
    GDestroyNotify element_free_func)
{
    GPtrArray *array;

    array = g_ptr_array_sized_new(reserved_size);
    g_ptr_array_set_free_func(array, element_free_func);

    return array;
}
#endif /* GLIB_CHECK_VERSION(2, 30, 0)*/

#if !GLIB_CHECK_VERSION(2,31,18)
/**
Code copied from dumpcap.c
*/
gpointer
g_async_queue_timeout_pop(GAsyncQueue *queue,
    guint64      timeout)
{
    GTimeVal  wait_time;
    gpointer  q_status;

    g_get_current_time(&wait_time);
    g_time_val_add(&wait_time, timeout);
    q_status = g_async_queue_timed_pop(queue, &wait_time);

    return q_status;
}

#endif /* GLIB_CHECK_VERSION(2,31,18)*/


#if !GLIB_CHECK_VERSION(2,31,0)
GThread *g_thread_new(const gchar *name, GThreadFunc func, gpointer data)
{
    GError *error = NULL;
    GThread *thread;

    thread = g_thread_create(func, data, TRUE, &error);

    if G_UNLIKELY (thread == NULL)
        g_error ("creating thread '%s': %s", name ? name : "", error->message);

    return thread;
}
#endif /* GLIB_CHECK_VERSION(2,31,0)*/

/*
* Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
