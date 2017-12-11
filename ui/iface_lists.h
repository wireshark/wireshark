/* iface_lists.h
 * Declarations of routines to manage the global list of interfaces and to
 * update widgets/windows displaying items from those lists
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __IFACE_LISTS_H__
#define __IFACE_LISTS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if defined(HAVE_LIBPCAP) || defined(HAVE_EXTCAP)
/*
 * Update the global interface list in the background. Create it if we
 * haven't done so already.
 */
extern void fill_in_local_interfaces_start(void);
#endif

#ifdef HAVE_LIBPCAP
/*
 * Used when sorting an interface list into alphabetical order by
 * their descriptions.
 */
extern gint if_list_comparator_alph(const void *first_arg, const void *second_arg);

/*
 * Update the global interface list in the foreground.
 */
extern void scan_local_interfaces(void (*update_cb)(void));

/*
 * Wait for the global interface list creation to finish.
 */
extern void fill_in_local_interfaces_wait(void(*update_cb)(void));

/*
 * Hide the interfaces
 */
extern void hide_interface(gchar* new_hide);

/*
 * Update the global interface list from preferences.
 */
extern void update_local_interfaces(void);

#endif /* HAVE_LIBPCAP */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __IFACE_LISTS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
