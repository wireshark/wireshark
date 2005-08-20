/* decode_as_dcerpc.c
 *
 * $Id$
 *
 * Routines to modify dcerpc bindings on the fly.
 *
 * Copyright 2004 Ulf Lamping
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

#include <gtk/gtk.h>
#include <string.h>

#include "decode_as_dlg.h"
#include "dlg_utils.h"
#include "globals.h"
#include "simple_dialog.h"
#include <epan/packet.h>
#include <epan/ipproto.h>
#include "gui_utils.h"
#include <epan/epan_dissect.h>
#include "compat_macros.h"
#include "decode_as_dcerpc.h"

#include <epan/dissectors/packet-dcerpc.h>


/**************************************************/
/*                Typedefs & Enums                */
/**************************************************/

/* list of dcerpc "Decode As" bindings */
GSList *decode_dcerpc_bindings = NULL;

/**************************************************/
/*            Global Functions                    */
/**************************************************/

/* inject one of our bindings into the dcerpc binding table */
static void 
decode_dcerpc_inject_binding(gpointer data, gpointer user_data _U_)
{
    dcerpc_add_conv_to_bind_table((decode_dcerpc_bind_values_t *) data);
}


/* inject all of our bindings into the dcerpc binding table */
static void 
decode_dcerpc_inject_bindings(gpointer data _U_) {
    g_slist_foreach(decode_dcerpc_bindings, decode_dcerpc_inject_binding, NULL /* user_data */);
}


/* init this file */
void 
decode_dcerpc_init(void) {
    GHook*      hook_init_proto;


    /* add a hook function to the dcerpc init_protocols hook */
    hook_init_proto = g_hook_alloc(&dcerpc_hooks_init_protos);
    hook_init_proto->func = decode_dcerpc_inject_bindings;
    g_hook_prepend(&dcerpc_hooks_init_protos, hook_init_proto);
}


/* clone a binding (uses g_malloc) */
static decode_dcerpc_bind_values_t *
decode_dcerpc_binding_clone(decode_dcerpc_bind_values_t *binding_in)
{
    decode_dcerpc_bind_values_t *stored_binding;

    stored_binding = g_malloc(sizeof(decode_dcerpc_bind_values_t));
    *stored_binding = *binding_in;
    COPY_ADDRESS(&stored_binding->addr_a, &binding_in->addr_a);
    COPY_ADDRESS(&stored_binding->addr_b, &binding_in->addr_b);
    stored_binding->ifname = g_string_new(binding_in->ifname->str);

    return stored_binding;
}


/* free a binding */
void 
decode_dcerpc_binding_free(void *binding_in)
{
    decode_dcerpc_bind_values_t *binding = binding_in;

    g_free((void *) binding->addr_a.data);
    g_free((void *) binding->addr_b.data);
    if(binding->ifname)
        g_string_free(binding->ifname, TRUE);
    g_free(binding);
}


/* compare two bindings (except the interface related things, e.g. uuid) */
static gint
decode_dcerpc_binding_cmp(gconstpointer a, gconstpointer b)
{
    const decode_dcerpc_bind_values_t *binding_a = a;
    const decode_dcerpc_bind_values_t *binding_b = b;


    /* don't compare uuid and ver! */
    if( 
        ADDRESSES_EQUAL(&binding_a->addr_a, &binding_b->addr_a) &&
        ADDRESSES_EQUAL(&binding_a->addr_b, &binding_b->addr_b) &&
        binding_a->ptype == binding_b->ptype &&
        binding_a->port_a == binding_b->port_a &&
        binding_a->port_b == binding_b->port_b &&
        binding_a->ctx_id == binding_b->ctx_id &&
        binding_a->smb_fid == binding_b->smb_fid)
    {
        /* equal */
        return 0;
    }

    /* unequal */
    return 1;
}


/**************************************************/
/*             Show Changed Bindings              */
/**************************************************/


/* add a single binding to the Show list */
static void
decode_dcerpc_add_show_list_single(gpointer data, gpointer user_data)
{
    gchar      string1[20];

    
    decode_dcerpc_bind_values_t *binding = data;

    g_snprintf(string1, sizeof(string1), "ctx_id: %u", binding->ctx_id);

    decode_add_to_show_list (
        user_data, 
        "DCE-RPC", 
        string1, 
        "-", 
        binding->ifname->str);
}


/* add all bindings to the Show list */
void
decode_dcerpc_add_show_list(gpointer user_data)
{
    g_slist_foreach(decode_dcerpc_bindings, decode_dcerpc_add_show_list_single, user_data);
}


/**************************************************/
/*         Modify the binding routines            */
/**************************************************/


/* removes all bindings */
void
decode_dcerpc_reset_all(void)
{
    decode_dcerpc_bind_values_t *binding;

    while(decode_dcerpc_bindings) {
        binding = decode_dcerpc_bindings->data;

        decode_dcerpc_binding_free(binding);
        decode_dcerpc_bindings = g_slist_remove(
            decode_dcerpc_bindings, 
            decode_dcerpc_bindings->data);
    }
}


/* remove a binding (looking the same way as the given one) */
static void
decode_dcerpc_binding_reset(
const gchar *table_name _U_, 
decode_dcerpc_bind_values_t *binding)
{
    GSList *le;
    decode_dcerpc_bind_values_t *old_binding;


    /* find the old binding (if it exists) */
    le = g_slist_find_custom(decode_dcerpc_bindings,
                                             binding,
                                             decode_dcerpc_binding_cmp);
    if(le == NULL)
        return;

    old_binding = le->data;

    decode_dcerpc_bindings = g_slist_remove(decode_dcerpc_bindings, le->data);

    g_free((void *) old_binding->addr_a.data);
    g_free((void *) old_binding->addr_b.data);
    g_string_free(old_binding->ifname, TRUE);
    g_free(old_binding);
}


/* a binding has changed (remove a previously existing one) */
static void
decode_dcerpc_binding_change(
const gchar *table_name, 
decode_dcerpc_bind_values_t *binding)
{

    decode_dcerpc_bind_values_t *stored_binding;

    /* remove a probably existing old binding */
    decode_dcerpc_binding_reset(table_name, binding);

    /* clone the new binding and append it to the list */
    stored_binding = decode_dcerpc_binding_clone(binding);
    decode_dcerpc_bindings = g_slist_append (decode_dcerpc_bindings, stored_binding);
}


/* a binding has changed (add/replace/remove it) */
static void
decode_change_one_dcerpc_binding(const gchar *table_name, decode_dcerpc_bind_values_t *binding, GtkWidget *list)
{
    dcerpc_uuid_key     *key;
    gchar              *abbrev;
#if GTK_MAJOR_VERSION < 2
    gint               row;
#else
    GtkTreeSelection  *selection;
    GtkTreeModel      *model;
    GtkTreeIter        iter;
#endif

#if GTK_MAJOR_VERSION < 2
    if (!GTK_CLIST(list)->selection)
    {
	abbrev = NULL;
	key = NULL;
    } else {
	row = GPOINTER_TO_INT(GTK_CLIST(list)->selection->data);
	key = gtk_clist_get_row_data(GTK_CLIST(list), row);
	gtk_clist_get_text(GTK_CLIST(list), row, E_LIST_S_PROTO_NAME, &abbrev);
    }
#else
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
    if (gtk_tree_selection_get_selected(selection, &model, &iter) == FALSE)
    {
	abbrev = NULL;
	key = NULL;
    } else {
        gtk_tree_model_get(model, &iter, E_LIST_S_PROTO_NAME, &abbrev,
                           E_LIST_S_TABLE+1, &key, -1);
    }
#endif

    if (abbrev != NULL && strcmp(abbrev, "(default)") == 0) {
        decode_dcerpc_binding_reset(table_name, binding);
    } else {
        binding->ifname = g_string_new(abbrev);
        binding->uuid = key->uuid;
        binding->ver = key->ver;
        decode_dcerpc_binding_change(table_name, binding);
    }
#if GTK_MAJOR_VERSION >= 2
    if (abbrev != NULL)
	g_free(abbrev);
#endif
}



/**************************************************/
/* Action routines for the "Decode As..." dialog  */
/*   - called when the OK button pressed          */
/**************************************************/

/*
 * This routine is called when the user clicks the "OK" button in the
 * "Decode As..." dialog window and the DCE-RPC page is foremost.
 * This routine takes care of making any changes requested to the DCE-RPC 
 * binding tables.
 *
 * @param notebook_pg A pointer to the "DCE-RPC" notebook page.
 */
static void
decode_dcerpc(GtkWidget *notebook_pg)
{
    GtkWidget *list;
    const gchar *table_name;
    decode_dcerpc_bind_values_t *binding;


    list = OBJECT_GET_DATA(notebook_pg, E_PAGE_LIST);
    if (requested_action == E_DECODE_NO)
#if GTK_MAJOR_VERSION < 2
	gtk_clist_unselect_all(GTK_CLIST(list));
#else
	gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(list)));
#endif

    binding = OBJECT_GET_DATA(notebook_pg, E_PAGE_BINDING);

    /*table_name = OBJECT_GET_DATA(notebook_pg, E_PAGE_TABLE);*/
    table_name = "DCE-RPC";
    decode_change_one_dcerpc_binding(table_name, binding, list);
}


/**************************************************/
/*                  Dialog setup                  */
/**************************************************/


/* add an interface to the list */
static void 
decode_dcerpc_add_to_list(gpointer key, gpointer value, gpointer user_data)
{
    /*dcerpc_uuid_key *k = key;*/
    dcerpc_uuid_value *v = value;

    if(strcmp(v->name, "(none)"))
        decode_add_to_list("DCE-RPC", v->name, key, user_data);
}


/* add all interfaces to the list */
static GtkWidget *
decode_add_dcerpc_menu (GtkWidget *page, const gchar *table_name _U_)
{
    GtkWidget *scrolled_window;
    GtkWidget *list;

    decode_list_menu_start(page, &list, &scrolled_window);
    g_hash_table_foreach(dcerpc_uuids, decode_dcerpc_add_to_list, list);
    decode_list_menu_finish(list);
    return(scrolled_window);
}


/* add a DCE-RPC page to the notebook */
GtkWidget *
decode_dcerpc_add_page (packet_info *pinfo)
{
    GtkWidget	*page_hb, *info_vb, *label, *scrolled_window;
    GString     *gs = g_string_new("");
    GString     *gs2 = g_string_new("");
    decode_dcerpc_bind_values_t *binding;


    /* clone binding */
    binding = g_malloc(sizeof(decode_dcerpc_bind_values_t));
    COPY_ADDRESS(&binding->addr_a, &pinfo->src);
    COPY_ADDRESS(&binding->addr_b, &pinfo->dst);
    binding->ptype = pinfo->ptype;
    binding->port_a = pinfo->srcport;
    binding->port_b = pinfo->destport;
    binding->ctx_id = pinfo->dcectxid;
    binding->smb_fid = dcerpc_get_transport_salt(pinfo);
    binding->ifname = NULL;
    /*binding->uuid = NULL;*/
    binding->ver = 0;

    /* create page content */
    page_hb = gtk_hbox_new(FALSE, 5);
    OBJECT_SET_DATA(page_hb, E_PAGE_ACTION, decode_dcerpc);
    OBJECT_SET_DATA(page_hb, E_PAGE_TABLE, "DCE-RPC");
    OBJECT_SET_DATA(page_hb, E_PAGE_TITLE, "DCE-RPC");
    OBJECT_SET_DATA(page_hb, E_PAGE_BINDING, binding);
    
    info_vb = gtk_vbox_new(FALSE, 5);
    gtk_box_pack_start(GTK_BOX(page_hb), info_vb, TRUE, TRUE, 0);

    /* Always enabled */
    label = gtk_label_new("Replace binding between:");
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    switch(binding->ptype) {
    case(PT_TCP):
        g_string_sprintf(gs2, "TCP port");
        break;
    case(PT_UDP):
        g_string_sprintf(gs2, "UDP port");
        break;
    default:
        g_string_sprintf(gs2, "Unknown port type");
    }

    /* XXX - how to print the address binding->addr_a? */
    g_string_sprintf(gs, "Address: ToBeDone %s: %u", gs2->str, binding->port_a);
    label = gtk_label_new(gs->str);
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    label = gtk_label_new("&");
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    /* XXX - how to print the address binding->addr_b? */
    g_string_sprintf(gs, "Address: ToBeDone %s: %u", gs2->str, binding->port_b);
    label = gtk_label_new(gs->str);
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    label = gtk_label_new("&");
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    g_string_sprintf(gs, "Context ID: %u", binding->ctx_id);
    label = gtk_label_new(gs->str);
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    label = gtk_label_new("&");
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);
    gtk_widget_set_sensitive(label, binding->smb_fid);

    g_string_sprintf(gs, "SMB FID: %u", binding->smb_fid);
    label = gtk_label_new(gs->str);
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);
    gtk_widget_set_sensitive(label, binding->smb_fid);

    /* Conditionally enabled - only when decoding packets */
    label = gtk_label_new("with:");
    gtk_box_pack_start(GTK_BOX(info_vb), label, TRUE, TRUE, 0);

    decode_dimmable = g_slist_prepend(decode_dimmable, label);
    scrolled_window = decode_add_dcerpc_menu(page_hb, "dcerpc" /*table_name*/);
    gtk_box_pack_start(GTK_BOX(page_hb), scrolled_window, TRUE, TRUE, 0);
    decode_dimmable = g_slist_prepend(decode_dimmable, scrolled_window);

    g_string_free(gs, TRUE);

    return(page_hb);
}
