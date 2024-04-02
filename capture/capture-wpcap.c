/* capture-wpcap.c
 * WinPcap/Npcap-specific interfaces for capturing.  We load WinPcap/Npcap
 * at run time, so that we only need one Wireshark binary and one TShark
 * binary for Windows, regardless of whether WinPcap/Npcap is installed
 * or not.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wireshark.h>

#include <windows.h>
#include <wchar.h>
#include <tchar.h>

#include <stdio.h>

#include <ws_attributes.h>

#include "capture/capture-wpcap.h"
#include <wsutil/feature_list.h>

bool has_wpcap;

#ifdef HAVE_LIBPCAP

#include <gmodule.h>

#include <epan/strutil.h>

#include "capture/capture_ifinfo.h"
#include "capture/capture-pcap-util.h"
#include "capture/capture-pcap-util-int.h"

#include <wsutil/file_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/ws_assert.h>

#define MAX_WIN_IF_NAME_LEN 511

static void    (*p_pcap_close) (pcap_t *);
static int     (*p_pcap_stats) (pcap_t *, struct pcap_stat *);
static int     (*p_pcap_dispatch) (pcap_t *, int, pcap_handler, unsigned char *);
static int     (*p_pcap_snapshot) (pcap_t *);
static int     (*p_pcap_datalink) (pcap_t *);
static int     (*p_pcap_setfilter) (pcap_t *, struct bpf_program *);
static char*   (*p_pcap_geterr) (pcap_t *);
static int     (*p_pcap_compile) (pcap_t *, struct bpf_program *, const char *, int,
			bpf_u_int32);
static int     (*p_pcap_compile_nopcap) (int, int, struct bpf_program *, const char *, int,
			bpf_u_int32);
static int     (*p_pcap_lookupnet) (const char *, bpf_u_int32 *, bpf_u_int32 *,
			char *);
static pcap_t* (*p_pcap_open_live) (const char *, int, int, int, char *);
static int     (*p_pcap_loop) (pcap_t *, int, pcap_handler, unsigned char *);
static pcap_t* (*p_pcap_open_dead) (int, int);
static void    (*p_pcap_freecode) (struct bpf_program *);
static int     (*p_pcap_findalldevs) (pcap_if_t **, char *);
static void    (*p_pcap_freealldevs) (pcap_if_t *);
static int (*p_pcap_datalink_name_to_val) (const char *);
static const char *(*p_pcap_datalink_val_to_name) (int);
static const char *(*p_pcap_datalink_val_to_description) (int);
static void    (*p_pcap_breakloop) (pcap_t *);
static const char *(*p_pcap_lib_version) (void);
static int     (*p_pcap_setbuff) (pcap_t *, int dim);
static int     (*p_pcap_next_ex) (pcap_t *, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
#ifdef HAVE_PCAP_REMOTE
static pcap_t* (*p_pcap_open) (const char *, int, int, int,
			       struct pcap_rmtauth *, char *);
static int     (*p_pcap_findalldevs_ex) (const char *, struct pcap_rmtauth *,
					 pcap_if_t **, char *);
static int     (*p_pcap_createsrcstr) (char *, int, const char *, const char *,
				       const char *, char *);
#endif
#ifdef HAVE_PCAP_SETSAMPLING
static struct pcap_samp* (*p_pcap_setsampling)(pcap_t *);
#endif

static int 	(*p_pcap_list_datalinks)(pcap_t *, int **);
static int	(*p_pcap_set_datalink)(pcap_t *, int);

#ifdef HAVE_PCAP_FREE_DATALINKS
static int	(*p_pcap_free_datalinks)(int *);
#endif

static char	*(*p_bpf_image)(const struct bpf_insn *, int);

#ifdef HAVE_PCAP_CREATE
static pcap_t	*(*p_pcap_create)(const char *, char *);
static int	(*p_pcap_set_snaplen)(pcap_t *, int);
static int	(*p_pcap_set_promisc)(pcap_t *, int);
static int	(*p_pcap_can_set_rfmon)(pcap_t *);
static int	(*p_pcap_set_rfmon)(pcap_t *, int);
static int	(*p_pcap_set_timeout)(pcap_t *, int);
static int	(*p_pcap_set_buffer_size)(pcap_t *, int);
static int	(*p_pcap_activate)(pcap_t *);
static const char *(*p_pcap_statustostr)(int);
#endif

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
static int      (*p_pcap_set_tstamp_type)(pcap_t *, int);
static int      (*p_pcap_set_tstamp_precision)(pcap_t *, int);
static int      (*p_pcap_get_tstamp_precision)(pcap_t *);
static int      (*p_pcap_list_tstamp_types)(pcap_t *, int **);
static void     (*p_pcap_free_tstamp_types)(int *);
static int      (*p_pcap_tstamp_type_name_to_val)(const char *);
static const char * (*p_pcap_tstamp_type_val_to_name)(int);
static const char * (*p_pcap_tstamp_type_val_to_description)(int);
#endif

typedef struct {
	const char	*name;
	void *	*ptr;
	bool	optional;
} symbol_table_t;

#define SYM(x, y)	{ G_STRINGIFY(x) , (void *) &G_PASTE(p_,x), y }

void
load_wpcap(void)
{

	/* These are the symbols I need or want from Wpcap */
	static const symbol_table_t	symbols[] = {
		SYM(pcap_close, false),
		SYM(pcap_stats, false),
		SYM(pcap_dispatch, false),
		SYM(pcap_snapshot, false),
		SYM(pcap_datalink, false),
		SYM(pcap_setfilter, false),
		SYM(pcap_geterr, false),
		SYM(pcap_compile, false),
		SYM(pcap_compile_nopcap, false),
		SYM(pcap_lookupnet, false),
#ifdef HAVE_PCAP_REMOTE
		SYM(pcap_open, false),
		SYM(pcap_findalldevs_ex, false),
		SYM(pcap_createsrcstr, false),
#endif
		SYM(pcap_open_live, false),
		SYM(pcap_open_dead, false),
#ifdef HAVE_PCAP_SETSAMPLING
		SYM(pcap_setsampling, true),
#endif
		SYM(pcap_loop, false),
		SYM(pcap_freecode, false),
		SYM(pcap_findalldevs, false),
		SYM(pcap_freealldevs, false),
		SYM(pcap_datalink_name_to_val, false),
		SYM(pcap_datalink_val_to_name, false),
		SYM(pcap_datalink_val_to_description, false),
		SYM(pcap_breakloop, false),
		SYM(pcap_lib_version, false),
		SYM(pcap_setbuff, true),
		SYM(pcap_next_ex, true),
		SYM(pcap_list_datalinks, false),
		SYM(pcap_set_datalink, false),
#ifdef HAVE_PCAP_FREE_DATALINKS
		SYM(pcap_free_datalinks, true),
#endif
		SYM(bpf_image, false),
#ifdef HAVE_PCAP_CREATE
		SYM(pcap_create, true),
		SYM(pcap_set_snaplen, true),
		SYM(pcap_set_promisc, true),
		SYM(pcap_can_set_rfmon, true),
		SYM(pcap_set_rfmon, true),
		SYM(pcap_set_timeout, false),
		SYM(pcap_set_buffer_size, false),
		SYM(pcap_activate, true),
		SYM(pcap_statustostr, true),
#endif
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
		SYM(pcap_set_tstamp_type, true),
		SYM(pcap_set_tstamp_precision, true),
		SYM(pcap_get_tstamp_precision, true),
		SYM(pcap_list_tstamp_types, true),
		SYM(pcap_free_tstamp_types, true),
		SYM(pcap_tstamp_type_name_to_val, true),
		SYM(pcap_tstamp_type_val_to_name, true),
		SYM(pcap_tstamp_type_val_to_description, true),
#endif
		{ NULL, NULL, false }
	};

	GModule		*wh; /* wpcap handle */
	const symbol_table_t	*sym;

	wh = load_wpcap_module();

	if (!wh) {
		return;
	}

	sym = symbols;
	while (sym->name) {
		if (!g_module_symbol(wh, sym->name, sym->ptr)) {
			if (sym->optional) {
				/*
				 * We don't care if it's missing; we just
				 * don't use it.
				 */
				*sym->ptr = NULL;
			} else {
				/*
				 * We require this symbol.
				 */
				return;
			}
		}
		sym++;
	}


	has_wpcap = true;
}

bool
caplibs_have_npcap(void)
{
	return has_wpcap && g_str_has_prefix(p_pcap_lib_version(), "Npcap");
}

bool
caplibs_get_npcap_version(unsigned int *major, unsigned int *minor)
{
	const char *version;
	static const char prefix[] = "Npcap version ";

	if (!has_wpcap)
		return false;	/* we don't have any pcap */

	version = p_pcap_lib_version();
	if (!g_str_has_prefix(version, prefix))
		return false;	/* we have it, but it's not Npcap */

	/*
	 * This is Npcap; return the major and minor version numbers.
	 * First, skip pas the "Npcap version " prefix.
	 */
	const char *major_version_number;
	const char *minor_version_number;
	const char *p;

	/*
	 * Get the major version number.
	 */
	major_version_number = version + sizeof prefix - 1;
	if (!ws_strtou(major_version_number, &p, major))
		return false;	/* not a number */
	if (*p != '.')
		return false;	/* not followed by a "." */
	p++;	/* skip over the '.' */

	/*
	 * Get the minor version number.
	 */
	minor_version_number = p;
	if (!ws_strtou(minor_version_number, &p, minor))
		return false;	/* not a number */
	if (*p != ',' && *p != '.' && *p != '\0') {
		/*
		 * Not followed by a comma (to separate from "based on
		 * libpcap ..."), not followed by a period (in case Npcap
		 * ever has a dot-dot release), and not followed by a
		 * '\0' (in case it has only the Npcap version number).
		 */
		return false;
	}
	return true;
}

static char *
local_code_page_str_to_utf8(char *str)
{
	ULONG utf16_len;
	wchar_t *utf16_str;
	char *utf8_str;

	if (str == NULL) {
		return NULL;
	}

	utf16_len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	utf16_str = g_malloc_n(utf16_len, sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, str, -1, utf16_str, utf16_len);

	utf8_str = g_utf16_to_utf8(utf16_str, -1, NULL, NULL, NULL);

	g_free(utf16_str);
	return utf8_str;
}

static void
prepare_errbuf(char *errbuf)
{
	ws_assert(errbuf);
	errbuf[0] = '\0';
}

static void
convert_errbuf_to_utf8(char *errbuf)
{
	char *utf8_err;
	if (errbuf[0] == '\0') {
		return;
	}
	errbuf[PCAP_ERRBUF_SIZE - 1] = '\0';
	utf8_err = local_code_page_str_to_utf8(errbuf);
	snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", utf8_err);
	g_free(utf8_err);
}

static char *
cant_load_winpcap_err(const char *app_name)
{
	return ws_strdup_printf(
"Unable to load Npcap or WinPcap (wpcap.dll); %s will not be able to\n"
"capture packets.\n"
"\n"
"In order to capture packets Npcap or WinPcap must be installed. See\n"
"\n"
"        https://npcap.com/\n"
"\n"
"for a downloadable version of Npcap and for instructions on how to\n"
"install it.",
	    app_name);
}

void
pcap_close(pcap_t *a)
{
	ws_assert(has_wpcap);
	p_pcap_close(a);
}

int
pcap_stats(pcap_t *a, struct pcap_stat *b)
{
	ws_assert(has_wpcap);
	return p_pcap_stats(a, b);
}

int
pcap_dispatch(pcap_t *a, int b, pcap_handler c, unsigned char *d)
{
	ws_assert(has_wpcap);
	return p_pcap_dispatch(a, b, c, d);
}

int
pcap_snapshot(pcap_t *a)
{
	ws_assert(has_wpcap);
	return p_pcap_snapshot(a);
}

int
pcap_datalink(pcap_t *a)
{
	ws_assert(has_wpcap);
	return p_pcap_datalink(a);
}

int
pcap_set_datalink(pcap_t *p, int dlt)
{
	ws_assert(has_wpcap);
	return p_pcap_set_datalink(p, dlt);
}

int
pcap_setfilter(pcap_t *a, struct bpf_program *b)
{
	ws_assert(has_wpcap);
	return p_pcap_setfilter(a, b);
}

char*
pcap_geterr(pcap_t *a)
{
	char *errbuf;
	ws_assert(has_wpcap);
	errbuf = p_pcap_geterr(a);
	convert_errbuf_to_utf8(errbuf);
	return errbuf;
}

int
pcap_compile(pcap_t *a, struct bpf_program *b, const char *c, int d,
	     bpf_u_int32 e)
{
	ws_assert(has_wpcap);
	return p_pcap_compile(a, b, c, d, e);
}

int
pcap_compile_nopcap(int a, int b, struct bpf_program *c, const char *d, int e,
		    bpf_u_int32 f)
{
	ws_assert(has_wpcap);
	return p_pcap_compile_nopcap(a, b, c, d, e, f);
}

int
pcap_lookupnet(const char *a, bpf_u_int32 *b, bpf_u_int32 *c, char *errbuf)
{
	int ret;
	ws_assert(has_wpcap);
	ret = p_pcap_lookupnet(a, b, c, errbuf);
	if (ret == -1)
		convert_errbuf_to_utf8(errbuf);
	return ret;
}

pcap_t*
pcap_open_live(const char *a, int b, int c, int d, char *errbuf)
{
	pcap_t *p;
	if (!has_wpcap) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
			   "unable to load Npcap or WinPcap (wpcap.dll); can't open %s to capture",
			   a);
		return NULL;
	}
	prepare_errbuf(errbuf);
	p = p_pcap_open_live(a, b, c, d, errbuf);
	convert_errbuf_to_utf8(errbuf);
	return p;
}

pcap_t*
pcap_open_dead(int a, int b)
{
	if (!has_wpcap) {
		return NULL;
	}
	return p_pcap_open_dead(a, b);
}

char *
bpf_image(const struct bpf_insn *a, int b)
{
	if (!has_wpcap) {
		return NULL;
	}
	return p_bpf_image(a, b);
}

#ifdef HAVE_PCAP_REMOTE
pcap_t*
pcap_open(const char *a, int b, int c, int d, struct pcap_rmtauth *e, char *errbuf)
{
	pcap_t *ret;
	if (!has_wpcap) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE,
			   "unable to load Npcap or WinPcap (wpcap.dll); can't open %s to capture",
			   a);
		return NULL;
	}
	prepare_errbuf(errbuf);
	ret = p_pcap_open(a, b, c, d, e, errbuf);
	convert_errbuf_to_utf8(errbuf);
	return ret;
}

int
ws_pcap_findalldevs_ex(const char *a, struct pcap_rmtauth *b, pcap_if_t **c, char *errbuf)
{
	int ret;
	ws_assert(has_wpcap);
	ret = p_pcap_findalldevs_ex(a, b, c, errbuf);
	if (ret == -1)
		convert_errbuf_to_utf8(errbuf);
	return ret;
}

int
pcap_createsrcstr(char *a, int b, const char *c, const char *d, const char *e,
		  char *errbuf)
{
	int ret;
	ws_assert(has_wpcap);
	ret = p_pcap_createsrcstr(a, b, c, d, e, errbuf);
	if (ret == -1)
		convert_errbuf_to_utf8(errbuf);
	return ret;
}
#endif

#ifdef HAVE_PCAP_SETSAMPLING
struct pcap_samp *
pcap_setsampling(pcap_t *a)
{
	ws_assert(has_wpcap);
	if (p_pcap_setsampling != NULL) {
		return p_pcap_setsampling(a);
	}
	return NULL;
}
#endif

int
pcap_loop(pcap_t *a, int b, pcap_handler c, unsigned char *d)
{
	ws_assert(has_wpcap);
	return p_pcap_loop(a, b, c, d);
}

void
pcap_freecode(struct bpf_program *a)
{
	ws_assert(has_wpcap);
	p_pcap_freecode(a);
}

int
pcap_findalldevs(pcap_if_t **a, char *errbuf)
{
	int ret;
	ws_assert(has_wpcap);
	ret = p_pcap_findalldevs(a, errbuf);
	if (ret == -1)
		convert_errbuf_to_utf8(errbuf);
	return ret;
}

void
pcap_freealldevs(pcap_if_t *a)
{
	ws_assert(has_wpcap);
	p_pcap_freealldevs(a);
}

#ifdef HAVE_PCAP_CREATE
pcap_t *
pcap_create(const char *a, char *errbuf)
{
	pcap_t *p;
	ws_assert(has_wpcap && p_pcap_create != NULL);
	p = p_pcap_create(a, errbuf);
	if (p == NULL)
		convert_errbuf_to_utf8(errbuf);
	return p;
}

int
pcap_set_snaplen(pcap_t *a, int b)
{
	ws_assert(has_wpcap && p_pcap_set_snaplen != NULL);
	return p_pcap_set_snaplen(a, b);
}

int
pcap_set_promisc(pcap_t *a, int b)
{
	ws_assert(has_wpcap && p_pcap_set_promisc != NULL);
	return p_pcap_set_promisc(a, b);
}

int
pcap_can_set_rfmon(pcap_t *a)
{
	ws_assert(has_wpcap);
	if (p_pcap_can_set_rfmon != NULL) {
		return p_pcap_can_set_rfmon(a);
	}
	return 0;
}

int
pcap_set_rfmon(pcap_t *a, int b)
{
	ws_assert(has_wpcap && p_pcap_set_rfmon != NULL);
	return p_pcap_set_rfmon(a, b);
}

int
pcap_set_timeout(pcap_t *a, int b)
{
	ws_assert(has_wpcap && p_pcap_set_timeout != NULL);
	return p_pcap_set_timeout(a, b);
}
int
pcap_set_buffer_size(pcap_t *a, int b)
{
	ws_assert(has_wpcap && p_pcap_set_buffer_size != NULL);
	return p_pcap_set_buffer_size(a, b);
}

int
pcap_activate(pcap_t *a)
{
	ws_assert(has_wpcap && p_pcap_activate != NULL);
	return p_pcap_activate(a);

}

const char *
pcap_statustostr(int a)
{
    static char ebuf[15 + 10 + 1];

    ws_assert(has_wpcap);
    if (p_pcap_statustostr != NULL) {
        return p_pcap_statustostr(a);
    }

    /* XXX copy routine from pcap.c ??? */
    (void)snprintf(ebuf, sizeof ebuf, "Don't have pcap_statustostr(), can't translate error: %d", a);
    return(ebuf);

}
#endif

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
int
pcap_set_tstamp_type(pcap_t *a, int b) {
	ws_assert(has_wpcap);
	if (p_pcap_set_tstamp_type != NULL) {
		return p_pcap_set_tstamp_type(a, b);
	}
	return PCAP_ERROR_CANTSET_TSTAMP_TYPE;
}

int
pcap_set_tstamp_precision(pcap_t *a, int b) {
	ws_assert(has_wpcap);
	if (p_pcap_set_tstamp_precision != NULL) {
		return p_pcap_set_tstamp_precision(a, b);
	}
	// No error code defined so return NOTSUP.
	return PCAP_ERROR_TSTAMP_PRECISION_NOTSUP;
}

int
pcap_get_tstamp_precision(pcap_t *a) {
	ws_assert(has_wpcap);
	if (p_pcap_get_tstamp_precision != NULL) {
		return p_pcap_get_tstamp_precision(a);
	}
	// No error code defined so return MICRO.
	return PCAP_TSTAMP_PRECISION_MICRO;
}

int
pcap_list_tstamp_types(pcap_t *a, int **b) {
	ws_assert(has_wpcap);
	if (p_pcap_list_tstamp_types != NULL) {
		return p_pcap_list_tstamp_types(a, b);
	}
	return PCAP_ERROR;
}

void
pcap_free_tstamp_types(int *a) {
	ws_assert(has_wpcap);
	if (p_pcap_free_tstamp_types != NULL) {
		p_pcap_free_tstamp_types(a);
	}
}

int
pcap_tstamp_type_name_to_val(const char *a) {
	ws_assert(has_wpcap);
	if (p_pcap_tstamp_type_name_to_val != NULL) {
		return p_pcap_tstamp_type_name_to_val(a);
	}
	return PCAP_ERROR;
}

const char *
pcap_tstamp_type_val_to_name(int a) {
	ws_assert(has_wpcap);
	if (p_pcap_tstamp_type_val_to_name != NULL) {
		return p_pcap_tstamp_type_val_to_name(a);
	}
	return NULL;
}

const char *
pcap_tstamp_type_val_to_description(int a) {
	ws_assert(has_wpcap);
	if (p_pcap_tstamp_type_val_to_description != NULL) {
		return p_pcap_tstamp_type_val_to_description(a);
	}
	return NULL;
}
#endif

int
pcap_datalink_name_to_val(const char *name)
{
	if (has_wpcap)
		return p_pcap_datalink_name_to_val(name);
	else
		return -1;
}

int
pcap_list_datalinks(pcap_t *p, int **ddlt)
{
	if (has_wpcap)
		return p_pcap_list_datalinks(p, ddlt);
	else
		return -1;
}

#ifdef HAVE_PCAP_FREE_DATALINKS
void
pcap_free_datalinks(int *ddlt)
{
	ws_assert(has_wpcap);

	/*
	 * If we don't have pcap_free_datalinks() in WinPcap,
	 * we don't free the memory - we can't use free(), as
	 * we might not have been built with the same version
	 * of the C runtime library as WinPcap was, and, if we're
	 * not, free() isn't guaranteed to work on something
	 * allocated by WinPcap.
	 */
	if (p_pcap_free_datalinks != NULL)
		p_pcap_free_datalinks(ddlt);
}
#endif

const char *
pcap_datalink_val_to_name(int dlt)
{
	if (has_wpcap)
		return p_pcap_datalink_val_to_name(dlt);
	else
		return NULL;
}

const char *
pcap_datalink_val_to_description(int dlt)
{
	if (has_wpcap)
		return p_pcap_datalink_val_to_description(dlt);
	return NULL;
}

void pcap_breakloop(pcap_t *a)
{
	p_pcap_breakloop(a);
}

/* setbuff is win32 specific! */
int pcap_setbuff(pcap_t *a, int b)
{
	ws_assert(has_wpcap);
	return p_pcap_setbuff(a, b);
}

int pcap_next_ex(pcap_t *a, struct pcap_pkthdr **b, const u_char **c)
{
	ws_assert(has_wpcap);
	return p_pcap_next_ex(a, b, c);
}

#ifdef HAVE_PCAP_REMOTE
GList *
get_remote_interface_list(const char *hostname, const char *port,
			  int auth_type, const char *username,
			  const char *passwd, int *err, char **err_str)
{
	if (!has_wpcap) {
		/*
		 * We don't have Npcap or WinPcap, so we can't get a list of
		 * interfaces.
		 */
		*err = DONT_HAVE_PCAP;
		if (err_str != NULL)
			*err_str = cant_load_winpcap_err("you");
		return NULL;
	}

	return get_interface_list_findalldevs_ex(hostname, port, auth_type,
	    username, passwd, err, err_str);
}
#endif

GList *
get_interface_list(int *err, char **err_str)
{
	if (!has_wpcap) {
		/*
		 * We don't have Npcap or WinPcap, so we can't get a list of
		 * interfaces.
		 */
		*err = DONT_HAVE_PCAP;
		if (err_str != NULL)
			*err_str = cant_load_winpcap_err("you");
		return NULL;
	}

	return get_interface_list_findalldevs(err, err_str);
}

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_interface_list()".
 */
char *
cant_get_if_list_error_message(const char *err_str)
{
	/*
	 * If the error message includes "Not enough storage is available
	 * to process this command" or "The operation completed successfully",
	 * suggest that they install a WinPcap version later than 3.0.
	 */
	if (strstr(err_str, "Not enough storage is available to process this command") != NULL ||
	    strstr(err_str, "The operation completed successfully") != NULL) {
		return ws_strdup_printf("Can't get list of interfaces: %s\n"
"This might be a problem with WinPcap 3.0. You should try updating to\n"
"Npcap. See https://npcap.com/ for more information.",
		    err_str);
	}
	return ws_strdup_printf("Can't get list of interfaces: %s", err_str);
}

if_capabilities_t *
get_if_capabilities_local(interface_options *interface_opts,
    cap_device_open_status *status, char **status_str)
{
	/*
	 * We're not getting capaibilities for a remote device; use
	 * pcap_create() and pcap_activate() if we have them, so that
	 * we can set various options, otherwise use pcap_open_live().
	 */
#ifdef HAVE_PCAP_CREATE
	if (p_pcap_create != NULL)
		return get_if_capabilities_pcap_create(interface_opts, status,
		    status_str);
#endif
	return get_if_capabilities_pcap_open_live(interface_opts, status,
	    status_str);
}

pcap_t *
open_capture_device_local(capture_options *capture_opts,
    interface_options *interface_opts, int timeout,
    cap_device_open_status *open_status,
    char (*open_status_str)[PCAP_ERRBUF_SIZE])
{
	/*
	 * We're not opening a remote device; use pcap_create() and
	 * pcap_activate() if we have them, so that we can set various
	 * options, otherwise use pcap_open_live().
	 */
#ifdef HAVE_PCAP_CREATE
	if (p_pcap_create != NULL)
		return open_capture_device_pcap_create(capture_opts,
		    interface_opts, timeout, open_status, open_status_str);
#endif
	return open_capture_device_pcap_open_live(interface_opts, timeout,
	    open_status, open_status_str);
}

/*
 * Append the WinPcap or Npcap SDK version with which we were compiled to a GString.
 */
void
gather_caplibs_compile_info(feature_list l)
{
	with_feature(l, "libpcap");
}

void
gather_caplibs_runtime_info(feature_list l)
{
	/*
	 * On Windows, we might have been compiled with WinPcap/Npcap but
	 * might not have it loaded; indicate whether we have it or
	 * not and, if we have it, what version we have.
	 */
	if (has_wpcap) {
		with_feature(l, "%s", p_pcap_lib_version());
	} else
		without_feature(l, "Npcap or WinPcap");
}

/*
 * If npf.sys is running, return true.
 */
bool
npf_sys_is_running(void)
{
	SC_HANDLE h_scm, h_serv;
	SERVICE_STATUS ss;

	h_scm = OpenSCManager(NULL, NULL, 0);
	if (!h_scm)
		return false;

	h_serv = OpenService(h_scm, _T("npcap"), SC_MANAGER_CONNECT|SERVICE_QUERY_STATUS);
	if (!h_serv) {
		h_serv = OpenService(h_scm, _T("npf"), SC_MANAGER_CONNECT|SERVICE_QUERY_STATUS);
		if (!h_serv) {
			CloseServiceHandle(h_scm);
			return false;
		}
	}

	if (QueryServiceStatus(h_serv, &ss)) {
		if (ss.dwCurrentState & SERVICE_RUNNING) {
			CloseServiceHandle(h_serv);
			CloseServiceHandle(h_scm);
			return true;
		}
	}
	CloseServiceHandle(h_serv);
	CloseServiceHandle(h_scm);
	return false;
}

#else /* HAVE_LIBPCAP */

void
load_wpcap(void)
{
	return;
}

/*
 * Append an indication that we were not compiled with WinPcap
 * to a GString.
 */
void
gather_caplibs_compile_info(feature_list l)
{
	without_feature(l, "libpcap");
}

void
gather_caplibs_runtime_info(feature_list l _U_)
{
}

bool
caplibs_have_npcap(void)
{
	return false;
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
