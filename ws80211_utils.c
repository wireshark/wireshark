/*
 * ws80211 utilities
 * Copyright 2012, Pontus Fuchs <pontus.fuchs@gmail.com>

Parts of this file was copied from iw:

Copyright (c) 2007, 2008	Johannes Berg
Copyright (c) 2007		Andy Lutomirski
Copyright (c) 2007		Mike Kershaw
Copyright (c) 2008-2009		Luis R. Rodriguez

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include "config.h"

#include <stdio.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "ws80211_utils.h"

#if defined(HAVE_LIBNL) && defined(HAVE_NL80211)
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include <linux/nl80211.h>

/* libnl 1.x compatibility code */
#ifdef HAVE_LIBNL1
#define nl_sock nl_handle
static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h)
{
	nl_handle_destroy(h);
}
#endif /* HAVE_LIBNL1 */

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

static struct nl80211_state nl_state;

int ws80211_init(void)
{
	int err;

	struct nl80211_state *state = &nl_state;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	state->nl_sock = 0;
	return err;
}

static int error_handler(struct sockaddr_nl *nla _U_, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = (int *)arg;
	*ret = err->error;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg _U_, void *arg)
{
	int *ret = (int *)arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg _U_, void *arg)
{
	int *ret = (int *)arg;
	*ret = 0;
	return NL_STOP;
}

static int nl80211_do_cmd(struct nl_msg *msg, struct nl_cb *cb)
{
	volatile int err;

	if (!nl_state.nl_sock)
		return -ENOLINK;

	err = nl_send_auto_complete(nl_state.nl_sock, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, (void *)&err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, (void *)&err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, (void *)&err);

	while (err > 0)
		nl_recvmsgs(nl_state.nl_sock, cb);
 out:
	nl_cb_put(cb);

	return err;
}

struct nliface_cookie
{
	char *ifname;
	GArray *interfaces;
};

/*
 * And now for a steaming heap of suck.
 *
 * The nla_for_each_nested() macro defined by at least some versions of the
 * Linux kernel's headers doesn't do the casting required when compiling
 * with a C++ compiler or with -Wc++-compat, so we get warnings, and those
 * warnings are fatal when we compile this file.
 *
 * So we replace it with our own version, which does the requisite cast.
 */

/**
 * nla_for_each_nested - iterate over nested attributes
 * @pos: loop counter, set to current attribute
 * @nla: attribute containing the nested attributes
 * @rem: initialized to len, holds bytes currently remaining in stream
 */
#undef nla_for_each_nested
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, (struct nlattr *)nla_data(nla), nla_len(nla), rem)

static int get_phys_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));

	struct nliface_cookie *cookie = (struct nliface_cookie *)arg;

	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];

	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		{NLA_UNSPEC, 0, 0},		/* __NL80211_FREQUENCY_ATTR_INVALID */
		{NLA_U32, 0, 0},		/* NL80211_FREQUENCY_ATTR_FREQ */
		{NLA_FLAG, 0, 0},		/* NL80211_FREQUENCY_ATTR_DISABLED */
		{NLA_FLAG, 0, 0},		/* NL80211_FREQUENCY_ATTR_PASSIVE_SCAN */
		{NLA_FLAG, 0, 0},		/* NL80211_FREQUENCY_ATTR_NO_IBSS */
		{NLA_FLAG, 0, 0},		/* NL80211_FREQUENCY_ATTR_RADAR */
		{NLA_U32, 0, 0}			/* NL80211_FREQUENCY_ATTR_MAX_TX_POWER */
	};

	struct nlattr *nl_band;
	struct nlattr *nl_freq;
	struct nlattr *nl_mode;
	int bandidx = 1;
	int rem_band, rem_freq, rem_mode;
	struct ws80211_interface *iface;
	int cap_monitor = 0;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb_msg[NL80211_ATTR_WIPHY_BANDS])
		return NL_SKIP;

	if (tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]) {
		nla_for_each_nested(nl_mode, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES], rem_mode) {
			if (nla_type(nl_mode) == NL80211_IFTYPE_MONITOR)
				cap_monitor = 1;
		}
	}
	if (!cap_monitor)
		return NL_SKIP;

	iface = (struct ws80211_interface *)g_malloc0(sizeof(*iface));
	if (!iface)
		return NL_SKIP;

	iface->frequencies = g_array_new(FALSE, FALSE, sizeof(int));
	iface->channel_types = 1 << WS80211_CHAN_NO_HT;

	if (tb_msg[NL80211_ATTR_WIPHY_NAME]) {
		iface->ifname = g_strdup_printf("%s.mon",
                nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));
	}

	nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
		bandidx++;

		nla_parse(tb_band, NL80211_BAND_ATTR_MAX,
			  (struct nlattr *)nla_data(nl_band),
			  nla_len(nl_band), NULL);

#ifdef NL80211_BAND_ATTR_HT_CAPA
		if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
			gboolean ht40;
			iface->channel_types |= 1 << WS80211_CHAN_HT20;
			ht40 = !!(nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]) & 0x02);
			if (ht40) {
				iface->channel_types |= 1 << WS80211_CHAN_HT40MINUS;
				iface->channel_types |= 1 << WS80211_CHAN_HT40PLUS;
			}
		}
#endif /* NL80211_BAND_ATTR_HT_CAPA */

		nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
			uint32_t freq;
			nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
				  (struct nlattr *)nla_data(nl_freq),
				  nla_len(nl_freq), freq_policy);
			if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
				continue;
			if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
				continue;

			freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
			g_array_append_val(iface->frequencies, freq);
		}
	}

	/* Can frequency be set? Only newer versions of cfg80211 supports this */
#ifdef HAVE_NL80211_CMD_SET_CHANNEL
	if (tb_msg[NL80211_ATTR_SUPPORTED_COMMANDS]) {
		int cmd;
		struct nlattr *nl_cmd;
		nla_for_each_nested(nl_cmd, tb_msg[NL80211_ATTR_SUPPORTED_COMMANDS], cmd) {
			if(nla_get_u32(nl_cmd) == NL80211_CMD_SET_CHANNEL)
				iface->can_set_freq = TRUE;
		}
	}
#else
	iface->can_set_freq = TRUE;
#endif
	g_array_append_val(cookie->interfaces, iface);

	return NL_SKIP;
}


static int ws80211_get_phys(GArray *interfaces)
{
	struct nliface_cookie cookie;
	struct nl_msg *msg;
	struct nl_cb *cb;
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);

	cookie.interfaces = interfaces;

	genlmsg_put(msg, 0, 0, nl_state.nl80211_id, 0,
		    NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, get_phys_handler, &cookie);

	return nl80211_do_cmd(msg, cb);

}

static int get_freq_wext(const char *ifname)
{
	int fd;
	int ret = -1;
	/* Ugly hack to avoid including wireless.h */
	struct {
		char name1[IFNAMSIZ];
		__s32 m;
		__s16 e;
		__u8 i;
		__u8 flags;
	} wrq;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return -1;

	g_strlcpy(wrq.name1, ifname, IFNAMSIZ);
	/* SIOCGIWFREQ */
	if (ioctl(fd, 0x8B05, &wrq) == 0) {
		if (wrq.e == 6)
			ret = wrq.m;
	}
	close(fd);
	return ret;
}

struct __iface_info
{
	struct ws80211_iface_info *pub;
	int type;
	int phyidx;
};

static int get_iface_info_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct __iface_info *iface_info = (struct __iface_info *)arg;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_IFTYPE]) {
		iface_info->type = nla_get_u32(tb_msg[NL80211_ATTR_IFTYPE]);
	}
	if (tb_msg[NL80211_ATTR_WIPHY]) {
		iface_info->phyidx = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
	}

	if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
		iface_info->pub->current_freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
		iface_info->pub->current_chan_type = WS80211_CHAN_NO_HT;

		if (tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
			switch (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_CHANNEL_TYPE])) {

			case NL80211_CHAN_NO_HT:
				iface_info->pub->current_chan_type = WS80211_CHAN_NO_HT;
				break;

			case NL80211_CHAN_HT20:
				iface_info->pub->current_chan_type = WS80211_CHAN_HT20;
				break;

			case NL80211_CHAN_HT40MINUS:
				iface_info->pub->current_chan_type = WS80211_CHAN_HT40MINUS;
				break;

			case NL80211_CHAN_HT40PLUS:
				iface_info->pub->current_chan_type = WS80211_CHAN_HT40PLUS;
				break;
			}
		}

	}
	return NL_SKIP;
}


static int __ws80211_get_iface_info(const char *name, struct __iface_info *iface_info)
{
	int devidx;
	struct nl_msg *msg;
	struct nl_cb *cb;
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);

	devidx = if_nametoindex(name);

	genlmsg_put(msg, 0, 0, nl_state.nl80211_id, 0,
		    0, NL80211_CMD_GET_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, get_iface_info_handler, iface_info);

	if (nl80211_do_cmd(msg, cb))
		return -1;

	/* Old kernels cant get the current freq via netlink. Try WEXT too :( */
	if (iface_info->pub->current_freq == -1)
		iface_info->pub->current_freq = get_freq_wext(name);
	return 0;

nla_put_failure:
	fprintf(stderr, "building message failed\n");
	return -1;
}

int ws80211_get_iface_info(const char *name, struct ws80211_iface_info *iface_info)
{
	struct __iface_info __iface_info;

	memset(iface_info, 0, sizeof(*iface_info));
	__iface_info.pub = iface_info;
	__iface_info.type = -1;
	__iface_info.phyidx= -1;
	__iface_info.pub->current_freq = -1;
	__iface_info.pub->current_chan_type = WS80211_CHAN_NO_HT;

	return __ws80211_get_iface_info(name, &__iface_info);
}

static int ws80211_populate_devices(GArray *interfaces)
{
	FILE *fh;
	char line[200];
	char *t;
	gchar *t2;
	char *ret;
	int i;
	unsigned int j;

	struct ws80211_iface_info pub;
	struct __iface_info iface_info;
	struct ws80211_interface *iface;

	/* Get a list of phy's that can handle monitor mode */
	ws80211_get_phys(interfaces);

	fh = g_fopen("/proc/net/dev", "r");
	if(!fh) {
		fprintf(stderr, "Cannot open /proc/net/dev");
		return -ENOENT;
	}

	/* Skip the first two lines */
	for (i = 0; i < 2; i++) {
		ret = fgets(line, sizeof(line), fh);
		if (ret == NULL) {
			fprintf(stderr, "Error parsing /proc/net/dev");
			fclose(fh);
			return -1;
		}
	}

	/* Update names of user created monitor interfaces */
	while(fgets(line, sizeof(line), fh)) {
		t = index(line, ':');
		if (!t)
			continue;
		*t = 0;
		t = line;
		while (*t && *t == ' ')
			t++;
		memset(&iface_info, 0, sizeof(iface_info));
		iface_info.pub = &pub;
		__ws80211_get_iface_info(t, &iface_info);

		if (iface_info.type == NL80211_IFTYPE_MONITOR) {
			for (j = 0; j < interfaces->len; j++) {
				iface = g_array_index(interfaces, struct ws80211_interface *, j);
				t2 = g_strdup_printf("phy%d.mon", iface_info.phyidx);
				if (t2) {
					if (!strcmp(t2, iface->ifname)) {
						g_free(iface->ifname);
						iface->ifname = g_strdup(t);
					}
					g_free(t2);
				}
			}
		}
	}
	fclose(fh);
	return 0;
}

static int ws80211_iface_up(const char *ifname)
{
	int sock;
	struct ifreq ifreq;

	sock = socket(AF_PACKET, SOCK_RAW, 0);
	if (sock == -1)
		return -1;

	g_strlcpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));

	if (ioctl(sock, SIOCGIFFLAGS, &ifreq))
		goto out_err;

	ifreq.ifr_flags |= IFF_UP;

	if (ioctl(sock, SIOCSIFFLAGS, &ifreq))
		goto out_err;

	close(sock);
	return 0;

out_err:
	close(sock);
	return -1;
}

static int ws80211_create_on_demand_interface(const char *name)
{
	int devidx, phyidx, err;
	struct nl_msg *msg;
	struct nl_cb *cb;

	devidx = if_nametoindex(name);
	if (devidx)
		return ws80211_iface_up(name);

	if (sscanf(name, "phy%d.mon", &phyidx) != 1)
		return -EINVAL;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

	genlmsg_put(msg, 0, 0, nl_state.nl80211_id, 0,
		    0, NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, phyidx);

	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, name);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	err = nl80211_do_cmd(msg, cb);
	if (err)
		return err;
	return ws80211_iface_up(name);

nla_put_failure:
	fprintf(stderr, "building message failed\n");
	return 2;
}

int ws80211_set_freq(const char *name, int freq, int chan_type)
{
	int devidx, err;
	struct nl_msg *msg;
	struct nl_cb *cb;

	err = ws80211_create_on_demand_interface(name);
	if (err)
		return err;

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);

	devidx = if_nametoindex(name);

#ifdef HAVE_NL80211_CMD_SET_CHANNEL
	genlmsg_put(msg, 0, 0, nl_state.nl80211_id, 0,
		    0, NL80211_CMD_SET_CHANNEL, 0);
#else
	genlmsg_put(msg, 0, 0, nl_state.nl80211_id, 0,
		    0, NL80211_CMD_SET_WIPHY, 0);
#endif

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);

	switch (chan_type) {

#ifdef NL80211_BAND_ATTR_HT_CAPA
	case WS80211_CHAN_NO_HT:
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);
		break;

	case WS80211_CHAN_HT20:
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT20);
		break;

	case WS80211_CHAN_HT40MINUS:
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT40MINUS);
		break;

	case WS80211_CHAN_HT40PLUS:
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT40PLUS);
		break;
#endif

	default:
		break;
	}
	err = nl80211_do_cmd(msg, cb);
	return err;

nla_put_failure:
	fprintf(stderr, "building message failed\n");
	return 2;

}

void ws80211_free_interfaces(GArray *interfaces)
{
	struct ws80211_interface *iface;

	if (!interfaces)
		return;

	while (interfaces->len) {
		iface = g_array_index(interfaces, struct ws80211_interface *, 0);
		g_array_remove_index(interfaces, 0);
		g_array_free(iface->frequencies, TRUE);
		g_free(iface->ifname);
		g_free(iface);
	}
	g_array_free(interfaces, TRUE);
}

GArray* ws80211_find_interfaces(void)
{
	GArray *interfaces;

	if (!nl_state.nl_sock)
		return NULL;

	interfaces = g_array_new(FALSE, FALSE, sizeof(struct ws80211_interface *));
	if (!interfaces)
		return NULL;

	if (ws80211_populate_devices(interfaces)) {
		ws80211_free_interfaces(interfaces);
		return NULL;
	}
	return interfaces;
}

int ws80211_frequency_to_channel(int freq)
{
	if (freq == 2484)
		return 14;

	if (freq < 2484)
		return (freq - 2407) / 5;

	return freq / 5 - 1000;
}

int
ws80211_str_to_chan_type(const gchar *s)
{
	int ret = -1;
	if (!s)
		return -1;

	if (!strcmp(s, CHAN_NO_HT))
		ret = WS80211_CHAN_NO_HT;
	if (!strcmp(s, CHAN_HT20))
		ret = WS80211_CHAN_HT20;
	if (!strcmp(s, CHAN_HT40MINUS))
		ret = WS80211_CHAN_HT40MINUS;
	if (!strcmp(s, CHAN_HT40PLUS))
		ret = WS80211_CHAN_HT40PLUS;
	return ret;
}

const gchar
*ws80211_chan_type_to_str(int type)
{
	switch (type) {
	case WS80211_CHAN_NO_HT:
		return CHAN_NO_HT;
	case WS80211_CHAN_HT20:
		return CHAN_HT20;
	case WS80211_CHAN_HT40MINUS:
		return CHAN_HT40MINUS;
	case WS80211_CHAN_HT40PLUS:
		return CHAN_HT40PLUS;
	}
	return NULL;
}

#else /* HAVE_LIBNL */
int ws80211_init(void)
{
	return -1;
}

GArray* ws80211_find_interfaces(void)
{
	return NULL;
}

int ws80211_get_iface_info(const char *name _U_, struct ws80211_iface_info *iface_info _U_)
{
	return -1;
}

void ws80211_free_interfaces(GArray *interfaces _U_)
{
}

int ws80211_frequency_to_channel(int freq _U_)
{
	return -1;
}

int ws80211_set_freq(const char *name _U_, int freq _U_, int chan_type _U_)
{
	return -1;
}

int ws80211_str_to_chan_type(const gchar *s _U_)
{
	return -1;
}

const gchar *ws80211_chan_type_to_str(int type _U_)
{
	return NULL;
}
#endif /* HAVE_LIBNL && HAVE_NL80211 */
