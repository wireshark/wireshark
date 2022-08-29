/* dpauxmon.c
 * dpauxmon is an extcap tool used to monitor DisplayPort AUX channel traffic
 * coming in from the kernel via generic netlink
 * Copyright 2018, Dirk Eibach, Guntermann & Drunck GmbH <dirk.eibach@gdsys.cc>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "dpauxmon"

#include <wireshark.h>

#include "extcap-base.h"

#include <wsutil/strtoi.h>
#include <wsutil/filesystem.h>
#include <wsutil/netlink.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>
#include <writecap/pcapio.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>

#include <errno.h>

#include <linux/genetlink.h>

#include "dpauxmon_user.h"

#define PCAP_SNAPLEN 128

#define DPAUXMON_EXTCAP_INTERFACE "dpauxmon"
#define DPAUXMON_VERSION_MAJOR "0"
#define DPAUXMON_VERSION_MINOR "1"
#define DPAUXMON_VERSION_RELEASE "0"

FILE* pcap_fp = NULL;

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_INTERFACE_ID,
};

static struct ws_option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	/* Generic application options */
	{ "help", ws_no_argument, NULL, OPT_HELP},
	{ "version", ws_no_argument, NULL, OPT_VERSION},
	/* Interfaces options */
	{ "interface_id", ws_required_argument, NULL, OPT_INTERFACE_ID},
	{ 0, 0, 0, 0 }
};

static struct nla_policy dpauxmon_attr_policy[DPAUXMON_ATTR_MAX + 1] = {
	[DPAUXMON_ATTR_IFINDEX] = { .type = NLA_U32 },
	[DPAUXMON_ATTR_FROM_SOURCE] = { .type = NLA_FLAG },
	[DPAUXMON_ATTR_TIMESTAMP] = { .type = NLA_MSECS },
};

struct family_handler_args {
	const char *group;
	int id;
};

static int list_config(char *interface)
{
	unsigned inc = 0;

	if (!interface) {
		ws_warning("No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, DPAUXMON_EXTCAP_INTERFACE)) {
		ws_warning("interface must be %s", DPAUXMON_EXTCAP_INTERFACE);
		return EXIT_FAILURE;
	}

	printf("arg {number=%u}{call=--interface_id}{display=Interface index}"
		"{type=unsigned}{range=1,65535}{default=%u}{tooltip=The dpauxmon interface index}\n",
		inc++, 0);

	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}

static int setup_dumpfile(const char* fifo, FILE** fp)
{
	guint64 bytes_written = 0;
	int err;

	if (!g_strcmp0(fifo, "-")) {
		*fp = stdout;
		return EXIT_SUCCESS;
	}

	*fp = fopen(fifo, "wb");
	if (!(*fp)) {
		ws_warning("Error creating output file: %s", g_strerror(errno));
		return EXIT_FAILURE;
	}

	if (!libpcap_write_file_header(*fp, 275, PCAP_SNAPLEN, FALSE, &bytes_written, &err)) {
		ws_warning("Can't write pcap file header");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int dump_packet(FILE* fp, const char* buf, const guint32 buflen, guint64 ts_usecs)
{
	guint64 bytes_written = 0;
	int err;
	int ret = EXIT_SUCCESS;

	if (!libpcap_write_packet(fp, ts_usecs / 1000000, ts_usecs % 1000000, buflen, buflen, buf, &bytes_written, &err)) {
		ws_warning("Can't write packet");
		ret = EXIT_FAILURE;
	}

	fflush(fp);

	return ret;
}

static int error_handler(struct sockaddr_nl *nla _U_, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = (int*)arg;
	*ret = err->error;
	return NL_STOP;
}

static int ack_handler(struct nl_msg *msg _U_, void *arg)
{
	int *ret = (int*)arg;
	*ret = 0;
	return NL_STOP;
}

static int family_handler(struct nl_msg *msg, void *arg)
{
	struct family_handler_args *grp = (struct family_handler_args *)arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int rem_mcgrp;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
		struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

		nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
			  (struct nlattr *)nla_data(mcgrp), nla_len(mcgrp), NULL);

		if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
			continue;

		if (strncmp((const char*)nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
			    grp->group,
			    nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
			continue;

		grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);

		break;
	}

	return NL_SKIP;
}

static int nl_get_multicast_id(struct nl_sock *sock, int family,
			       const char *group)
{
	struct nl_msg *msg;
	struct nl_cb *cb;
	int ret, ctrlid;
	struct family_handler_args grp = {
		.group = group,
		.id = -ENOENT,
	};

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		ret = -ENOMEM;
		goto out_fail_cb;
	}

	ctrlid = genl_ctrl_resolve(sock, "nlctrl");

	genlmsg_put(msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);

	ret = -ENOBUFS;
	NLA_PUT_U16(msg, CTRL_ATTR_FAMILY_ID, family);

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0)
		goto nla_put_failure;

	ret = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, family_handler, &grp);

	while (ret > 0)
		nl_recvmsgs(sock, cb);

	if (ret == 0)
		ret = grp.id;
nla_put_failure:
	nl_cb_put(cb);
out_fail_cb:
	nlmsg_free(msg);
	return ret;
}

/*
 * netlink callback handlers
 */

static int nl_receive_timeout(struct nl_sock* sk, struct sockaddr_nl* nla, unsigned char** buf, struct ucred** creds)
{
	struct pollfd fds = {nl_socket_get_fd(sk), POLLIN, 0};
	int poll_res = poll(&fds, 1, 500);

	if (poll_res < 0) {
		ws_debug("poll() failed in nl_receive_timeout");
		g_usleep(500000);
		return -nl_syserr2nlerr(errno);
	}

	return poll_res ? nl_recv(sk, nla, buf, creds) : 0;
}

static int send_start(struct nl_sock *sock, int family, unsigned int interface_id)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
	int res = 0;

	msg = nlmsg_alloc();
	if (msg == NULL) {
		ws_critical("Unable to allocate netlink message");
		return -ENOMEM;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0,
		    DPAUXMON_CMD_START, 1);
	if (hdr == NULL) {
		ws_critical("Unable to write genl header");
		res = -ENOMEM;
		goto out_free;
	}

	if ((err = nla_put_u32(msg, DPAUXMON_ATTR_IFINDEX, interface_id)) < 0) {
		ws_critical("Unable to add attribute: %s", nl_geterror(err));
		res = -EIO;
		goto out_free;
	}

	if ((err = nl_send_auto_complete(sock, msg)) < 0)
		ws_debug("Starting monitor failed, already running? :%s", nl_geterror(err));

out_free:
	nlmsg_free(msg);
	return res;
}

static void send_stop(struct nl_sock *sock, int family, unsigned int interface_id)
{
	struct nl_msg *msg;
	void *hdr;
	int err;

	msg = nlmsg_alloc();
	if (msg == NULL) {
		ws_critical("Unable to allocate netlink message");
		return;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0,
		    DPAUXMON_CMD_STOP, 1);
	if (hdr == NULL) {
		ws_critical("Unable to write genl header");
		goto out_free;
	}

	if ((err = nla_put_u32(msg, DPAUXMON_ATTR_IFINDEX, interface_id)) < 0) {
		ws_critical("Unable to add attribute: %s", nl_geterror(err));
		goto out_free;
	}

	if ((err = nl_send_auto_complete(sock, msg)) < 0) {
		ws_critical("Unable to send message: %s", nl_geterror(err));
		goto out_free;
	}

out_free:
	nlmsg_free(msg);
}

static int handle_data(struct nl_cache_ops *unused _U_, struct genl_cmd *cmd _U_,
			 struct genl_info *info, void *arg _U_)
{
	unsigned char *data;
	guint32 data_size;
	guint64 ts = 0;
	guint8 packet[21] = { 0x00 };

	if (!info->attrs[DPAUXMON_ATTR_DATA])
		return NL_SKIP;

	data = (unsigned char*)nla_data(info->attrs[DPAUXMON_ATTR_DATA]);
	data_size = nla_len(info->attrs[DPAUXMON_ATTR_DATA]);

	if (data_size > 19) {
		ws_debug("Invalid packet size %u", data_size);
		return NL_SKIP;
	}

	if (info->attrs[DPAUXMON_ATTR_TIMESTAMP])
		ts = nla_get_msecs(info->attrs[DPAUXMON_ATTR_TIMESTAMP]);

	packet[1] = info->attrs[DPAUXMON_ATTR_FROM_SOURCE] ? 0x01 : 0x00;

	memcpy(&packet[2], data, data_size);

	if (dump_packet(pcap_fp, packet, data_size + 2, ts) == EXIT_FAILURE)
		extcap_end_application = FALSE;

	return NL_OK;
}

static int parse_cb(struct nl_msg *msg, void *arg _U_)
{
	return genl_handle_msg(msg, NULL);
}

static struct genl_cmd cmds[] = {
#if 0
	{
		.c_id		= DPAUXMON_CMD_START,
		.c_name		= "dpauxmon start",
		.c_maxattr	= DPAUXMON_ATTR_MAX,
		.c_attr_policy	= dpauxmon_attr_policy,
		.c_msg_parser	= &handle_start,
	},
	{
		.c_id		= DPAUXMON_CMD_STOP,
		.c_name		= "dpauxmon stop",
		.c_maxattr	= DPAUXMON_ATTR_MAX,
		.c_attr_policy	= dpauxmon_attr_policy,
		.c_msg_parser	= &handle_stop,
	},
#endif
	{
		.c_id		= DPAUXMON_CMD_DATA,
		.c_name		= "dpauxmon data",
		.c_maxattr	= DPAUXMON_ATTR_MAX,
		.c_attr_policy	= dpauxmon_attr_policy,
		.c_msg_parser	= &handle_data,
	},
};

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

static struct genl_ops ops = {
	.o_name = "dpauxmon",
	.o_cmds = cmds,
	.o_ncmds = ARRAY_SIZE(cmds),
};

struct nl_sock *sock;

static void run_listener(const char* fifo, unsigned int interface_id)
{
	int err;
	int grp;
	struct nl_cb *socket_cb;

	if (setup_dumpfile(fifo, &pcap_fp) == EXIT_FAILURE) {
		if (pcap_fp)
			goto close_out;
	}

	if (!(sock = nl_socket_alloc())) {
		ws_critical("Unable to allocate netlink socket");
		goto close_out;
	}

	if ((err = nl_connect(sock, NETLINK_GENERIC)) < 0) {
		ws_critical("Unable to connect netlink socket: %s",
			   nl_geterror(err));
		goto free_out;
	}

	if ((err = genl_register_family(&ops)) < 0) {
		ws_critical("Unable to register Generic Netlink family: %s",
			   nl_geterror(err));
		goto err_out;
	}

	if ((err = genl_ops_resolve(sock, &ops)) < 0) {
		ws_critical("Unable to resolve family name: %s",
			   nl_geterror(err));
		goto err_out;
	}

	/* register notification handler callback */
	if ((err = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
			parse_cb, NULL)) < 0) {
		ws_critical("Unable to modify valid message callback %s",
			   nl_geterror(err));
		goto err_out;
	}

	grp = nl_get_multicast_id(sock, ops.o_id, "notify");
	nl_socket_add_membership(sock, grp);

	if (!(socket_cb = nl_socket_get_cb(sock))) {
		ws_warning("Can't overwrite recv callback");
	} else {
		nl_cb_overwrite_recv(socket_cb, nl_receive_timeout);
		nl_cb_put(socket_cb);
	}

	err = send_start(sock, ops.o_id, interface_id);
	if (err)
		goto err_out;

	nl_socket_disable_seq_check(sock);

	ws_debug("DisplayPort AUX monitor running on interface %u", interface_id);

	while(!extcap_end_application) {
		if ((err = nl_recvmsgs_default(sock)) < 0)
			ws_warning("Unable to receive message: %s", nl_geterror(err));
	}

	send_stop(sock, ops.o_id, interface_id);

err_out:
	nl_close(sock);
free_out:
	nl_socket_free(sock);
close_out:
	fclose(pcap_fp);
}

int main(int argc, char *argv[])
{
	char* configuration_init_error;
	int option_idx = 0;
	int result;
	unsigned int interface_id = 0;
	int ret = EXIT_FAILURE;
	extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
	char* help_header = NULL;

	/* Initialize log handler early so we can have proper logging during startup. */
	extcap_log_init("dpauxmon");

	/*
	 * Get credential information for later use.
	 */
	init_process_policies();

	/*
	 * Attempt to get the pathname of the directory containing the
	 * executable file.
	 */
	configuration_init_error = configuration_init(argv[0], NULL);
	if (configuration_init_error != NULL) {
		ws_warning("Can't get pathname of directory containing the extcap program: %s.",
			configuration_init_error);
		g_free(configuration_init_error);
	}

	extcap_base_set_util_info(extcap_conf, argv[0], DPAUXMON_VERSION_MAJOR, DPAUXMON_VERSION_MINOR, DPAUXMON_VERSION_RELEASE,
		NULL);
	extcap_base_register_interface(extcap_conf, DPAUXMON_EXTCAP_INTERFACE, "DisplayPort AUX channel monitor capture", 275, "DisplayPort AUX channel monitor");

	help_header = ws_strdup_printf(
		" %s --extcap-interfaces\n"
		" %s --extcap-interface=%s --extcap-dlts\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --interface_id 0 --fifo myfifo --capture",
		argv[0], argv[0], DPAUXMON_EXTCAP_INTERFACE, argv[0], DPAUXMON_EXTCAP_INTERFACE, argv[0], DPAUXMON_EXTCAP_INTERFACE);
	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);
	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");
	extcap_help_add_option(extcap_conf, "--port <port> ", "the dpauxmon interface index");

	ws_opterr = 0;
	ws_optind = 0;

	if (argc == 1) {
		extcap_help_print(extcap_conf);
		goto end;
	}

	while ((result = ws_getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {
		switch (result) {

		case OPT_HELP:
			extcap_help_print(extcap_conf);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_VERSION:
			extcap_version_print(extcap_conf);
			goto end;

		case OPT_INTERFACE_ID:
			if (!ws_strtou32(ws_optarg, NULL, &interface_id)) {
				ws_warning("Invalid interface id: %s", ws_optarg);
				goto end;
			}
			break;

		case ':':
			/* missing option argument */
			ws_warning("Option '%s' requires an argument", argv[ws_optind - 1]);
			break;

		default:
			if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, ws_optarg)) {
				ws_warning("Invalid option: %s", argv[ws_optind - 1]);
				goto end;
			}
		}
	}

	extcap_cmdline_debug(argv, argc);

	if (ws_optind != argc) {
		ws_warning("Unexpected extra option: %s", argv[ws_optind]);
		goto end;
	}

	if (extcap_base_handle_interface(extcap_conf)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (!extcap_base_register_graceful_shutdown_cb(extcap_conf, NULL)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (extcap_conf->show_config) {
		ret = list_config(extcap_conf->interface);
		goto end;
	}

	if (extcap_conf->capture)
		run_listener(extcap_conf->fifo, interface_id);

end:
	/* clean up stuff */
	extcap_base_cleanup(&extcap_conf);
	return ret;
}
