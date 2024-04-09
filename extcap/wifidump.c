/* wifidump.c
 * wifidump is an extcap tool used to capture Wi-Fi frames using a remote ssh host
 *
 * Adapted from sshdump.
 *
 * Copyright 2022, Adrian Granados <adrian@intuitibits.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "wifidump"

#include <extcap/extcap-base.h>
#include <extcap/ssh-base.h>
#include <wsutil/interface.h>
#include <wsutil/file_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/please_report_bug.h>
#include <wsutil/wslog.h>

#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <cli_main.h>

static char* wifidump_extcap_interface;
#ifdef _WIN32
#define DEFAULT_WIFIDUMP_EXTCAP_INTERFACE "wifidump.exe"
#else
#define DEFAULT_WIFIDUMP_EXTCAP_INTERFACE "wifidump"
#endif

#define WIFIDUMP_VERSION_MAJOR "1"
#define WIFIDUMP_VERSION_MINOR "0"
#define WIFIDUMP_VERSION_RELEASE "0"

#define SSH_READ_BLOCK_SIZE 256

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_REMOTE_HOST,
	OPT_REMOTE_PORT,
	OPT_REMOTE_USERNAME,
	OPT_REMOTE_PASSWORD,
	OPT_REMOTE_INTERFACE,
	OPT_REMOTE_CHANNEL_FREQUENCY,
	OPT_REMOTE_CHANNEL_WIDTH,
	OPT_REMOTE_FILTER,
	OPT_SSHKEY,
	OPT_SSHKEY_PASSPHRASE,
	OPT_PROXYCOMMAND,
	OPT_SSH_SHA1,
	OPT_REMOTE_COUNT
};

static const struct ws_option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	{ "help", ws_no_argument, NULL, OPT_HELP},
	{ "version", ws_no_argument, NULL, OPT_VERSION},
	SSH_BASE_OPTIONS,
	{ "remote-channel-frequency", ws_required_argument, NULL, OPT_REMOTE_CHANNEL_FREQUENCY},
	{ "remote-channel-width", ws_required_argument, NULL, OPT_REMOTE_CHANNEL_WIDTH},
	{ 0, 0, 0, 0}
};

static const char * remote_capture_functions =
"\n"
"function iface_down {\n"
"  local iface=$1\n"
"  sudo ip link set $iface down > /dev/null 2>&1\n"
"}\n"
"\n"
"function iface_up {\n"
"  local iface=$1\n"
"  sudo ip link set $iface up > /dev/null 2>&1\n"
"}\n"
"\n"
"function iface_monitor {\n"
"  local iface=$1\n"
"  sudo iw dev $iface set monitor control otherbss > /dev/null 2>&1 ||\n"
"  sudo iw dev $iface set type monitor control otherbss > /dev/null 2>&1\n"
"}\n"
"\n"
"function iface_scan {\n"
"  local iface=$1\n"
"  iface_down $iface &&\n"
"  sudo iw dev $iface set type managed > /dev/null 2>&1 &&\n"
"  iface_up $iface &&\n"
"  sudo iw dev $iface scan > /dev/null 2>&1\n"
"}\n"
"\n"
"function iface_config {\n"
"  local iface=$1\n"
"  local freq=$2\n"
"  local ch_width=$3\n"
"  local center_freq=$4\n"
"  if [ $freq -eq $center_freq ]; then\n"
"    sudo iw dev $1 set freq $freq $ch_width 2>&1\n"
"  else\n"
"    sudo iw dev $1 set freq $freq $ch_width $center_freq 2>&1\n"
"  fi\n"
"}\n"
"\n"
"function iface_start {\n"
"  local iface=$1\n"
"  local count=$2\n"
"  local filter=\"${@:3}\"\n"
"  if [ $count -gt 0 ]; then\n"
"    sudo tcpdump -i $iface -U -w - -c $count $filter\n"
"  else\n"
"    sudo tcpdump -i $iface -U -w - $filter\n"
"  fi\n"
"}\n"
"\n"
"function capture_generic {\n"
"  local iface=$1\n"
"  local freq=$2\n"
"  local ch_width=$3\n"
"  local center_freq=$4\n"
"  local count=$5\n"
"  local filter=\"${@:6}\"\n"
"  if ! { iwconfig $iface | grep Monitor > /dev/null 2>&1; }; then\n"
"    iface_down    $iface &&\n"
"    iface_monitor $iface &&\n"
"    iface_up      $iface\n"
"  else\n"
"    iface_monitor $iface\n"
"  fi\n"
"  iface_config  $iface $freq $ch_width $center_freq &&\n"
"  iface_start   $iface $count $filter\n"
"}\n"
"\n"
"function capture_iwlwifi {\n"
"  local iface=$1\n"
"  local freq=$2\n"
"  local ch_width=$3\n"
"  local center_freq=$4\n"
"  local count=$5\n"
"  local filter=\"${@:6}\"\n"
"  INDEX=`sudo iw dev $iface info | grep wiphy | grep -Eo '[0-9]+'`\n"
"  sudo iw phy phy${INDEX} channels | grep $freq | grep -i disabled > /dev/null 2>&1 &&\n"
"  iface_scan $iface\n"
"  MON=${iface}mon\n"
"  sudo iw $iface interface add $MON type monitor flags none > /dev/null 2>&1\n"
"  iface_up $MON &&\n"
"  iface_down $iface &&\n"
"  iface_config $MON $freq $ch_width $center_freq &&\n"
"  iface_start $MON $count $filter\n"
"}\n"
"\n"
"function capture {\n"
"  local iface=$1\n"
"  local freq=$2\n"
"  local ch_width=$3\n"
"  local center_freq=$4\n"
"  local count=$5\n"
"  local filter=\"${@:6}\"\n"
"  if [ \"$iface\" == \"auto\" ]; then\n"
"    iface=`sudo iw dev | grep -i interface | awk '{ print $2 }' | sort | head -n 1`\n"
"  fi\n"
"  local driver=`/usr/sbin/ethtool -i $iface | grep driver | awk '{ print $2 }'`\n"
"  if [ $driver = \"iwlwifi\" ]; then\n"
"    capture_iwlwifi $iface $freq $ch_width $center_freq $count $filter\n"
"  else\n"
"    capture_generic $iface $freq $ch_width $center_freq $count $filter\n"
"  fi\n"
"}\n"
"\n";

static unsigned int wifi_freqs_2dot4_5ghz[] = {
	2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462,
	2467, 2472, 2484,
	5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5500, 5520, 5540, 5560, 5580,
  5600, 5620, 5640, 5660, 5680, 5700, 5720, 5745, 5765, 5785, 5805, 5825,
	0
};

static unsigned int freq_to_channel(unsigned int freq_mhz) {
	if (freq_mhz == 2484)
		return 14;
	else if (freq_mhz >= 2412 && freq_mhz <= 2484)
		return ((freq_mhz - 2412) / 5) + 1;
	else if (freq_mhz >= 5160 && freq_mhz <= 5885)
		return ((freq_mhz - 5180) / 5) + 36;
	else if (freq_mhz >= 5955 && freq_mhz <= 7115)
		return ((freq_mhz - 5955) / 5) + 1;
	else
		return 0;
}

static const char *freq_to_band(unsigned int freq_mhz)
{
	if (freq_mhz >= 2412 && freq_mhz <= 2484)
		return "2.4 GHz";
	else if (freq_mhz >= 5160 && freq_mhz <= 5885)
		return "5 GHz";
	else if (freq_mhz >= 5955 && freq_mhz <= 7115)
		return "6 GHz";
	else
	 return NULL;
}

static unsigned int center_freq(unsigned int freq_mhz, unsigned int ch_width_mhz) {

	unsigned int start_freq;

	if (ch_width_mhz == 20) {
		return freq_mhz;
	}
  else if (ch_width_mhz == 40) {
    if (freq_mhz >= 5180 && freq_mhz <= 5720) {
			for (start_freq = 5180; start_freq <= 5700; start_freq += ch_width_mhz) {
      	if (freq_mhz >= start_freq && freq_mhz <= (start_freq + 20))
        	return ((start_freq * 2) + 20) / 2;
			}
		}
    else if (freq_mhz >= 5745 && freq_mhz <= 5765)
      return 5755;
    else if (freq_mhz >= 5785 && freq_mhz <= 5805)
      return 5795;
    else if (freq_mhz >= 5955 && freq_mhz <= 7095) {
			for (start_freq = 5955; start_freq <= 7075; start_freq += ch_width_mhz) {
        if (freq_mhz >= start_freq && freq_mhz <= (start_freq + 20))
          return ((start_freq * 2) + 20) / 2;
			}
		}
	}
  else if (ch_width_mhz == 80) {
    if (freq_mhz >= 5180 && freq_mhz <= 5660) {
			for (start_freq = 5180; start_freq <= 5660; start_freq += ch_width_mhz) {
      	if (freq_mhz >= start_freq && freq_mhz <= (start_freq + 60))
        	return ((start_freq * 2) + 60) / 2;
			}
		}
    else if (freq_mhz >= 5745 && freq_mhz <= 5805)
      return 5775;
    else if (freq_mhz >= 5955 && freq_mhz <= 7055) {
			for (start_freq = 5955; start_freq <= 6995; start_freq += ch_width_mhz) {
        if (freq_mhz >= start_freq && freq_mhz <= (start_freq + 60))
        	return ((start_freq * 2) + 60) / 2;
			}
		}
	}
  else if (ch_width_mhz == 160) {
    if (freq_mhz >= 5180 && freq_mhz <= 5640) {
			for (start_freq = 5180; start_freq <= 5500; start_freq += ch_width_mhz) {
        if (freq_mhz >= start_freq && freq_mhz <= (start_freq + 140))
          return ((start_freq * 2) + 140) / 2;
			}
		}
    else if (freq_mhz >= 5955 && freq_mhz <= 7055) {
			for (start_freq = 5955; start_freq <= 6915; start_freq += ch_width_mhz) {
      	if (freq_mhz >= start_freq && freq_mhz <= (start_freq + 140))
        	return ((start_freq * 2) + 140) / 2;
			}
		}
	}

  return -1;
}

static int ssh_loop_read(ssh_channel channel, FILE* fp)
{
	int nbytes;
	int ret = EXIT_SUCCESS;
	char buffer[SSH_READ_BLOCK_SIZE];

	/* read from stdin until data are available */
	while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
		nbytes = ssh_channel_read(channel, buffer, SSH_READ_BLOCK_SIZE, 0);
		if (nbytes < 0) {
			ws_warning("Error reading from channel");
			goto end;
		}
		if (nbytes == 0) {
			break;
		}
		if (fwrite(buffer, 1, nbytes, fp) != (unsigned)nbytes) {
			ws_warning("Error writing to fifo");
			ret = EXIT_FAILURE;
			goto end;
		}
		fflush(fp);
	}

	/* read loop finished... maybe something wrong happened. Read from stderr */
	while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
		nbytes = ssh_channel_read(channel, buffer, SSH_READ_BLOCK_SIZE, 1);
		if (nbytes < 0) {
			ws_warning("Error reading from channel");
			goto end;
		}
		if (fwrite(buffer, 1, nbytes, stderr) != (unsigned)nbytes) {
			ws_warning("Error writing to stderr");
			break;
		}
	}

end:
	if (ssh_channel_send_eof(channel) != SSH_OK) {
		ws_warning("Error sending EOF in ssh channel");
		ret = EXIT_FAILURE;
	}
	return ret;
}

static ssh_channel run_ssh_command(ssh_session sshs, const char* capture_functions,
	const char* iface, const uint16_t channel_frequency, const uint16_t channel_width,
	const uint16_t center_frequency, const char* cfilter, const uint32_t count)
{
	char* cmdline;
	ssh_channel channel;
	char* quoted_iface = NULL;
	char* quoted_filter = NULL;
	char* count_str = NULL;
	unsigned int remote_port = 22;

	channel = ssh_channel_new(sshs);
	if (!channel) {
		ws_warning("Can't create channel");
		return NULL;
	}

	if (ssh_channel_open_session(channel) != SSH_OK) {
		ws_warning("Can't open session");
		ssh_channel_free(channel);
		return NULL;
	}

	ssh_options_get_port(sshs, &remote_port);

	quoted_iface = iface ? g_shell_quote(iface) : NULL;
	quoted_filter = g_shell_quote(cfilter ? cfilter : "");
	cmdline = ws_strdup_printf("%s capture %s %u %u %u %u %s",
		capture_functions,
		quoted_iface ? quoted_iface : "auto",
		channel_frequency,
		channel_width,
		center_frequency,
		count,
		quoted_filter);

	ws_debug("Running: %s", cmdline);
	if (ssh_channel_request_exec(channel, cmdline) != SSH_OK) {
		ws_warning("Can't request exec");
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		channel = NULL;
	}

	g_free(quoted_iface);
	g_free(quoted_filter);
	g_free(cmdline);
	g_free(count_str);

	return channel;
}

static int ssh_open_remote_connection(const ssh_params_t* params, const char* capture_functions,
	const char* iface, const uint16_t channel_frequency, const uint16_t channel_width,
	const uint16_t center_frequency, const char* cfilter, const uint32_t count, const char* fifo)
{
	ssh_session sshs = NULL;
	ssh_channel channel = NULL;
	FILE* fp = stdout;
	int ret = EXIT_FAILURE;
	char* err_info = NULL;

	if (g_strcmp0(fifo, "-")) {
		/* Open or create the output file */
		fp = fopen(fifo, "wb");
		if (fp == NULL) {
			ws_warning("Error creating output file: %s (%s)", fifo, g_strerror(errno));
			return EXIT_FAILURE;
		}
	}

	sshs = create_ssh_connection(params, &err_info);

	if (!sshs) {
		ws_warning("Error creating connection.");
		goto cleanup;
	}

	channel = run_ssh_command(sshs, capture_functions, iface, channel_frequency,
		channel_width, center_frequency, cfilter, count);

	if (!channel) {
		ws_warning("Can't run ssh command.");
		goto cleanup;
	}

	/* read from channel and write into fp */
	if (ssh_loop_read(channel, fp) != EXIT_SUCCESS) {
		ws_warning("Error in read loop.");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	ret = EXIT_SUCCESS;
cleanup:
	if (err_info)
		ws_warning("%s", err_info);
	g_free(err_info);

	/* clean up and exit */
	ssh_cleanup(&sshs, &channel);

	if (g_strcmp0(fifo, "-"))
		fclose(fp);
	return ret;
}

static int list_config(char *interface)
{
	unsigned inc = 0;
	int i, psc;

	if (!interface) {
		ws_warning("ERROR: No interface specified.");
		return EXIT_FAILURE;
	}

	if (g_strcmp0(interface, wifidump_extcap_interface)) {
		ws_warning("ERROR: interface must be %s", wifidump_extcap_interface);
		return EXIT_FAILURE;
	}

	// Server tab
	printf("arg {number=%u}{call=--remote-host}{display=Remote SSH server address}"
		"{type=string}{tooltip=The remote SSH host. It can be both "
		"an IP address or a hostname}{required=true}{group=Server}\n", inc++);
	printf("arg {number=%u}{call=--remote-port}{display=Remote SSH server port}"
		"{type=unsigned}{tooltip=The remote SSH host port (1-65535)}"
		"{range=1,65535}{group=Server}\n", inc++);

	// Authentication tab
	printf("arg {number=%u}{call=--remote-username}{display=Remote SSH server username}"
		"{type=string}{tooltip=The remote SSH username. If not provided, "
		"the current user will be used}{group=Authentication}\n", inc++);
	printf("arg {number=%u}{call=--remote-password}{display=Remote SSH server password}"
		"{type=password}{tooltip=The SSH password, used when other methods (SSH agent "
		"or key files) are unavailable.}{group=Authentication}\n", inc++);
	printf("arg {number=%u}{call=--sshkey}{display=Path to SSH private key}"
		"{type=fileselect}{tooltip=The path on the local filesystem of the private ssh key}"
		"{mustexist=true}{group=Authentication}\n", inc++);
	printf("arg {number=%u}{call=--sshkey-passphrase}{display=SSH key passphrase}"
		"{type=password}{tooltip=Passphrase to unlock the SSH private key}{group=Authentication}\n",
		inc++);
	printf("arg {number=%u}{call=--ssh-sha1}{display=Support SHA-1 keys (deprecated)}"
	       "{type=boolflag}{tooltip=Support keys and key exchange algorithms using SHA-1 (deprecated)}{group=Authentication}"
	       "\n", inc++);


	// Capture tab
	printf("arg {number=%u}{call=--remote-interface}{display=Remote interface}"
		"{type=string}{tooltip=The remote network interface used to capture"
		"}{default=auto}{group=Capture}\n", inc++);
	printf("arg {number=%u}{call=--remote-channel-frequency}{display=Remote channel}"
		"{type=selector}{tooltip=The remote channel used to capture}{group=Capture}\n", inc);

	unsigned int freq = 0;
	for (i = 0; (freq = wifi_freqs_2dot4_5ghz[i]); i++) {
		printf("value {arg=%u}{value=%u}{display=%s, Channel %u}\n", inc, freq, freq_to_band(freq), freq_to_channel(freq));
	}

	for (freq = 5955, psc = 3; freq <= 7115; freq += 20, psc++) {
		printf("value {arg=%u}{value=%u}{display=%s, Channel %u%s}\n", inc, freq,
			freq_to_band(freq), freq_to_channel(freq), (psc % 4 == 0) ? " (PSC)" : "");
	}
	inc++;

	printf("arg {number=%u}{call=--remote-channel-width}{display=Remote channel width}"
		"{type=selector}{tooltip=The remote channel width used to capture}"
		"{group=Capture}\n", inc);
	printf("value {arg=%u}{value=20}{display=20 MHz}\n", inc);
	printf("value {arg=%u}{value=40}{display=40 MHz}\n", inc);
	printf("value {arg=%u}{value=80}{display=80 MHz}\n", inc);
	printf("value {arg=%u}{value=160}{display=160 MHz}\n", inc);
	inc++;

	printf("arg {number=%u}{call=--remote-filter}{display=Remote capture filter}{type=string}"
		"{tooltip=The remote capture filter}{group=Capture}\n", inc++);
	printf("arg {number=%u}{call=--remote-count}{display=Frames to capture}"
		"{type=unsigned}{tooltip=The number of remote frames to capture.}"
		"{group=Capture}\n", inc++);

	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}

static char* concat_filters(const char* extcap_filter, const char* remote_filter)
{
	if (!extcap_filter && remote_filter)
		return g_strdup(remote_filter);

	if (!remote_filter && extcap_filter)
		return g_strdup(extcap_filter);

	if (!remote_filter && !extcap_filter)
		return NULL;

	return ws_strdup_printf("(%s) and (%s)", extcap_filter, remote_filter);
}

int main(int argc, char *argv[])
{
	char* err_msg;
	int result;
	int option_idx = 0;
	ssh_params_t* ssh_params = ssh_params_new();
	char* remote_interface = NULL;
	uint16_t remote_channel_frequency = 0;
	uint16_t remote_channel_width = 0;
	uint16_t remote_center_frequency = 0;
	char* remote_filter = NULL;
	uint32_t count = 0;
	int ret = EXIT_FAILURE;
	extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
	char* help_url;
	char* help_header = NULL;
	char* interface_description = g_strdup("Wi-Fi remote capture");

	/* Initialize log handler early so we can have proper logging during startup. */
	extcap_log_init("wifidump");

	wifidump_extcap_interface = g_path_get_basename(argv[0]);

	/*
	 * Get credential information for later use.
	 */
	init_process_policies();

	/*
	 * Attempt to get the pathname of the directory containing the
	 * executable file.
	 */
	err_msg = configuration_init(argv[0], NULL);
	if (err_msg != NULL) {
		ws_warning("Can't get pathname of directory containing the extcap program: %s.",
			err_msg);
		g_free(err_msg);
	}

	help_url = data_file_url("wifidump.html");
	extcap_base_set_util_info(extcap_conf, argv[0], WIFIDUMP_VERSION_MAJOR, WIFIDUMP_VERSION_MINOR,
		WIFIDUMP_VERSION_RELEASE, help_url);
	g_free(help_url);
	add_libssh_info(extcap_conf);
	if (g_strcmp0(wifidump_extcap_interface, DEFAULT_WIFIDUMP_EXTCAP_INTERFACE)) {
		char* temp = interface_description;
		interface_description = ws_strdup_printf("%s, custom version", interface_description);
		g_free(temp);
	}
	extcap_base_register_interface(extcap_conf, wifidump_extcap_interface, interface_description, 147, "Remote capture dependent DLT");
	g_free(interface_description);

	help_header = ws_strdup_printf(
		" %s --extcap-interfaces\n"
		" %s --extcap-interface=%s --extcap-dlts\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --remote-host myhost --remote-port 22222 "
		"--remote-username myuser --remote-interface wlan0 --remote-channel-frequency 5180 "
		"--remote-channel-width 40 --fifo=FILENAME --capture\n", argv[0], argv[0], wifidump_extcap_interface, argv[0],
		wifidump_extcap_interface, argv[0], wifidump_extcap_interface);
	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);
	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");
	extcap_help_add_option(extcap_conf, "--remote-host <host>", "the remote SSH host");
	extcap_help_add_option(extcap_conf, "--remote-port <port>", "the remote SSH port");
	extcap_help_add_option(extcap_conf, "--remote-username <username>", "the remote SSH username");
	extcap_help_add_option(extcap_conf, "--remote-password <password>", "the remote SSH password. If not specified, ssh-agent and ssh-key are used");
	extcap_help_add_option(extcap_conf, "--sshkey <public key path>", "the path of the ssh key");
	extcap_help_add_option(extcap_conf, "--sshkey-passphrase <public key passphrase>", "the passphrase to unlock public ssh");
	extcap_help_add_option(extcap_conf, "--ssh-sha1", "support keys and key exchange using SHA-1 (deprecated)");
	extcap_help_add_option(extcap_conf, "--remote-interface <iface>", "the remote capture interface");
	extcap_help_add_option(extcap_conf, "--remote-channel-frequency <channel_frequency>", "the remote channel frequency in MHz");
	extcap_help_add_option(extcap_conf, "--remote-channel-width <channel_width>", "the remote channel width in MHz");
	extcap_help_add_option(extcap_conf, "--remote-filter <filter>", "a filter for remote capture");
	extcap_help_add_option(extcap_conf, "--remote-count <count>", "the number of frames to capture");

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
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_REMOTE_HOST:
			g_free(ssh_params->host);
			ssh_params->host = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_PORT:
			if (!ws_strtou16(ws_optarg, NULL, &ssh_params->port) || ssh_params->port == 0) {
				ws_warning("Invalid port: %s", ws_optarg);
				goto end;
			}
			break;

		case OPT_REMOTE_USERNAME:
			g_free(ssh_params->username);
			ssh_params->username = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_PASSWORD:
			g_free(ssh_params->password);
			ssh_params->password = g_strdup(ws_optarg);
			memset(ws_optarg, 'X', strlen(ws_optarg));
			break;

		case OPT_SSHKEY:
			g_free(ssh_params->sshkey_path);
			ssh_params->sshkey_path = g_strdup(ws_optarg);
			break;

		case OPT_SSHKEY_PASSPHRASE:
			g_free(ssh_params->sshkey_passphrase);
			ssh_params->sshkey_passphrase = g_strdup(ws_optarg);
			memset(ws_optarg, 'X', strlen(ws_optarg));
			break;

		case OPT_SSH_SHA1:
			ssh_params->ssh_sha1 = true;
			break;

		case OPT_REMOTE_INTERFACE:
			g_free(remote_interface);
			remote_interface = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_CHANNEL_FREQUENCY:
			if (!ws_strtou16(ws_optarg, NULL, &remote_channel_frequency)) {
				ws_warning("Invalid channel frequency: %s", ws_optarg);
				goto end;
			}
			break;

		case OPT_REMOTE_CHANNEL_WIDTH:
			if (!ws_strtou16(ws_optarg, NULL, &remote_channel_width)) {
				ws_warning("Invalid channel width: %s", ws_optarg);
				goto end;
			}
			break;

		case OPT_REMOTE_FILTER:
			g_free(remote_filter);
			remote_filter = g_strdup(ws_optarg);
			break;

		case OPT_REMOTE_COUNT:
			if (!ws_strtou32(ws_optarg, NULL, &count)) {
				ws_warning("Invalid value for count: %s", ws_optarg);
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

	if (extcap_base_handle_interface(extcap_conf)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (extcap_conf->show_config) {
		ret = list_config(extcap_conf->interface);
		goto end;
	}

	err_msg = ws_init_sockets();
	if (err_msg != NULL) {
		ws_warning("ERROR: %s", err_msg);
		g_free(err_msg);
		ws_warning("%s", please_report_bug());
		goto end;
	}

	if (extcap_conf->capture) {
		char* filter;

		if (!ssh_params->host) {
			ws_warning("Missing parameter: --remote-host");
			goto end;
		}
		remote_center_frequency = center_freq(remote_channel_frequency, remote_channel_width);
		filter = concat_filters(extcap_conf->capture_filter, remote_filter);
		ssh_params_set_log_level(ssh_params, extcap_conf->debug);
		ret = ssh_open_remote_connection(ssh_params, remote_capture_functions,
			remote_interface, remote_channel_frequency, remote_channel_width, remote_center_frequency,
			filter, count, extcap_conf->fifo);
		g_free(filter);
	} else {
		ws_debug("You should not come here... maybe some parameter missing?");
		ret = EXIT_FAILURE;
	}

end:
	/* clean up stuff */
	ssh_params_free(ssh_params);
	g_free(remote_interface);
	g_free(remote_filter);
	extcap_base_cleanup(&extcap_conf);
	return ret;
}

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
