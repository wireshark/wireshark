/* sshdig.c
 * sshdig is extcap tool used to capture events on a remote host via SSH
 *
 * Copied from sshdump.c, copyright 2015, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "sshdig"

#include <extcap/extcap-base.h>
#include <extcap/ssh-base.h>
#include <wsutil/application_flavor.h>
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

static char* sshdig_extcap_interface;
#define DEFAULT_SSHDIG_EXTCAP_INTERFACE "sshdig"

#define SSHDIG_VERSION_MAJOR "1"
#define SSHDIG_VERSION_MINOR "0"
#define SSHDIG_VERSION_RELEASE "0"

#define SSH_READ_BLOCK_SIZE 256

enum {
    EXTCAP_BASE_OPTIONS_ENUM,
    OPT_HELP,
    OPT_VERSION,
    OPT_REMOTE_HOST,
    OPT_REMOTE_PORT,
    OPT_REMOTE_USERNAME,
    OPT_REMOTE_PASSWORD,
    OPT_REMOTE_CAPTURE_COMMAND_SELECT,
    OPT_REMOTE_CAPTURE_COMMAND,
    OPT_SSHKEY,
    OPT_SSHKEY_PASSPHRASE,
    OPT_PROXYCOMMAND,
    OPT_SSH_SHA1,
    OPT_REMOTE_COUNT,
    OPT_REMOTE_PRIV,
    OPT_REMOTE_PRIV_USER,
    OPT_REMOTE_MODERN_BPF,
    OPT_REMOTE_IO_SNAPLEN,
};

static struct ws_option longopts[] = {
    EXTCAP_BASE_OPTIONS,
    {"help", ws_no_argument, NULL, OPT_HELP},
    {"version", ws_no_argument, NULL, OPT_VERSION},
    SSH_BASE_OPTIONS,
    {"remote-capture-command-select", ws_required_argument, NULL, OPT_REMOTE_CAPTURE_COMMAND_SELECT},
    {"remote-capture-command", ws_required_argument, NULL, OPT_REMOTE_CAPTURE_COMMAND},
    {"remote-priv", ws_required_argument, NULL, OPT_REMOTE_PRIV},
    {"remote-priv-user", ws_required_argument, NULL, OPT_REMOTE_PRIV_USER},
    {"remote-modern-bpf", ws_no_argument, NULL, OPT_REMOTE_MODERN_BPF},
    {"remote-io-snaplen", ws_required_argument, NULL, OPT_REMOTE_IO_SNAPLEN},
    {0, 0, 0, 0}};

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

static ssh_channel run_ssh_command(ssh_session sshs, const char* capture_command_select,
        const char* capture_command, const char* privilege,
        const char* cfilter, const uint32_t count, bool modern_bpf, const uint32_t io_snaplen)
{
    char* cmdline = NULL;
    ssh_channel channel;
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

    if (capture_command_select == NULL || !g_strcmp0(capture_command_select, "other")) {
        if (capture_command && *capture_command) {
            cmdline = g_strdup(capture_command);
            ws_debug("Remote capture command has disabled other options");
        } else {
            capture_command_select = "sysdig";
        }
    }

    /* escape parameters to go save with the shell */
    if (!g_strcmp0(capture_command_select, "sysdig")) {
        char *count_str = NULL;
        char *io_snaplen_str = NULL;
        char *quoted_filter = NULL;

        quoted_filter = g_shell_quote(cfilter ? cfilter : "");
        if (count > 0) {
            count_str = ws_strdup_printf(" --numevents=%u", count);
        }
        if (io_snaplen > 0) {
            io_snaplen_str = ws_strdup_printf(" --snaplen=%u", io_snaplen);
        }

        cmdline = ws_strdup_printf("%s sysdig --unbuffered %s --write=- %s %s %s",
                privilege,
                modern_bpf ? " --modern-bpf" : "",
                count_str ? count_str : "",
                io_snaplen_str ? io_snaplen_str : "",
                quoted_filter);

        g_free(count_str);
        g_free(io_snaplen_str);
        g_free(quoted_filter);
    }

    ws_debug("Running: %s", cmdline);
    if (ssh_channel_request_exec(channel, cmdline) != SSH_OK) {
        ws_warning("Can't request exec");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        channel = NULL;
    }

    g_free(cmdline);

    return channel;
}

static int ssh_open_remote_connection(const ssh_params_t* params, const char* cfilter,
        const char* capture_command_select, const char* capture_command, const char* privilege,
        const uint32_t count, const char* fifo, bool modern_bpf, const uint32_t io_snaplen)
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

    channel = run_ssh_command(sshs, capture_command_select, capture_command, privilege, cfilter, count, modern_bpf, io_snaplen);

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

    if (!interface) {
        ws_warning("ERROR: No interface specified.");
        return EXIT_FAILURE;
    }

    if (g_strcmp0(interface, sshdig_extcap_interface)) {
        ws_warning("ERROR: interface must be %s", sshdig_extcap_interface);
        return EXIT_FAILURE;
    }

    printf("arg {number=%u}{call=--remote-host}{display=Remote SSH server address}"
            "{type=string}{tooltip=The remote SSH host. It can be both "
            "an IP address or a hostname}{required=true}{group=Server}\n", inc++);
    printf("arg {number=%u}{call=--remote-port}{display=Remote SSH server port}"
            "{type=unsigned}{default=22}{tooltip=The remote SSH host port (1-65535)}"
            "{range=1,65535}{group=Server}\n", inc++);
    printf("arg {number=%u}{call=--remote-username}{display=Remote SSH server username}"
            "{type=string}{tooltip=The remote SSH username. If not provided, "
            "the current user will be used}{group=Authentication}\n", inc++);
    printf("arg {number=%u}{call=--remote-password}{display=Remote SSH server password}"
            "{type=password}{tooltip=The SSH password, used when other methods (SSH agent "
            "or key files) are unavailable.}{group=Authentication}\n", inc++);
    printf("arg {number=%u}{call=--sshkey}{display=Path to SSH private key}"
            "{type=fileselect}{tooltip=The path on the local filesystem of the private SSH key (OpenSSH format)}"
            "{mustexist=true}{group=Authentication}\n", inc++);
    printf("arg {number=%u}{call=--sshkey-passphrase}{display=SSH key passphrase}"
            "{type=password}{tooltip=Passphrase to unlock the SSH private key}{group=Authentication}\n",
            inc++);
    printf("arg {number=%u}{call=--proxycommand}{display=ProxyCommand}"
            "{type=string}{tooltip=The command to use as proxy for the SSH connection}"
            "{group=Authentication}\n", inc++);
    printf("arg {number=%u}{call=--ssh-sha1}{display=Support SHA-1 keys (deprecated)}"
            "{type=boolflag}{tooltip=Support keys and key exchange algorithms using SHA-1 (deprecated)}{group=Authentication}"
            "\n", inc++);
    printf("arg {number=%u}{call=--remote-capture-command-select}{display=Remote capture command selection}"
            "{type=radio}{tooltip=The remote capture command to build a command line for}{group=Capture}\n", inc);
    printf("value {arg=%u}{value=sysdig}{display=sysdig}\n", inc);
    // XXX Add falcodump?
    printf("value {arg=%u}{value=other}{display=Other:}\n", inc++);
    printf("arg {number=%u}{call=--remote-capture-command}{display=Remote capture command}"
            "{type=string}{tooltip=The remote command used to capture}{group=Capture}\n", inc++);
    printf("arg {number=%u}{call=--remote-priv}{display=Gain capture privilege on the remote machine}"
            "{type=radio}{tooltip=Optionally prepend the capture command with sudo or doas on the remote machine}"
            "{group=Capture}\n", inc);
    printf("value {arg=%u}{value=none}{display=none}{default=true}\n", inc);
    printf("value {arg=%u}{value=sudo}{display=sudo}\n", inc);
    printf("value {arg=%u}{value=doas -n}{display=doas}\n", inc++);
    printf("arg {number=%u}{call=--remote-priv-user}{display=Privileged user name for sudo or doas}"
            "{type=string}{tooltip=User name of privileged user to execute the capture command on the remote machine}"
            "{group=Capture}\n", inc++);
    printf("{group=Capture}\n");
    printf("arg {number=%u}{call=--remote-count}{display=Events to capture}"
            "{type=unsigned}{default=0}{tooltip=The number of remote events to capture. (Default: inf)}"
            "{group=Capture}\n", inc++);
    printf("arg {number=%u}{call=--remote-io-snaplen}{display=I/O snapshot length}"
           "{type=unsigned}{default=80}{tooltip=The number of bytes to capture in each I/O event. (Default: 80)}"
           "{group=Capture}\n", inc++);
    printf("arg {number=%u}{call=--remote-modern-bpf}{display=Use eBPF}{type=boolflag}{default=true}"
            "{tooltip=Use eBPF for capture. With this no kernel module is required}{group=Capture}\n", inc++);

    extcap_config_debug(&inc);

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    char* err_msg;
    int result;
    int option_idx = 0;
    ssh_params_t* ssh_params = ssh_params_new();
    char* remote_capture_command_select = NULL;
    char* remote_capture_command = NULL;
    uint32_t count = 0;
    uint32_t io_snaplen = 0;
    int ret = EXIT_FAILURE;
    extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
    char* help_url;
    char* help_header = NULL;
    char* priv = NULL;
    char* priv_user = NULL;
    char* interface_description = g_strdup("SSH remote syscall capture");
    bool modern_bpf = 0;

    /* Set the program name. */
    g_set_prgname("sshdig");

    /* Initialize log handler early so we can have proper logging during startup. */
    extcap_log_init();

    sshdig_extcap_interface = g_path_get_basename(argv[0]);
    if (g_str_has_suffix(sshdig_extcap_interface, ".exe")) {
        sshdig_extcap_interface[strlen(sshdig_extcap_interface) - 4] = '\0';
    }

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    set_application_flavor(APPLICATION_FLAVOR_STRATOSHARK);
    err_msg = configuration_init(argv[0]);
    if (err_msg != NULL) {
        ws_warning("Can't get pathname of directory containing the extcap program: %s.",
                err_msg);
        g_free(err_msg);
    }

    help_url = data_file_url("sshdig.html");
    extcap_base_set_util_info(extcap_conf, argv[0], SSHDIG_VERSION_MAJOR, SSHDIG_VERSION_MINOR,
            SSHDIG_VERSION_RELEASE, help_url);
    g_free(help_url);
    add_libssh_info(extcap_conf);
    if (g_strcmp0(sshdig_extcap_interface, DEFAULT_SSHDIG_EXTCAP_INTERFACE)) {
        char* temp = interface_description;
        interface_description = ws_strdup_printf("%s, custom version", interface_description);
        g_free(temp);
    }
    extcap_base_register_interface(extcap_conf, sshdig_extcap_interface, interface_description, 147, "Remote capture dependent DLT");
    g_free(interface_description);

    help_header = ws_strdup_printf(
            " %s --extcap-interfaces\n"
            " %s --extcap-interface=%s --extcap-dlts\n"
            " %s --extcap-interface=%s --extcap-config\n"
            " %s --extcap-interface=%s --remote-host myhost --remote-port 22222 "
            "--fifo=FILENAME --capture\n", argv[0], argv[0], sshdig_extcap_interface, argv[0],
            sshdig_extcap_interface, argv[0], sshdig_extcap_interface);
    extcap_help_add_header(extcap_conf, help_header);
    g_free(help_header);
    extcap_help_add_option(extcap_conf, "--help", "print this help");
    extcap_help_add_option(extcap_conf, "--version", "print the version");
    extcap_help_add_option(extcap_conf, "--remote-host <host>", "the remote SSH host");
    extcap_help_add_option(extcap_conf, "--remote-port <port>", "the remote SSH port");
    extcap_help_add_option(extcap_conf, "--remote-username <username>", "the remote SSH username");
    extcap_help_add_option(extcap_conf, "--remote-password <password>", "the remote SSH password. If not specified, ssh-agent and ssh-key are used");
    extcap_help_add_option(extcap_conf, "--sshkey <private key path>", "the path of the SSH key (OpenSSH format)");
    extcap_help_add_option(extcap_conf, "--sshkey-passphrase <private key passphrase>", "the passphrase to unlock private SSH key");
    extcap_help_add_option(extcap_conf, "--proxycommand <proxy command>", "the command to use as proxy for the SSH connection");
    extcap_help_add_option(extcap_conf, "--ssh-sha1", "support keys and key exchange using SHA-1 (deprecated)");
    extcap_help_add_option(extcap_conf, "--remote-capture-command-select <selection>", "sysdig or other remote capture command");
    extcap_help_add_option(extcap_conf, "--remote-capture-command <capture command>", "the remote capture command");
    extcap_help_add_option(extcap_conf, "--remote-priv <selection>", "none, sudo or doas");
    extcap_help_add_option(extcap_conf, "--remote-priv-user <username>", "privileged user name");
    extcap_help_add_option(extcap_conf, "--remote-count <count>", "the number of events to capture");
    extcap_help_add_option(extcap_conf, "--remote-modern-bpf", "use eBPF");
    extcap_help_add_option(extcap_conf, "--remote-io-snaplen <snaplen>", "the number of bytes to capture in each I/O event");

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

            case OPT_PROXYCOMMAND:
                g_free(ssh_params->proxycommand);
                ssh_params->proxycommand = g_strdup(ws_optarg);
                break;

            case OPT_SSH_SHA1:
                ssh_params->ssh_sha1 = true;
                break;

            case OPT_REMOTE_CAPTURE_COMMAND_SELECT:
                g_free(remote_capture_command_select);
                remote_capture_command_select = g_strdup(ws_optarg);
                break;

            case OPT_REMOTE_CAPTURE_COMMAND:
                g_free(remote_capture_command);
                remote_capture_command = g_strdup(ws_optarg);
                break;

            case OPT_REMOTE_PRIV:
                g_free(priv);
                priv = g_strdup(ws_optarg);
                break;

            case OPT_REMOTE_PRIV_USER:
                g_free(priv_user);
                priv_user = g_strdup(ws_optarg);
                break;

            case OPT_REMOTE_COUNT:
                if (!ws_strtou32(ws_optarg, NULL, &count)) {
                    ws_warning("Invalid value for count: %s", ws_optarg);
                    goto end;
                }
                break;

            case OPT_REMOTE_MODERN_BPF:
                    modern_bpf = true;
                break;

            case OPT_REMOTE_IO_SNAPLEN:
                if (!ws_strtou32(ws_optarg, NULL, &io_snaplen)) {
                    ws_warning("Invalid value for I/O snapshot length: %s", ws_optarg);
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
        char* privilege;

        if (!ssh_params->host) {
            ws_warning("Missing parameter: --remote-host");
            goto end;
        }

        if ((priv) && g_strcmp0(priv, "none") && strlen(g_strstrip(priv))) {
            if ((priv_user) && strlen(g_strstrip(priv_user)))
                /* Both sudo and doas use the same command line option */
                privilege = g_strconcat(priv, " -u ", priv_user, NULL);
            else
                privilege = g_strdup(priv);
        } else {
            privilege = g_strdup("");
        }

        ssh_params_set_log_level(ssh_params, extcap_conf->debug);
        ret = ssh_open_remote_connection(ssh_params, extcap_conf->capture_filter,
                remote_capture_command_select, remote_capture_command,
                privilege, count, extcap_conf->fifo, modern_bpf, io_snaplen);
        g_free(privilege);
    } else {
        ws_debug("You should not come here... maybe some parameter missing?");
        ret = EXIT_FAILURE;
    }

end:
    /* clean up stuff */
    ssh_params_free(ssh_params);
    g_free(remote_capture_command_select);
    g_free(remote_capture_command);
    g_free(priv);
    g_free(priv_user);
    extcap_base_cleanup(&extcap_conf);
    return ret;
}
