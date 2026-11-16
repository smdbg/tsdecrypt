/* smdbg fork modifications, 2026-11-16: see CHANGELOG.md. */
/*
 * tsdecrypt
 * Copyright (C) 2011-2012 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License (COPYING file) for more details.
 *
 */
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <sys/resource.h>
#include <poll.h>
#include <limits.h>

#include "libfuncs/libfuncs.h"

#include "data.h"
#include "util.h"
#include "csa.h"
#include "camd.h"
#include "process.h"
#include "udp.h"
#include "notify.h"
#include "filter.h"
#include "input-shift.h"

#define FIRST_REPORT_SEC 3

#define PROGRAM_NAME "tsdecrypt"
static const char *program_id = PROGRAM_NAME " v" VERSION " (" GIT_VER ", " DLIB ")";

int keep_running = 1;
static FILE *log_file = NULL;
static char *log_filename = NULL;
static int local_syslog = 0;
static int remote_syslog = 0;

static int packet_from_file = 0;
static int packet_buflen;
static uint8_t packet_buf[256];
static enum msg_type packet_type = ECM_MSG;

extern int ai_family;

static void do_log(FILE *f, time_t now, const char *msg) {
	char date[64];
	struct tm tm;
	// There is no need to show timestamps when debug options are used
	if (packet_from_file) {
		fprintf(f, "%s", msg);
		return;
	}
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%F %H:%M:%S", localtime_r(&now, &tm));
	fprintf(f, "%s | %s", date, msg);
}

static void LOG_func(const char *msg) {
	time_t now = time(NULL);
	do_log(stderr, now, msg);
	if (log_file)
		do_log(log_file, now, msg);
	if (local_syslog)
		syslog(LOG_INFO, msg, strlen(msg));
	if (remote_syslog)
		LOG(msg);
}

static const char short_options[] = "i:d:N:90:Sl:L:F:I:1:RzM:T:W:O:o:t:rk:g:upwx3yc:C:Y:Q:A:s:U:P:B:46eZ:Ef:a:X:vqH:G:2:KJ:D:jbhVn:m:";

enum { OPT_INPUT_SHIFT = 1000, OPT_INPUT_SHIFT_MEMORY, OPT_INPUT_SHIFT_STATUS, OPT_INPUT_PASSTHROUGH };

// Unused short options: 578
static const struct option long_options[] = {
	{ "ident",				required_argument, NULL, 'i' },
	{ "daemon",				required_argument, NULL, 'd' },
	{ "syslog",				no_argument,       NULL, 'S' },
	{ "syslog-host",		required_argument, NULL, 'l' },
	{ "syslog-port",		required_argument, NULL, 'L' },
	{ "log-file",			required_argument, NULL, 'F' },
	{ "notify-program",		required_argument, NULL, 'N' },
	{ "notify-wait",		no_argument,       NULL, '9' },
	{ "status-file",		required_argument, NULL, '0' },

	{ "input",				required_argument, NULL, 'I' },
	{ "input-source",		required_argument, NULL, '1' },
	{ "input-rtp",			no_argument,       NULL, 'R' },
	{ "input-ignore-disc",	no_argument,       NULL, 'z' },
	{ "input-service",		required_argument, NULL, 'M' },
	{ "input-buffer",		required_argument, NULL, 'T' },
	{ "input-shift",         required_argument, NULL, OPT_INPUT_SHIFT },
	{ "input-shift-memory",  required_argument, NULL, OPT_INPUT_SHIFT_MEMORY },
	{ "input-shift-status",  required_argument, NULL, OPT_INPUT_SHIFT_STATUS },
	{ "input-passthrough",   no_argument,       NULL, OPT_INPUT_PASSTHROUGH },
	{ "input-dump",			required_argument, NULL, 'W' },

	{ "output",				required_argument, NULL, 'O' },
	{ "output-intf",		required_argument, NULL, 'o' },
	{ "output-ttl",			required_argument, NULL, 't' },
	{ "output-rtp",			no_argument,       NULL, 'r' },
	{ "output-rtp-ssrc",	required_argument, NULL, 'k' },
	{ "output-tos",			required_argument, NULL, 'g' },
	{ "no-output-on-error",	no_argument,       NULL, 'u' },
	{ "no-output-filter",	no_argument,       NULL, 'p' },
	{ "output-nit-pass",	no_argument,       NULL, 'y' },
	{ "output-eit-pass",	no_argument,       NULL, 'w' },
	{ "output-tdt-pass",	no_argument,       NULL, 'x' },
	{ "output-enc-pass",	no_argument,       NULL, '3' },

	{ "ca-system",			required_argument, NULL, 'c' },
	{ "caid",				required_argument, NULL, 'C' },
	{ "const-cw",			required_argument, NULL, 'Y' },
	{ "biss-key",			required_argument, NULL, 'Q' },

	{ "camd-proto",			required_argument, NULL, 'A' },
	{ "camd-server",		required_argument, NULL, 's' },
	{ "camd-user",			required_argument, NULL, 'U' },
	{ "camd-pass",			required_argument, NULL, 'P' },
	{ "camd-des-key",		required_argument, NULL, 'B' },
	{ "ipv4",				no_argument,       NULL, '4' },
	{ "ipv6",				no_argument,       NULL, '6' },

	{ "emm",				no_argument,       NULL, 'e' },
	{ "emm-pid",			required_argument, NULL, 'Z' },
	{ "emm-only",			no_argument,       NULL, 'E' },
	{ "emm-report-time",	required_argument, NULL, 'f' },
	{ "emm-filter",			required_argument, NULL, 'a' },

	{ "ecm-pid",			required_argument, NULL, 'X' },
	{ "ecm-only",			no_argument,       NULL, 'v' },
	{ "ecm-report-time",	required_argument, NULL, 'H' },
	{ "ecm-irdeto-type",	required_argument, NULL, 'G' },
	{ "ecm-irdeto-chid",	required_argument, NULL, '2' },
	{ "ecm-no-log",			no_argument      , NULL, 'K' },
	{ "cw-warn-time",		required_argument, NULL, 'J' },

	{ "ecm-and-emm-only",	no_argument,       NULL, 'q' },

	{ "debug",				required_argument, NULL, 'D' },
	{ "pid-report",			no_argument,       NULL, 'j' },
	{ "bench",				no_argument,       NULL, 'b' },
	{ "help",				no_argument,       NULL, 'h' },
	{ "version",			no_argument,       NULL, 'V' },

	{ "ecm-file",			required_argument, NULL, 'n' },
	{ "emm-file",			required_argument, NULL, 'm' },

	{ 0, 0, 0, 0 }
};

static void show_help(struct ts *ts) {
	printf("%s\n", program_id);
	printf("Copyright (C) 2011-2012 Unix Solutions Ltd.\n");
	printf("\n");
	printf("	Usage: " PROGRAM_NAME " [opts]\n");
	printf("\n");
	printf("Main options:\n");
	printf(" -i --ident <server>        | Format PROVIDER/CHANNEL. Default: empty\n");
	printf(" -d --daemon <pidfile>      | Daemonize program and write pid file.\n");
	printf(" -N --notify-program <prg>  | Execute <prg> to report events. Default: empty\n");
	printf(" -9 --notify-wait           | Enable one by one notification delivery.\n");
	printf("                            . Default: not set (async, deliver ASAP)\n");
	printf(" -0 --status-file <file>    | Save current program status in file.\n");
	printf("\n");
	printf("Input options:\n");
	printf(" -I --input <source>        | Where to read from. File or multicast address.\n");
	printf("                            .    -I 224.0.0.1:5000    (v4 multicast)\n");
	printf("                            .    -I [ff01::1111]:5000 (v6 multicast)\n");
	printf("                            .    -I file://in.ts      (read from file)\n");
	printf("                            . By default the input is stdin.\n");
	printf(" -1 --input-source <ipaddr> | Set multicast input source ip.\n");
	printf(" -R --input-rtp             | Enable RTP input\n");
	printf(" -z --input-ignore-disc     | Do not report discontinuty errors in input.\n");
	printf(" -M --input-service <srvid> | Choose service id when input is MPTS.\n");
	printf(" -T --input-buffer <ms>     | Set input buffer time in ms. Default: %u\n", ts->input_buffer_time);
	printf("    --input-shift <ms>      | Delay whole input BEFORE ECM processing (0..10000). Default: 0\n");
	printf("    --input-shift-memory <B>| Hard RAM queue cap in bytes (required with nonzero shift).\n");
	printf("    --input-shift-status <f>| Atomic JSON queue counters, every 10 seconds; use tmpfs.\n");
	printf("    --input-passthrough    | Forward whole TS unchanged; no CAMD, parsing or decryption.\n");
	printf(" -W --input-dump <filename> | Save input stream in file.\n");
	printf("\n");
	printf("Output options:\n");
	printf(" -O --output <dest>         | Where to send output. File or multicast address.\n");
	printf("                            .    -O 239.0.0.1:5000    (v4 multicast)\n");
	printf("                            .    -O [ff01::2222]:5000 (v6 multicast)\n");
	printf("                            .    -O file://out.ts     (write to file)\n");
	printf("                            . By default the output is stdout.\n");
	printf(" -o --output-intf <value>   | Set multicast output interface.\n");
	printf("                            . Default for IPv4: 0.0.0.0 (intf addr)\n");
	printf("                            . Default for IPv6: -1      (intf number)\n");
	printf(" -t --output-ttl <ttl>      | Set multicast ttl. Default: %d\n", ts->output.ttl);
	printf(" -r --output-rtp            | Enable RTP output.\n");
	printf(" -k --output-rtp-ssrc <id>  | Set RTP SSRC. Default: %u\n", ts->rtp_ssrc);
	printf(" -g --output-tos <tos>      | Set TOS value of output packets. Default: none\n");
	printf(" -u --no-output-on-error    | Do not output data when the code word is missing.\n");
	printf(" -p --no-output-filter      | Disable output filtering. Default: %s\n", ts->pid_filter ? "enabled" : "disabled");
	printf(" -3 --output-enc-pass       | Output the stream even if can not be decrypted.\n");
	printf(" -y --output-nit-pass       | Pass through NIT.\n");
	printf(" -w --output-eit-pass       | Pass through EIT (EPG).\n");
	printf(" -x --output-tdt-pass       | Pass through TDT/TOT.\n");
	printf("\n");
	printf("CA options:\n");
	printf(" -c --ca-system <ca_sys>    | Process input EMM/ECM from <ca_sys>.\n");
	printf("                            | Valid systems are: CONAX (default), CRYPTOWORKS,\n");
	printf("                            .   IRDETO, SECA (MEDIAGUARD), VIACCESS,\n");
	printf("                            .   VIDEOGUARD (NDS), NAGRA, DRECRYPT, BULCRYPT,\n");
	printf("                            .   GRIFFIN and DGCRYPT.\n");
	printf(" -C --caid <caid>           | Set CAID. Default: Taken from --ca-system.\n");
	printf(" -Y --const-cw <codeword>   | Set constant code word for decryption.\n");
	printf("                            . Example cw: a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8\n");
	printf(" -Q --biss-key <biss-key>   | Set BISS key for decryption.\n");
	printf("                            . Example key: 112233445566\n");
	printf("\n");
	printf("CAMD server options:\n");
	printf(" -A --camd-proto <proto>    | Set CAMD network protocol.\n");
	printf("                            . Valid protocols are: CS378X (default) and NEWCAMD\n");
	printf(" -s --camd-server <host>    | Set CAMD server address. Default port: 2233\n");
	printf("                            . Example IPv4 addr and port: 127.0.0.1:2233\n");
	printf("                            . Example IPv6 addr and port: [2a00::1014]:2233\n");
	printf("                            . Example hostname          : example.com\n");
	printf("                            . Example hostname and port : example.com:2233\n");
	printf("                            . Example IPv4 hostname     : ipv4.google.com\n");
	printf("                            . Example IPv6 hostname     : ipv6.google.com\n");
	printf(" -U --camd-user <user>      | Set CAMD server user. Default: %s\n", ts->camd.user);
	printf(" -P --camd-pass <pass>      | Set CAMD server password. Default: %s\n", ts->camd.pass);
	printf(" -B --camd-des-key <key>    | Set DES key for newcamd protocol.\n");
	printf("                            . Default: %s\n", ts->camd.newcamd.hex_des_key);
	printf(" -4 --ipv4                  | Use only IPv4 addresses of the camd server.\n");
	printf(" -6 --ipv6                  | Use only IPv6 addresses of the camd server.\n");
	printf("\n");
	printf("EMM options:\n");
	printf(" -e --emm                   | Enable sending EMM's to CAMD. Default: %s\n", ts->process_emm ? "enabled" : "disabled");
	printf(" -E --emm-only              | Send only EMMs to CAMD, skipping ECMs and without\n");
	printf("                            .   decoding the input stream.\n");
	printf(" -Z --emm-pid <pid>         | Force EMM pid. Default: none\n");
	printf(" -f --emm-report-time <sec> | Report each <sec> seconds how much EMMs have been\n");
	printf("                            .   received/processed. Set <sec> to 0 to disable\n");
	printf("                            .   the reports. Default: %d sec\n", ts->emm_report_interval);
	printf(" -a --emm-filter <filter>   | Add EMM filter defined by <filter>.\n");
	printf("                            . This option can be used multiple times (max:%u).\n", MAX_FILTERS);
	printf("                            . See FILTERING file for more info.\n");
	printf("\n");
	printf("ECM options:\n");
	printf(" -X --ecm-pid <pid>         | Force ECM pid. Default: none\n");
	printf(" -v --ecm-only              | Send only ECMs to CAMD, skipping EMMs and without\n");
	printf("                            .   decoding the input stream.\n");
	printf(" -H --ecm-report-time <sec> | Report each <sec> how much ECMs and CWs have been\n");
	printf("                            .   processed/skipped. Set <sec> to 0 to disable\n");
	printf("                            .   the reports. Default: %d sec\n", ts->ecm_report_interval);
	printf(" -G --ecm-irdeto-type <int> | Process IRDETO ECMs with index X /0-255/\n");
	printf("                            .   It is better to use --ecm-irdeto-chid option!\n");
	printf(" -2 --ecm-irdeto-chid <int> | Set CHID to filter Irdeto ECMs (Default: 0x0000).\n");
	printf(" -K --ecm-no-log            | Disable ECM and code words logging.\n");
	printf(" -J --cw-warn-time <sec>    | Warn if no valid code word has been received.\n");
	printf("                            .   Set <sec> to 0 to disable. Default: %d sec\n", ts->cw_warn_sec);
	printf("\n");
	printf(" -q --ecm-and-emm-only      | Send ECMs and EMMs to CAMD but do not decode\n");
	printf("                            .   the input stream.\n");
	printf("\n");
	printf("Logging options:\n");
	printf(" -S --syslog                | Log messages using syslog.\n");
	printf(" -l --syslog-host <host>    | Syslog server address. Default: disabled\n");
	printf(" -L --syslog-port <port>    | Syslog server port. Default: %d\n", ts->syslog_port);
	printf(" -F --log-file <filename>   | Log to file <filename>.\n");
	printf(" -D --debug <level>         | Message debug level.\n");
	printf("                            .    0 = default messages\n");
	printf("                            .    1 = show PSI tables\n");
	printf("                            .    2 = show EMMs\n");
	printf("                            .    3 = show duplicate ECMs\n");
	printf("                            .    4 = packet debug\n");
	printf("                            .    5 = packet debug + packet dump\n");
	printf("\n");
	printf("Debugging options:\n");
	printf(" -n --ecm-file <file.txt>   | Read ECM from text file.\n");
	printf(" -m --emm-file <file.txt>   | Read EMM from text file.\n");
	printf("\n");
	printf("Misc options:\n");
	printf(" -j --pid-report            | Report how much packets were received.\n");
	printf(" -b --bench                 | Benchmark decrypton.\n");
	printf(" -h --help                  | Show help screen.\n");
	printf(" -V --version               | Show program version.\n");
	printf("\n");
}

static int parse_io_param(struct io *io, char *opt, int open_flags, mode_t open_mode) {
	int port_set = 0, host_set;
	if (strcmp(opt, "-") == 0) {
		io->type = FILE_IO;
		io->fd = (open_flags & O_WRONLY) ? STDOUT_FILENO : STDIN_FILENO;
		return 1;
	}
	io->type = WTF_IO;
	if (strstr(opt, "file://") == opt) {
		io->fname = opt + 7; // strlen("file://")
		io->type = FILE_IO;
	} else if (strchr(opt, '/')) {
		io->fname = opt;
		io->type = FILE_IO;
	}
	if (io->type == FILE_IO) {
		io->fd = open(io->fname, open_flags, open_mode);
		if (io->fd < 0) {
			fprintf(stderr, "ERROR: Can not open file (%s): %s\n", io->fname, strerror(errno));
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	io->type = NET_IO;
	host_set = parse_host_and_port(opt, &io->hostname, &io->service, &port_set);
	return !(!port_set || !host_set);
}

static unsigned long long parse_unsigned(const char *value, unsigned long long maximum, const char *option) {
	char *end;
	unsigned long long result;
	if (!*value || strspn(value, "0123456789") != strlen(value))
		goto invalid;
	errno = 0;
	result = strtoull(value, &end, 10);
	if (errno || *end || result > maximum)
		goto invalid;
	return result;
invalid:
	fprintf(stderr, "ERROR: %s requires an integer from 0 to %llu.\n", option, maximum);
	exit(EXIT_FAILURE);
}

static void parse_options(struct ts *ts, int argc, char **argv) {
	int j, i, ca_err = 0, server_err = 1, input_addr_err = 0, output_addr_err = 0, ident_err = 0, port_set = 0;
	while ((j = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
		if (j == '?')
			exit(EXIT_FAILURE);
		switch (j) {
			case 'i': // -- ident
				ts->ident = optarg;
				break;
			case 'd': // --daemon
				ts->pidfile = optarg;
				break;
			case 'N': // --notify-program
				ts->notify_program = optarg;
				break;
			case '9': // --notify-wait
				ts->notify_wait = !ts->notify_wait;
				break;
			case '0': // --status-file
				ts->status_file = optarg;
				ts->status_file_tmp = calloc(1, strlen(optarg) + 16);
				snprintf(ts->status_file_tmp, strlen(optarg) + 16, "%s.tmp", optarg);
				break;
			case 'S': // --syslog
				ts->syslog_active = 1;
				ts->syslog_remote = 0;
				break;
			case 'l': // --syslog-host
				ts->syslog_host = optarg;
				ts->syslog_active = 1;
				ts->syslog_remote = 1;
				break;
			case 'L': // --syslog-port
				ts->syslog_port = atoi(optarg);
				break;
			case 'F': // --log-file
				log_filename = optarg;
				break;

			case 'I': // --input
				input_addr_err = !parse_io_param(&ts->input, optarg, O_RDONLY, 0);
				break;
			case '1': // --input-source
				if (!inet_aton(optarg, &ts->input.isrc)) {
					fprintf(stderr, "ERROR: Can't parse input-source IP address: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case 'R': // --input-rtp
				ts->rtp_input = !ts->rtp_input;
				break;
			case 'z': // --input-ignore-disc
				ts->ts_discont = !ts->ts_discont;
				break;
			case 'M': // --input-service
				ts->forced_service_id = strtoul(optarg, NULL, 0) & 0xffff;
				break;
			case 'T': // --input-buffer
				ts->input_buffer_time = strtoul(optarg, NULL, 0);
				break;
			case OPT_INPUT_SHIFT:
				ts->input_shift_ms = parse_unsigned(optarg, INPUT_SHIFT_MAX_MS, "--input-shift");
				break;
			case OPT_INPUT_SHIFT_MEMORY:
				ts->input_shift_memory = parse_unsigned(optarg, SIZE_MAX, "--input-shift-memory");
				break;
			case OPT_INPUT_SHIFT_STATUS:
				ts->input_shift_status = optarg;
				break;
			case OPT_INPUT_PASSTHROUGH:
				ts->input_passthrough = 1;
				break;
			case 'W': // --input-dump
				ts->input_dump_filename = optarg;
				break;

			case 'O': // --output
				output_addr_err = !parse_io_param(&ts->output, optarg,
					O_CREAT | O_WRONLY | O_TRUNC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				break;
			case 'o': // --output-intf
				if (strchr(optarg, '.'))
					inet_aton(optarg, &ts->output.intf);
				else
					ts->output.v6_if_index = atoi(optarg);
				break;
			case 't': // --output-ttl
				ts->output.ttl = atoi(optarg);
				break;
			case 'r': // --output-rtp
				ts->rtp_output = 1;
				break;
			case 'k': // --output-rtp-ssrc
				ts->rtp_ssrc = strtoul(optarg, NULL, 0);
				break;
			case 'g': // --output-tos
				ts->output.tos = (uint8_t)strtol(optarg, NULL, 0);
				break;
			case 'u': // --no-output-on-error
				ts->no_output_on_error = !ts->no_output_on_error;
				break;
			case 'p': // --no-output-filter
				ts->pid_filter = !ts->pid_filter;
				break;
			case 'y': // --output-nit-pass
				ts->nit_passthrough = !ts->nit_passthrough;
				break;
			case 'w': // --output-eit-pass
				ts->eit_passthrough = !ts->eit_passthrough;
				break;
			case 'x': // --output-tdt-pass
				ts->tdt_passthrough = !ts->tdt_passthrough;
				break;
			case '3': // --output-enc-pass
				ts->allow_encrypted_output = !ts->allow_encrypted_output;
				break;
			case 'c': // --ca-system
				if (strcasecmp("IRDETO", optarg) == 0)
					ts->req_CA_sys = CA_IRDETO;
				else if (strcasecmp("CONNAX", optarg) == 0 || strcasecmp("CONAX", optarg) == 0)
					ts->req_CA_sys = CA_CONAX;
				else if (strcasecmp("CRYPTOWORKS", optarg) == 0)
					ts->req_CA_sys = CA_CRYPTOWORKS;
				else if (strcasecmp("SECA", optarg) == 0 || strcasecmp("MEDIAGUARD", optarg) == 0)
					ts->req_CA_sys = CA_SECA;
				else if (strcasecmp("VIACCESS", optarg) == 0)
					ts->req_CA_sys = CA_VIACCESS;
				else if (strcasecmp("VIDEOGUARD", optarg) == 0 || strcasecmp("NDS", optarg) == 0)
					ts->req_CA_sys = CA_VIDEOGUARD;
				else if (strcasecmp("NAGRA", optarg) == 0)
					ts->req_CA_sys = CA_NAGRA;
				else if (strcasecmp("DRE-CRYPT", optarg) == 0 || strcasecmp("DRECRYPT", optarg) == 0)
					ts->req_CA_sys = CA_DRECRYPT;
				else if (strcasecmp("BULCRYPT", optarg) == 0)
					ts->req_CA_sys = CA_BULCRYPT;
				else if (strcasecmp("GRIFFIN", optarg) == 0)
					ts->req_CA_sys = CA_GRIFFIN;
				else if (strcasecmp("DGCRYPT", optarg) == 0)
					ts->req_CA_sys = CA_DGCRYPT;
				else
					ca_err = 1;
				break;
			case 'C': // --caid
				ts->forced_caid = strtoul(optarg, NULL, 0) & 0xffff;
				break;
			case 'Y': // --const-cw
				ts->camd.constant_codeword = 1;
				if (strlen(optarg) > 2 && optarg[0] == '0' && optarg[1] == 'x')
					optarg += 2;
				if (strlen(optarg) != CODEWORD_LENGTH * 2) {
					fprintf(stderr, "ERROR: Constant code word should be %u characters long.\n", CODEWORD_LENGTH * 2);
					exit(EXIT_FAILURE);
				}
				if (decode_hex_string(optarg, ts->camd.key->cw, strlen(optarg)) < 0) {
					fprintf(stderr, "ERROR: Invalid hex string for constant code word: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				camd_set_cw(ts, ts->camd.key->cw, 0);
				ts->camd.key->is_valid_cw = 1;
				break;
			case 'Q': // --biss-key
				ts->camd.constant_codeword = 1;
				if (strlen(optarg) > 2 && optarg[0] == '0' && optarg[1] == 'x')
					optarg += 2;
				uint8_t *key = ts->camd.key->cw;
				// Sometimes the BISS keys are entered with their checksums already calculated (16 symbols, 8 bytes)
				// This is the same as constant cw with the same key for even and odd
				if (strlen(optarg) == (BISSKEY_LENGTH + 2) * 2) {
					if (decode_hex_string(optarg, key, strlen(optarg)) < 0) {
						fprintf(stderr, "ERROR: Invalid hex string for BISS key: %s\n", optarg);
						exit(EXIT_FAILURE);
					}
				} else {
					// BISS key without checksum (12 symbols, 6 bytes)
					if (strlen(optarg) != BISSKEY_LENGTH * 2) {
						fprintf(stderr, "ERROR: BISS key should be %u characters long.\n", BISSKEY_LENGTH * 2);
						exit(EXIT_FAILURE);
					}
					if (decode_hex_string(optarg, key, strlen(optarg)) < 0) {
						fprintf(stderr, "ERROR: Invalid hex string for BISS key: %s\n", optarg);
						exit(EXIT_FAILURE);
					}
					// Calculate BISS KEY crc
					memmove(key + 4, key + 3, 3);
					key[3] = (uint8_t)(key[0] + key[1] + key[2]);
					key[7] = (uint8_t)(key[4] + key[5] + key[6]);
				}
				// Even and odd keys are the same
				memcpy(key + 8, key, 8);
				camd_set_cw(ts, ts->camd.key->cw, 0);
				ts->camd.key->is_valid_cw = 1;
				break;

			case 'A': // --camd-proto
				if (strcasecmp(optarg, "cs378x") == 0) {
					camd_proto_cs378x(&ts->camd.ops);
				} else if (strcasecmp(optarg, "newcamd") == 0) {
					camd_proto_newcamd(&ts->camd.ops);
				} else {
					fprintf(stderr, "Unknown CAMD protocol: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;
			case 's': // --camd-server
				server_err = !parse_host_and_port(optarg, &ts->camd.hostname, &ts->camd.service, &port_set);
				break;
			case 'U': // --camd-user
				if (strlen(optarg) < 64)
					ts->camd.user = optarg;
				break;
			case 'P': // --camd-pass
				ts->camd.pass = optarg;
				break;
			case 'B': // --camd-des-key
				if (strlen(optarg) > 2 && optarg[0] == '0' && optarg[1] == 'x')
					optarg += 2;
				if (strlen(optarg) != DESKEY_LENGTH) {
					fprintf(stderr, "ERROR: des key should be %u characters long.\n", DESKEY_LENGTH);
					exit(EXIT_FAILURE);
				}
				strncpy(ts->camd.newcamd.hex_des_key, optarg, sizeof(ts->camd.newcamd.hex_des_key) - 1);
				ts->camd.newcamd.hex_des_key[sizeof(ts->camd.newcamd.hex_des_key) - 1] = 0;
				break;
			case '4': // --ipv4
				ai_family = AF_INET;
				break;
			case '6': // --ipv6
				ai_family = AF_INET6;
				break;

			case 'e': // --emm
				ts->process_emm = !ts->process_emm;
				break;
			case 'Z': // --emm-pid
				ts->forced_emm_pid = strtoul(optarg, NULL, 0) & 0x1fff;
				break;
			case 'E': // --emm-only
				ts->process_emm = 1;
				ts->process_ecm = 0;
				ts->output_stream = 0;
				break;
			case 'f': // --emm-report-time
				ts->emm_report_interval = strtoul(optarg, NULL, 10);
				if (ts->emm_report_interval > 86400)
					ts->emm_report_interval = 86400;
				break;

			case 'a': // --emm-filter
				if (ts->emm_filters_num + 1 > MAX_FILTERS) {
					fprintf(stderr, "ERROR: Maximum allowed filters are %d.\n", MAX_FILTERS);
					exit(EXIT_FAILURE);
				}
				if (filter_parse(optarg, &ts->emm_filters[ts->emm_filters_num])) {
					ts->emm_filters_num++;
				} else {
					fprintf(stderr, "ERROR: Can't parse EMM filter: %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				break;

			case 'X': // --ecm-pid
				ts->forced_ecm_pid = strtoul(optarg, NULL, 0) & 0x1fff;
				break;
			case 'v': // --ecm-only
				ts->process_emm = 0;
				ts->process_ecm = 1;
				ts->output_stream = 0;
				break;
			case 'H': // --ecm-report-time
				ts->ecm_report_interval = strtoul(optarg, NULL, 10);
				if (ts->ecm_report_interval > 86400)
					ts->ecm_report_interval = 86400;
				break;
			case 'G': // --ecm-irdeto-type
				ts->irdeto_ecm_idx = strtoul(optarg, NULL, 0);
				ts->irdeto_ecm_filter_type = IRDETO_FILTER_IDX;
				break;
			case '2': // --ecm-irdeto-chid
				ts->irdeto_ecm_chid = strtoul(optarg, NULL, 0);
				ts->irdeto_ecm_filter_type = IRDETO_FILTER_CHID;
				break;
			case 'K': // --ecm-no-log
				ts->ecm_cw_log = !ts->ecm_cw_log;
				break;
			case 'J': // --cw-warn-time
				ts->cw_warn_sec = strtoul(optarg, NULL, 10);
				if (ts->cw_warn_sec > 86400)
					ts->cw_warn_sec = 86400;
				ts->cw_last_warn= ts->cw_last_warn + ts->cw_warn_sec;
				break;
			case 'q': // --ecm-and-emm-only
				ts->process_emm = 1;
				ts->process_ecm = 1;
				ts->output_stream = 0;
				break;

			case 'D': // --debug
				ts->debug_level = atoi(optarg);
				if (ts->debug_level > 0)
					ts->pid_report = 1;
				break;
			case 'j': // --pid-report
				ts->pid_report = 1;
				break;
			case 'b': // --bench
				csa_benchmark();
				exit(EXIT_SUCCESS);

			case 'n': // --ecm-file
			case 'm': // --emm-file
				packet_from_file = 1;
				packet_buflen = file_hex2buf(optarg, packet_buf, sizeof(packet_buf));
				if (!packet_buflen) {
					fprintf(stderr, "ERROR: Can't init packet from file.\n");
					exit(1);
				}
				packet_type = j == 'n' ? ECM_MSG : EMM_MSG;
				break;

			case 'h': // --help
				show_help(ts);
				exit(EXIT_SUCCESS);

			case 'V': // --version
				printf("%s\n", program_id);
				exit(EXIT_SUCCESS);
		}
	}
	if (ts->input_shift_ms && ts->input_shift_memory < 4096) {
		fprintf(stderr, "ERROR: Nonzero --input-shift requires --input-shift-memory of at least 4096 bytes.\n");
		exit(EXIT_FAILURE);
	}
	if (ts->input_shift_ms && packet_from_file) {
		fprintf(stderr, "ERROR: --input-shift requires transport-stream input, not a single ECM/EMM file.\n");
		exit(EXIT_FAILURE);
	}
	if (ts->input_passthrough) {
		if (packet_from_file || ts->input_buffer_time || ts->camd.constant_codeword || ts->process_emm) {
			fprintf(stderr, "ERROR: --input-passthrough cannot be combined with ECM/EMM file, --input-buffer, constant CW or --emm.\n");
			exit(EXIT_FAILURE);
		}
		ts->process_ecm = 0;
		ts->process_emm = 0;
		ts->pid_filter = 0;
		ts->threaded = 0;
		server_err = 0;
	}
	if (!ts->ident) {
		if (ts->syslog_active || ts->notify_program || ts->status_file)
			ident_err = 1;
	}

	if (packet_from_file) {
		int err = 0;
		if (!ts->forced_caid) {
			fprintf(stderr, "ERROR: CAID was not set. Use --caid option.\n");
			err++;
		}
		if (!ts->forced_service_id) {
			fprintf(stderr, "ERROR: Service id was not set. Use --input-service option.\n");
			err++;
		}
		if (err)
			exit(EXIT_FAILURE);

		ts->threaded = 0;
		input_addr_err = 0;
		output_addr_err = 0;
		ts->input.type = FILE_IO;
		ts->input.fd = 0;
		ts->output.type = FILE_IO;
		ts->output.fd = 1;
		ts->pid_filter = 0;
		ts->process_ecm = 0;
		ts->process_emm = 0;
		ts->output_stream = 0;
		ts->camd.no_reconnect = 1;
		ts->camd.check_emm_errors = 1;
		ts->emm_filters_num = 0;
	}

	// Constant codeword is special. Disable conflicting options
	if (ts->camd.constant_codeword) {
		server_err = 0; // No server settings are required
		ts->process_ecm = 0;
		ts->process_emm = 0;
		ts->output_stream = 1;
	}

	if (ident_err || ca_err || server_err || input_addr_err || output_addr_err || ts->input.type == WTF_IO || ts->output.type == WTF_IO) {
		if (ident_err)
			fprintf(stderr, "ERROR: Ident is not set, please use --ident option.\n");
		if (ca_err)
			fprintf(stderr, "ERROR: Requested CA system is unsupported.\n");
		if (server_err)
			fprintf(stderr, "ERROR: CAMD server address is not set or it is invalid.\n");
		if (input_addr_err)
			fprintf(stderr, "ERROR: Input address is invalid.\n");
		if (output_addr_err)
			fprintf(stderr, "ERROR: Output address is invalid.\n");
		exit(EXIT_FAILURE);
	}
	if (decode_hex_string(ts->camd.newcamd.hex_des_key, ts->camd.newcamd.bin_des_key, DESKEY_LENGTH) < 0) {
		fprintf(stderr, "ERROR: Invalid hex string for des key: %s\n", ts->camd.newcamd.hex_des_key);
		exit(EXIT_FAILURE);
	}
	if (!ts->input_passthrough && ts->camd.ops.proto == CAMD_NEWCAMD && !port_set) {
		fprintf(stderr, "ERROR: CAMD server port is not set. Use --camd-server %s:xxxx to set the port.\n", ts->camd.hostname);
		exit(EXIT_FAILURE);
	}

	if (log_filename) {
		log_file = fopen(log_filename, "a");
		if (!log_file) {
			fprintf(stderr, "ERROR: Can't open log file %s: %s\n", log_filename, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (ts->ident)
		ts_LOGf("Ident      : %s\n", ts->ident);
	if (ts->notify_program)
		ts_LOGf("Notify prg : %s (%s)\n", ts->notify_program, ts->notify_wait ? "sync" : "async");
	if (ts->status_file)
		ts_LOGf("Status file: %s\n", ts->status_file);
	if (ts->pidfile)
		ts_LOGf("Daemonize  : %s pid file.\n", ts->pidfile);
	if (ts->syslog_active) {
		if (ts->syslog_remote)
			ts_LOGf("Syslog     : %s:%d\n", ts->syslog_host, ts->syslog_port);
		else
			ts_LOGf("Syslog     : enabled\n");
	} else {
		if (!packet_from_file)
			ts_LOGf("Syslog     : disabled\n");
	}

	if (!ts->input_passthrough && !ts->camd.constant_codeword) {
		if (ts->forced_caid)
			ts->req_CA_sys = ts_get_CA_sys(ts->forced_caid);
		if (!ts->forced_caid)
			ts_LOGf("CA System  : %s\n", ts_get_CA_sys_txt(ts->req_CA_sys));
		else
			ts_LOGf("CA System  : %s | CAID: 0x%04x (%d)\n",
				ts_get_CA_sys_txt(ts->req_CA_sys),
				ts->forced_caid, ts->forced_caid);
	} else if (!ts->input_passthrough) {
		char cw_even[64], cw_odd[64];
		ts_hex_dump_buf(cw_even, sizeof(cw_even), ts->key.cw    , 8, 0);
		ts_hex_dump_buf(cw_odd , sizeof(cw_odd ), ts->key.cw + 8, 8, 0);
		ts_LOGf("Constant CW: even = %s\n", cw_even);
		ts_LOGf("Constant CW: odd  = %s\n", cw_odd);
	}

	if (ts->input.type == NET_IO) {
		ts_LOGf("Input addr : %s://%s:%s/\n",
			ts->rtp_input ? "rtp" : "udp",
			ts->input.hostname, ts->input.service);
		ts_LOGf("Input src  : %s\n", inet_ntoa(ts->input.isrc));
		if (ts->input_buffer_time) {
			ts_LOGf("Input buff : %u ms\n", ts->input_buffer_time);
		}
	} else if (ts->input.type == FILE_IO) {
		if (!packet_from_file)
			ts_LOGf("Input file : %s\n", ts->input.fd == 0 ? "STDIN" : ts->input.fname);
	}
	if (ts->input_dump_filename) {
		ts->input_dump_file = fopen(ts->input_dump_filename, "w");
		if (ts->input_dump_file)
			ts_LOGf("Input dump : %s\n", ts->input_dump_filename);
		else
			ts_LOGf("Input dump : %s | ERROR: %s\n", ts->input_dump_filename, strerror(errno));
	}
	if (ts->forced_service_id)
		ts_LOGf("Service id : 0x%04x (%d)\n",
			ts->forced_service_id, ts->forced_service_id);
	if (ts->req_CA_sys == CA_IRDETO) {
		switch (ts->irdeto_ecm_filter_type) {
		case IRDETO_FILTER_IDX : ts_LOGf("Irdeto ECM : Index: 0x%02x (%d)\n", ts->irdeto_ecm_idx, ts->irdeto_ecm_idx); break;
		case IRDETO_FILTER_CHID: ts_LOGf("Irdeto ECM : CHID: 0x%04x (%d)\n", ts->irdeto_ecm_chid, ts->irdeto_ecm_chid); break;
		}
	}

	if (ts->output_stream) {
		if (ts->output.type == NET_IO) {
			ts_LOGf("Output addr: %s://%s:%s/\n",
				ts->rtp_output ? "rtp" : "udp",
				ts->output.hostname, ts->output.service);
			ts_LOGf("Output intf: %s (IPv6 intf index:%d)\n",
				inet_ntoa(ts->output.intf), ts->output.v6_if_index);
			ts_LOGf("Output ttl : %d\n", ts->output.ttl);
			if (ts->output.tos > -1)
				ts_LOGf("Output TOS : %u (0x%02x)\n", ts->output.tos, ts->output.tos);
			if (ts->rtp_output) {
				ts_LOGf("RTP SSRC   : %u (0x%04x)\n",
					ts->rtp_ssrc, ts->rtp_ssrc);
				// It is recommended that RTP seqnum starts with random number
				RAND_bytes((unsigned char *)&(ts->rtp_seqnum), 2);
			}
		} else if (ts->output.type == FILE_IO) {
			ts_LOGf("Output file: %s\n", ts->output.fd == 1 ? "STDOUT" : ts->output.fname);
		}
		ts_LOGf("Out filter : %s (%s)%s\n",
			ts->pid_filter ? "enabled" : "disabled",
			ts->pid_filter ? "output only service related PIDs" : "output everything",
			ts->no_output_on_error ? " (No output on CW error)" : ""
		);
		if (ts->pid_filter) {
			if (ts->nit_passthrough)
				ts_LOGf("Out filter : Pass through NIT.\n");
			if (ts->eit_passthrough)
				ts_LOGf("Out filter : Pass through EIT (EPG).\n");
			if (ts->tdt_passthrough)
				ts_LOGf("Out filter : Pass through TDT/TOT.\n");
		}
		ts_LOGf("TS discont : %s\n", ts->ts_discont ? "report" : "ignore");
		ts->threaded = !ts->input_passthrough && !(ts->input.type == FILE_IO && ts->input.fd != 0);
		ts_LOGf("Decoding   : %s\n", ts->input_passthrough ? "disabled (whole-input passthrough)" : ts->threaded ? "threaded" : "single thread");
	} else {
		ts_LOGf("Decoding   : disabled\n");
	}

	if (!ts->input_passthrough && !ts->camd.constant_codeword) {
		ts_LOGf("CAMD proto : %s\n", ts->camd.ops.ident);
		ts_LOGf("CAMD addr  : %s:%s%s\n", ts->camd.hostname, ts->camd.service,
			ai_family == AF_INET  ? " (IPv4 only)" :
			ai_family == AF_INET6 ? " (IPv6 only)" :
			" (IPv4/IPv6)"
		);
		ts_LOGf("CAMD user  : %s\n", ts->camd.user);
		ts_LOGf("CAMD pass  : %s\n", ts->camd.pass);
		if (ts->camd.ops.proto == CAMD_NEWCAMD)
			ts_LOGf("CAMD deskey: %s\n", ts->camd.newcamd.hex_des_key);
	}

	if (!packet_from_file)
		ts_LOGf("EMM process: %s\n", ts->process_emm ? "Yes" : "No");

	if (ts->process_emm) {
		if (ts->forced_emm_pid)
			ts_LOGf("EMM pid    : 0x%04x (%d)\n", ts->forced_emm_pid, ts->forced_emm_pid);

		if (ts->emm_report_interval)
			ts_LOGf("EMM report : %d sec\n", ts->emm_report_interval);
		else
			ts_LOGf("EMM report : disabled\n");

		for (i = 0; i < ts->emm_filters_num; i++) {
			char tmp[512];
			filter_dump(&ts->emm_filters[i], tmp, sizeof(tmp));
			ts_LOGf("EMM filter : [%2d] %s\n", i + 1,  tmp);
		}
	}

	if (!packet_from_file)
		ts_LOGf("ECM process: %s\n", ts->process_ecm ? "Yes" : "No");

	if (ts->process_ecm) {
		if (ts->forced_ecm_pid)
			ts_LOGf("ECM pid    : 0x%04x (%d)\n", ts->forced_ecm_pid, ts->forced_ecm_pid);

		if (ts->ecm_report_interval)
			ts_LOGf("ECM report : %d sec\n", ts->emm_report_interval);
		else
			ts_LOGf("ECM report : disabled\n");

		if (ts->cw_warn_sec)
			ts_LOGf("CW warning : %d sec\n", ts->cw_warn_sec);
		else
			ts_LOGf("CW warning : disabled\n");

		if (!ts->ecm_cw_log)
			ts_LOGf("ECM/CW log : disabled\n");
	}

	if (ts->ident) {
		int len = strlen(ts->ident);
		for (i = 0; i < len; i++) {
			if (ts->ident[i] == '/')
				ts->ident[i] = '-';
		}
	}
}

static void report_emms(struct ts *ts, time_t now) {
	ts_LOGf("EMM | Received %u, Skipped %u, Sent %u, Processed %u in %lu seconds.\n",
		ts->emm_input_count,
		ts->emm_skipped_count,
		ts->emm_seen_count,
		ts->emm_processed_count,
		now - ts->emm_last_report);
	if (ts->emm_seen_count == 0) {
		notify(ts, "NO_EMM_RECEIVED", "No EMMs were received in last %lu seconds.",
			now - ts->emm_last_report);
	}
	ts->emm_last_report = now;
	ts->emm_input_count = 0;
	ts->emm_seen_count = 0;
	ts->emm_skipped_count = 0;
	ts->emm_processed_count = 0;
}

static void report_ecms(struct ts *ts, time_t now) {
	if ((ts->stream_is_not_scrambled || !ts->have_valid_pmt || ts->no_input) && ts->ecm_seen_count == 0)
		return;
	ts_LOGf("ECM | Received %u (%u dup) and processed %u in %lu seconds.\n",
		ts->ecm_seen_count,
		ts->ecm_duplicate_count,
		ts->ecm_processed_count,
		now - ts->ecm_last_report);
	ts->ecm_last_report = now;
	ts->ecm_seen_count = 0;
	ts->ecm_duplicate_count = 0;
	ts->ecm_processed_count = 0;
}

static void report_cw_warn(struct ts *ts, time_t now) {
	if (ts->stream_is_not_scrambled || !ts->have_valid_pmt || ts->no_input)
		return;
	if (now - ts->key.ts > 1) {
		notify(ts, "NO_CODE_WORD", "No valid code word was received in %ld sec.",
			now - ts->key.ts);
		ts_LOGf("CW  | *ERR* No valid code word was received for %ld seconds!\n",
			now - ts->key.ts);
	}
	ts->cw_last_warn = now;
	ts->cw_next_warn = now + ts->cw_warn_sec;
}

static void do_reports(struct ts *ts) {
	static int first_emm_report = 1;
	static int first_ecm_report = 1;
	time_t now = time(NULL);
	if (ts->process_emm && ts->emm_report_interval) {
		if (first_emm_report && now >= ts->emm_last_report) {
			first_emm_report = 0;
			ts->emm_last_report -= FIRST_REPORT_SEC;
			report_emms(ts, now);
		} else if ((time_t)(ts->emm_last_report + ts->emm_report_interval) <= now) {
			report_emms(ts, now);
		}
	}
	if (ts->process_ecm && ts->ecm_report_interval) {
		if (first_ecm_report && now >= ts->ecm_last_report) {
			first_ecm_report = 0;
			ts->ecm_last_report -= FIRST_REPORT_SEC;
			report_ecms(ts, now);
		} else if ((time_t)(ts->ecm_last_report + ts->ecm_report_interval) <= now) {
			report_ecms(ts, now);
		}
	}
	if (ts->stream_is_not_scrambled && ts->last_not_scrambled_report_ts <= now - 60) {
		ts_LOGf("CLR | No encrypted packets in the last %ld seconds. Stream is clear.\n", now - ts->last_scrambled_packet_ts);
		notify(ts, "STREAM_CLEAR", "No encrypted packets in the last %ld seconds. Stream is clear.", now - ts->last_scrambled_packet_ts);
		ts->last_not_scrambled_report_ts = now;
		ts->key.is_valid_cw = 0;
	} else {
		if (ts->process_ecm && !ts->key.is_valid_cw) {
			if (ts->cw_warn_sec && now >= ts->cw_next_warn) {
				report_cw_warn(ts, now);
			}
		}
	}
	if (!ts->no_input) {
		if (ts->last_pmt_ts <= now - 3) {
			if (ts->have_valid_pmt) {
				ts_LOGf("MIS | There is no valid PMT in the input.\n");
				notify(ts, "NO_PROGRAM", "The input is missing valid program.");
				ts->have_valid_pmt = 0;
				ts->key.is_valid_cw = 0;
			}
		}
	}
}

static struct ts ts;

void signal_quit(int sig) {
	if (!keep_running)
		raise(sig);
	keep_running = 0;
	ts_LOGf("Killed %s with signal %d\n", program_id, sig);
	if (ts.input.type == NET_IO)
		shutdown_fd(&ts.input.fd);
	if (ts.output.type == NET_IO)
		shutdown_fd(&ts.output.fd);
	/* An outstanding ECM reply must not hold shutdown beyond the shift queue.
	 * Leave descriptor ownership to camd_stop; only wake its blocking receive. */
	if (ts.camd.server_fd >= 0)
		shutdown(ts.camd.server_fd, SHUT_RDWR);
	signal(sig, SIG_DFL);
}

void signal_alarm(int sig) {
	(void)sig;
	raise(SIGINT);
}

#define RTP_HDR_SZ  12

static uint8_t ts_packet[FRAME_SIZE + RTP_HDR_SZ];
static uint8_t rtp_hdr[2][RTP_HDR_SZ];

static int shifted_dispatch(struct ts *stream, uint8_t *data, size_t length) {
	if (stream->input_passthrough)
		return output_raw_packets(stream, data, length);
	process_packets(stream, data, length);
	return 0;
}

static int shift_status_write(struct ts *stream, const struct input_shift *shift, const char *state) {
	char temporary[PATH_MAX];
	FILE *file;
	int fd, failed;
	if (!stream->input_shift_status)
		return 0;
	if (snprintf(temporary, sizeof(temporary), "%s.%ld.tmp", stream->input_shift_status, (long)getpid()) >= (int)sizeof(temporary))
		return -1;
	fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -1;
	file = fdopen(fd, "w");
	if (!file) {
		close(fd);
		unlink(temporary);
		return -1;
	}
	failed = fprintf(file,
		"{\"pid\":%ld,\"shift_ms\":%u,\"capacity_bytes\":%zu,\"allocated_bytes\":%zu,"
		"\"used_bytes\":%zu,\"peak_bytes\":%zu,\"queued_bytes\":%zu,"
		"\"queued_blocks\":%zu,\"capacity_blocks\":%zu,"
		"\"received_blocks\":%" PRIu64 ",\"released_blocks\":%" PRIu64 ","
		"\"overflows\":%" PRIu64 ",\"max_late_ms\":%.3f,\"state\":\"%s\",\"updated_at\":%ld}\n",
		(long)getpid(), stream->input_shift_ms, shift->capacity_bytes, shift->allocated_bytes,
		input_shift_used(shift), shift->peak_bytes, shift->queued_bytes,
		shift->count, shift->capacity_blocks, shift->received_blocks, shift->released_blocks,
		shift->overflows, shift->max_late_ns / 1000000.0, state, (long)time(NULL)) < 0;
	if (fclose(file) != 0)
		failed = 1;
	if (failed || rename(temporary, stream->input_shift_status) != 0) {
		unlink(temporary);
		return -1;
	}
	return 0;
}

/* The queue is deliberately BEFORE process_packets: ECM, EMM, tables and A/V
 * share the same receive-time deadline. No ECM is parsed at enqueue time. */
static int run_shifted_input(struct ts *stream) {
	struct input_shift *shift = input_shift_create(stream->input_shift_ms ? stream->input_shift_memory : 4096, stream->input_shift_ms);
	uint8_t packet[FRAME_SIZE + RTP_HDR_SZ];
	size_t partial = 0;
	uint64_t last_input = input_shift_now(), next_status = last_input, next_report = last_input;
	int eof = 0, result = 0, status_warning = 0;
	uint16_t last_sequence = 0;
	int have_sequence = 0;
	const char *final_state = "stopped";
	if (!shift) {
		ts_LOGf("SHIFT | Cannot allocate bounded RAM queue: %s\n", strerror(errno));
		return -1;
	}
	ts_LOGf("SHIFT | Whole input delayed %u ms before ECM; RAM %zu bytes, %zu blocks.\n",
		stream->input_shift_ms, shift->allocated_bytes, shift->capacity_blocks);
	while (keep_running && (!eof || shift->count)) {
		uint64_t now = input_shift_now();
		struct input_shift_block *block;
		struct pollfd ready;
		ssize_t length;
		size_t complete, i;
		int polled, drained = 0;
		/* Bounded work per turn: a delayed scheduler must still service input. */
		while (drained++ < 64 && (block = input_shift_ready(shift, now))) {
			if (shifted_dispatch(stream, block->data, block->length) != 0) {
				ts_LOGf("SHIFT | Output write failed; stopping rather than dropping queued data.\n");
				result = -1;
				goto finished;
			}
			input_shift_release(shift, now);
			now = input_shift_now();
		}
		if (now >= next_report) {
			if (!stream->input_passthrough && !stream->camd.constant_codeword)
				do_reports(stream);
			next_report = now + 1000000000;
		}
		if (now >= next_status) {
			const char *state = !shift->received_blocks || !shift->released_blocks ? "buffering" : shift->count ? "running" : "idle";
			if (shift_status_write(stream, shift, state) != 0 && !status_warning) {
				ts_LOGf("SHIFT | Cannot write queue status: %s\n", strerror(errno));
				status_warning = 1;
			}
			next_status = now + 10000000000ULL;
		}
		if (stream->input.type == NET_IO && now - last_input >= 2000000000 && !stream->no_input) {
			stream->no_input = 1;
			ts_LOGf("SHIFT | No input for 2 seconds; queued blocks still drain on schedule.\n");
			notify(stream, "INPUT_TIMEOUT", "No input for 2 seconds; RAM shift remains scheduled.");
		}
		if (eof && !shift->count)
			break;
		ready.fd = eof ? -1 : stream->input.fd;
		ready.events = POLLIN;
		ready.revents = 0;
		polled = poll(&ready, 1, input_shift_wait_ms(shift, now, 100));
		if (!keep_running)
			break;
		if (polled < 0) {
			if (errno == EINTR)
				continue;
			ts_LOGf("SHIFT | Input poll failed: %s\n", strerror(errno));
			result = -1;
			break;
		}
		if (!polled)
			continue;
		if (ready.revents & POLLNVAL) {
			ts_LOGf("SHIFT | Input descriptor is invalid.\n");
			result = -1;
			break;
		}
		if (stream->input.type == NET_IO) {
			size_t maximum = FRAME_SIZE + (stream->rtp_input ? RTP_HDR_SZ : 0);
			length = recv(stream->input.fd, packet, maximum, MSG_TRUNC);
			if (length > (ssize_t)maximum) {
				ts_LOGf("SHIFT | Oversized UDP input (%zd bytes); expected at most %zu.\n", length, maximum);
				result = -1;
				break;
			}
		} else {
			length = read(stream->input.fd, packet + partial, FRAME_SIZE - partial);
		}
		if (length < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				continue;
			ts_LOGf("SHIFT | Input read failed: %s\n", strerror(errno));
			result = -1;
			break;
		}
		if (!length) {
			if (stream->input.type != NET_IO) {
				eof = 1;
				if (partial) {
					ts_LOGf("SHIFT | Truncated TS packet at EOF (%zu bytes).\n", partial);
					result = -1;
					break;
				}
			}
			continue;
		}
		now = input_shift_now();
		last_input = now;
		if (stream->no_input) {
			stream->no_input = 0;
			notify(stream, "INPUT_OK", "Input resumed; RAM shift remains scheduled.");
		}
		if (stream->input.type == NET_IO && stream->rtp_input) {
			uint16_t sequence;
			/* Existing input format is MPEG-TS with the fixed 12-byte RTP header. */
			if (length <= RTP_HDR_SZ || packet[0] != 0x80 || (packet[1] & 0x7f) != 33) {
				ts_LOGf("SHIFT | Unsupported RTP header; expected MPEG-TS without extensions or CSRC.\n");
				result = -1;
				break;
			}
			sequence = ((uint16_t)packet[2] << 8) | packet[3];
			if (have_sequence && (uint16_t)(last_sequence + 1) != sequence && stream->ts_discont)
				ts_LOGf("SHIFT | RTP sequence discontinuity: expected %u, got %u.\n", (uint16_t)(last_sequence + 1), sequence);
			last_sequence = sequence;
			have_sequence = 1;
			length -= RTP_HDR_SZ;
			memmove(packet, packet + RTP_HDR_SZ, length);
		}
		complete = (size_t)length + partial;
		partial = complete % 188;
		complete -= partial;
		if (stream->input.type == NET_IO && partial) {
			ts_LOGf("SHIFT | UDP input length is not a multiple of 188 bytes.\n");
			result = -1;
			break;
		}
		for (i = 0; i < complete; i += 188) {
			if (packet[i] != 0x47) {
				ts_LOGf("SHIFT | Input is not aligned MPEG-TS (missing sync byte).\n");
				result = -1;
				goto finished;
			}
		}
		if (complete) {
			if (stream->input_dump_file)
				fwrite(packet, complete, 1, stream->input_dump_file);
			if (input_shift_push(shift, packet, complete, now) != 0) {
				final_state = shift->overflows ? "overflow" : "error";
				ts_LOGf("SHIFT | RAM limit reached (%zu bytes, %u ms shift); stopping without overwriting data.\n",
					shift->capacity_bytes, stream->input_shift_ms);
				notify(stream, "SHIFT_OVERFLOW", "RAM shift queue exceeded its assigned memory cap.");
				result = -1;
				break;
			}
		}
		if (partial)
			memmove(packet, packet + complete, partial);
	}
finished:
	if (result && strcmp(final_state, "stopped") == 0)
		final_state = "error";
	shift_status_write(stream, shift, final_state);
	input_shift_destroy(shift);
	return result;
}

int main(int argc, char **argv) {
	ssize_t readen;
	int have_data = 1;
	int ntimeouts = 0;
	time_t timeout_start = time(NULL);
	int rtp_hdr_pos = 0, num_packets = 0;
	struct rlimit rl;
	int exit_status = EXIT_SUCCESS;

	if (getrlimit(RLIMIT_STACK, &rl) == 0) {
		if (rl.rlim_cur > THREAD_STACK_SIZE) {
			rl.rlim_cur = THREAD_STACK_SIZE;
			setrlimit(RLIMIT_STACK, &rl);
		}
	}

	memset(rtp_hdr[0], 0, RTP_HDR_SZ);
	memset(rtp_hdr[1], 0, RTP_HDR_SZ);

	data_init(&ts);

	ts_set_log_func(LOG_func);

	parse_options(&ts, argc, argv);

	if (ts.pidfile)
		daemonize(ts.pidfile);

	if (ts.syslog_active) {
		if (ts.syslog_remote) {
			log_init(ts.ident, 1, 1, ts.syslog_host, ts.syslog_port);
			remote_syslog = 1;
		} else {
			openlog(ts.ident, LOG_NDELAY | LOG_PID, LOG_USER);
			local_syslog = 1;
		}
	}

	ts.notify = notify_alloc(&ts);

	ts_LOGf("Start %s\n", program_id);
	notify(&ts, "START", "Starting %s", program_id);

	if (ts.input.type == NET_IO && udp_connect_input(&ts.input) < 1) {
		exit_status = EXIT_FAILURE;
		goto EXIT;
	}
	if (ts.output.type == NET_IO && udp_connect_output(&ts.output) < 1) {
		exit_status = EXIT_FAILURE;
		goto EXIT;
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	signal(SIGINT , signal_quit);
	signal(SIGTERM, signal_quit);

	if (ts.threaded) {
		pthread_create(&ts.decode_thread, &ts.thread_attr, &decode_thread, &ts);
		pthread_create(&ts.write_thread , &ts.thread_attr, &write_thread , &ts);
	}

	ts.emm_last_report = time(NULL) + FIRST_REPORT_SEC;
	ts.ecm_last_report = time(NULL) + FIRST_REPORT_SEC;
	if (!ts.input_passthrough)
		camd_start(&ts);

	if (packet_from_file) {
		uint8_t tmp[2048];
		ts_hex_dump_buf((char *)tmp, sizeof(tmp), packet_buf, packet_buflen, 16);
		ts_LOGf("%s | Processing packet with CAID 0x%04x\n", packet_type == ECM_MSG ? "ECM" : "EMM", ts.forced_caid);
		ts_LOGf("%s | Packet dump:\n%s\n", packet_type == ECM_MSG ? "ECM" : "EMM", tmp);
		camd_process_packet(&ts, camd_msg_alloc(packet_type, ts.forced_caid, ts.forced_service_id, packet_buf, packet_buflen));
		goto EXIT;
	}

	if (ts.input_shift_ms || ts.input_passthrough) {
		if (run_shifted_input(&ts) != 0) {
			exit_status = EXIT_FAILURE;
			/* Fatal queue/read errors must also cancel a pending CAMD reply.
			 * Otherwise camd_stop can wait for its network timeout before exit. */
			keep_running = 0;
			if (ts.camd.server_fd >= 0)
				shutdown(ts.camd.server_fd, SHUT_RDWR);
		}
		goto EXIT;
	}

	do {
		if (!ts.input_passthrough && !ts.camd.constant_codeword)
			do_reports(&ts);

		if (ts.input.type == NET_IO) {
			set_log_io_errors(0);
			if (!ts.rtp_input) {
				readen = fdread_ex(ts.input.fd, (char *)ts_packet, FRAME_SIZE, 250, 4, 1);
			} else {
				readen = fdread_ex(ts.input.fd, (char *)ts_packet, FRAME_SIZE + RTP_HDR_SZ, 250, 4, 1);
				if (readen > RTP_HDR_SZ) {
					memcpy(rtp_hdr[rtp_hdr_pos], ts_packet, RTP_HDR_SZ);
					memmove(ts_packet, ts_packet + RTP_HDR_SZ, FRAME_SIZE);
					readen -= RTP_HDR_SZ;
					uint16_t ssrc  = (rtp_hdr[rtp_hdr_pos][2] << 8) | rtp_hdr[rtp_hdr_pos][3];
					uint16_t pssrc = (rtp_hdr[!rtp_hdr_pos][2] << 8) | rtp_hdr[!rtp_hdr_pos][3];
					rtp_hdr_pos = !rtp_hdr_pos;
					if (pssrc + 1 != ssrc && (ssrc != 0 && pssrc != 0xffff) && num_packets > 2)
						if (ts.ts_discont)
							ts_LOGf("--- | RTP discontinuity last_ssrc %5d, curr_ssrc %5d, lost %d packet\n",
								pssrc, ssrc, ((ssrc - pssrc)-1) & 0xffff);
					num_packets++;
				}
			}
			set_log_io_errors(1);
			if (!keep_running)
				break;
			if (readen < 0) {
				ts_LOGf("--- | Input read timeout.\n");
				if (!ntimeouts) {
					timeout_start = time(NULL);
					notify(&ts, "INPUT_TIMEOUT", "Read timeout on input %s://%s:%s/",
							ts.rtp_input ? "rtp" : "udp",
							ts.input.hostname, ts.input.service);
				}
				ts.no_input = 1;
				ntimeouts++;
			} else {
				if (ntimeouts && readen > 0) {
					time_t now = time(NULL);
					ts_LOGf("+++ | Input OK after %ld sec timeout.\n", (now - timeout_start) + 2);
					notify(&ts, "INPUT_OK", "Data is available on input %s://%s:%s/ after %ld seconds timeout.",
							ts.rtp_input ? "rtp" : "udp",
							ts.input.hostname, ts.input.service,
							(now - timeout_start) + 2); // Timeout is detected when ~2 seconds there is no incoming data
					ts.have_valid_pmt = 1; // We need to report if there is not PMT after INPUT is now OK
					ts.last_pmt_ts = time(NULL);
					ts.no_input = 0;
					ntimeouts = 0;
				}
			}
		} else {
			readen = read(ts.input.fd, ts_packet, FRAME_SIZE);
			have_data = !(readen <= 0);
		}
		if (readen > 0) {
			if (ts.input_dump_file)
				fwrite(ts_packet, readen, 1, ts.input_dump_file);
			if (shifted_dispatch(&ts, ts_packet, readen) != 0) {
				exit_status = EXIT_FAILURE;
				break;
			}
		}
	} while (have_data && keep_running);
EXIT:
	if (!ts.input_passthrough)
		camd_stop(&ts);

	// If pthread_join failes make sure we exit...
	signal(SIGINT , SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGALRM, signal_alarm);
	alarm(2);
	if (ts.threaded) {
		ts.decode_stop = 1;
		ts.write_stop = 1;

		if (ts.decode_thread)
			pthread_join(ts.decode_thread, NULL);
		if (ts.write_thread)
			pthread_join(ts.write_thread, NULL);
	}

	show_pid_report(&ts);

	notify_sync(&ts, "STOP", "Stopping %s", program_id);
	ts_LOGf("Stop %s\n", program_id);

	if (ts.syslog_active) {
		if (ts.syslog_remote)
			log_close();
		else
			closelog();
	}

	if (ts.input_dump_file)
		fclose(ts.input_dump_file);

	if (ts.pidfile)
		unlink(ts.pidfile);

	if (log_file)
		fclose(log_file);

	notify_free(&ts.notify);
	data_free(&ts);

	exit(exit_status);
}
