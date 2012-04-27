/*
 * pcapick
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski
 *
 * Licensed under GNU GPL v. 3
 */

#include <getopt.h>
#include <ctype.h>
#include <string.h>
#include <math.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <libpjf/main.h>
#include <libflowcalc.h>
#include <libtrace.h>

#include "pcapick.h"

/** Prints usage help screen */
static void help(void)
{
	printf("Usage: pcapick [OPTIONS] <TRACE FILE> <GT-WEB FILE>\n");
	printf("\n");
	printf("  Rewrites one IP trace file into many files basing on web application name\n");
	printf("\n");
	printf("Options:\n");
	printf("  -f \"<filter>\"          apply given packet filter on the input trace file\n");
	printf("  -d <dir>               output directory\n");
	printf("  -a                     dont ignore HTTP traffic\n");
	printf("  -o <offset>            timestamp offset in gt-web file\n");
	printf("  --verbose,-V           be verbose (alias for --debug=5)\n");
	printf("  --debug=<num>          set debugging level\n");
	printf("  --help,-h              show this usage help screen\n");
	printf("  --version,-v           show version and copying information\n");
}

/** Prints version and copying information. */
static void version(void)
{
	printf("pcapick %s\n", PCAPICK_VER);
	printf("Author: Paweł Foremski <pjf@iitis.pl>\n");
	printf("Copyright (C) 2012 IITiS PAN\n");
	printf("Licensed under GNU GPL v3\n");
	printf("Part of the MuTriCs project: <http://mutrics.iitis.pl/>\n");
	printf("Realized under grant nr 2011/01/N/ST6/07202 of the Polish National Science Centre\n");
}

/** Parses arguments and loads modules
 * @retval 0     ok
 * @retval 1     error, main() should exit (eg. wrong arg. given)
 * @retval 2     ok, but main() should exit (eg. on --version or --help) */
static int parse_argv(struct pcapick *pp, int argc, char *argv[])
{
	int i, c;

	static char *short_opts = "hvVf:d:ao:";
	static struct option long_opts[] = {
		/* name, has_arg, NULL, short_ch */
		{ "verbose",    0, NULL,  1  },
		{ "debug",      1, NULL,  2  },
		{ "help",       0, NULL,  3  },
		{ "version",    0, NULL,  4  },
		{ 0, 0, 0, 0 }
	};

	/* defaults */
	debug = 0;
	pp->dir = "./out";

	for (;;) {
		c = getopt_long(argc, argv, short_opts, long_opts, &i);
		if (c == -1) break; /* end of options */

		switch (c) {
			case 'V':
			case  1 : debug = 5; break;
			case  2 : debug = atoi(optarg); break;
			case 'h':
			case  3 : help(); return 2;
			case 'v':
			case  4 : version(); return 2;
			case 'f': pp->filter = mmatic_strdup(pp->mm, optarg); break;
			case 'd': pp->dir = mmatic_strdup(pp->mm, optarg); break;
			case 'a': pp->all = true; break;
			case 'o': pp->drift = strtod(optarg, NULL); break;
			default: help(); return 1;
		}
	}

	if (argc - optind > 1) {
		pp->pcap_file = mmatic_strdup(pp->mm, argv[optind]);
		pp->gt_file = mmatic_strdup(pp->mm, argv[optind+1]);
	} else {
		help();
		return 1;
	}

	return 0;
}

/*******************************/
/** Convert URL to something closer to a web app name
 * @param buf128   an 128-element array
 */
static void fix_name(char *buf128)
{
	static char name[128];
	char *sl1, *sl2;
	int i;

	if (strncmp(buf128, "https://", 8) == 0)
		strncpy(name, buf128 + 8, sizeof(name));
	else if (strncmp(buf128, "http://", 7) == 0)
		strncpy(name, buf128 + 7, sizeof(name));
	else
		return;

	sl1 = strchr(name, '/');
	if (sl1) {
		*sl1 = '_';

		sl2 = strchr(sl1+1, '/');
		if (sl2) *sl2 = '\0';

		sl2 = strchr(sl1+1, '?');
		if (sl2) *sl2 = '\0';

		sl2 = strchr(sl1+1, '.');
		if (sl2) *sl1 = '\0';

		if (sl1[1] == '\0')
			sl1[0] = '\0';
	}

	for (i = 0; name[i]; i++) {
		if (isalnum(name[i]))
			continue;

		switch (name[i]) {
			case '.':
			case '-':
			case '_':
				continue;
			default:
				break;
		}

		name[i] = '_';
	}

	strncpy(buf128, name, 128);
}

static void update_reqs(struct pcapick *pp)
{
	char buf[BUFSIZ], *tok, *addr;
	struct req *req, *req2;
	tlist *reqs;
	double length;
	int i;
	bool https;

	if (!pp->gth)
		return;

	/* IDEA: dont read everything once (@1) */

	/* read each line and parse */
	while (fgets(buf, sizeof buf, pp->gth)) {
		if (!isdigit(buf[0]))
			continue;

		pp->reqnum++;

		/* read request data */
		req = mmatic_zalloc(pp->mm, sizeof *req);
		for (i = 0, tok = strtok(buf, ","); tok; tok = strtok(NULL, ","), i++) {
			switch (i) {
				case 0: /* start time */
					req->start = strtod(tok, NULL) - pp->drift;
					break;
				case 1: /* first byte time offset */
					break;
				case 2: /* last byte time offset */
					length = strtod(tok, NULL);
					req->stop = req->start + length;
					break;
				case 3: /* remote IP address */
					addr = tok;
					break;
				case 4: /* request type */
					/* support old format */
					if (strncmp(tok, "http", 4) == 0) {
						strcpy(req->type, "unknown");
						strncpy(req->appname, tok, sizeof(req->appname));
						i++;
						break;
					}

					strncpy(req->type, tok, sizeof(req->type));
					break;
				case 5: /* tab address */
					strncpy(req->appname, tok, sizeof(req->appname));
					break;
				case 6: /* requested URL */
					if (strncmp(tok, "http", 4) != 0) {
						i--;
						break;
					}

					strncpy(req->url, tok, sizeof(req->url));
					break;
				default: /* ignore the rest */
					break;
			}
		}

		/* is HTTPS? */
		https = (strncmp(req->appname, "https://", 8) == 0);

		/* find given IP */
		reqs = thash_get(https ? pp->https_reqs : pp->http_reqs, addr);
		if (!reqs) {
			reqs = tlist_create(NULL, pp->mm);
			thash_set(https ? pp->https_reqs : pp->http_reqs, addr, reqs);
		}

		/* position list iterator on the first non-later web request */
		tlist_resetend(reqs);
		while ((req2 = tlist_iterback(reqs))) {
			if (req2->start <= req->start) {
				tlist_iter(reqs);
				break;
			}
		}

		/* append the request in chronological order */
		if (req2)
			tlist_insertafter(reqs, req);
		else
			tlist_prepend(reqs, req);
	}

	/* update if @1 is fixed */
	i = -1;
	thash_iter_loop(pp->https_reqs, addr, reqs) {
		if (i == -1 || tlist_count(reqs) < i) {
			i = tlist_count(reqs);
			pp->min_addr = addr;

			tlist_reset(reqs);
			req = tlist_peek(reqs);
			pp->min_ts = req->start;
		}
	}
	printf("# time offset reference point: %s at %.6f\n", pp->min_addr, pp->min_ts);

	if (feof(pp->gth)) {
		fclose(pp->gth);
		pp->gth = NULL;
	}
}

static struct req *find_req(struct pcapick *pp, const char *addr, bool https, double ts)
{
	struct req *req;
	tlist *reqs;

	update_reqs(pp);

	reqs = thash_get(https ? pp->https_reqs : pp->http_reqs, addr);
	if (!reqs)
		return NULL;

	/* remove old entries and ensure that ts < req->stop */
	tlist_reset(reqs);
	while ((req = tlist_iter(reqs))) {
		if (ts > req->stop) {
			pjf_assert(req->pkts == 0);

			dbg(5, "no packets in request: start=%.6f length=%.06f appname=%s\n",
				req->start, req->stop - req->start, req->appname);
			pp->no_pkts++;

			tlist_remove(reqs);
			mmatic_free(req);
			continue;
		}

		break;
	}

	/* if not yet started, return NULL */
	if (!req || ts < req->start - PCAPICK_TIMEDIFF_DOWN)
		return NULL;

	/* reserve this request for the calling flow */
	tlist_remove(reqs);

	/* convert URL addresses */
	fix_name(req->appname);
	fix_name(req->url);

	return req;
}

bool tls_is_app(libtrace_packet_t *pkt)
{
	uint8_t proto;
	uint16_t ethertype;
	uint32_t rem;
	void *ptr;
	uint8_t *v;
	int i, j;

	ptr = trace_get_layer3(pkt, &ethertype, &rem);
	if (!ptr || ethertype != TRACE_ETHERTYPE_IP)
		return false;

	ptr = trace_get_payload_from_ip(ptr, &proto, &rem);
	if (!ptr || proto != TRACE_IPPROTO_TCP)
		return false;

	v = trace_get_payload_from_tcp(ptr, &rem);
	if (!v || rem < 5)
		return false;

	i = 0;
	while (i < rem) {
		/* TLS major version must be 3 */
		if (v[i+1] != 3)
			return false;

		/* TLS minor version must be <= 3 */
		if (v[i+2] > 3)
			return false;

		/* check TLS Record Layer Protocol Type */
		switch (v[i]) {
			case 0x14: /* ChangeCipherSpec */
			case 0x15: /* Alert */
			case 0x16: /* Handshake */
				break;
			case 0x17: /* Application */
				return true;
			default:   /* not TLS? */
				return false;
		}

		/* read the length and jump to next record */
		j = v[i+3];
		j = (j << 16) + v[i+4];
		if (j > 16384)
			return false;

		i += j + 5;
	}

	return false;
}

void buffer_pkt(struct pcapick *pp, struct flow *f, libtrace_packet_t *pkt)
{
	if (!f->buffer)
		f->buffer = tlist_create(trace_destroy_packet, pp->mm);

	tlist_push(f->buffer, trace_copy_packet(pkt));
}

/*******************************/

static void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct pcapick *pp = pdata;
	struct flow *f = data;
	char *dir, *uri;
	libtrace_out_t *out;
	libtrace_packet_t *pkt2;
	double diff;

	if (f->ignore)
		return;

	/*
	 * check if its a web app flow
	 */
	if (is_new) {
		if (pp->all) {
			if (lf->src.port == 80) {
				f->https = false;
				f->port = lf->dst.port;
				strncpy(f->addr, inet_ntoa(lf->src.addr.ip4), sizeof(f->addr));
				goto found;
			} else if (lf->dst.port == 80) {
				f->https = false;
				f->port = lf->src.port;
				strncpy(f->addr, inet_ntoa(lf->dst.addr.ip4), sizeof(f->addr));
				goto found;
			}
		}

		if (lf->src.port == 443) {
			f->https = true;
			f->port = lf->dst.port;
			strncpy(f->addr, inet_ntoa(lf->src.addr.ip4), sizeof(f->addr));
		} else if (lf->dst.port == 443) {
			f->https = true;
			f->port = lf->src.port;
			strncpy(f->addr, inet_ntoa(lf->dst.addr.ip4), sizeof(f->addr));
		} else {
			f->ignore = true;
			return;
		}
	}

	/*
	 * check for reference point
	 */
	if (pp->min_ts > 0 && strcmp(pp->min_addr, f->addr) == 0) {
		diff = pp->min_ts - ts;
		if (fabs(diff) < 900) {
			if (fabs(diff - pp->min_sugg) > 0.5) {
				printf("# possible time offset suggestion: %.6f\n", diff);
					pp->min_sugg = diff;
			}
		}
	}

found:
	pp->pktnum++;

	/*
	 * check if the packet is still within a web request
	 */
	if (f->req && ts > f->req->stop + PCAPICK_TIMEDIFF_UP) {
		dbg(4, "flow %d (%s:%d): matched %d packets\n",
			lf->id, f->addr, f->port, f->req->pkts);
		pp->with_pkts++;

		mmatic_free(f->req);
		f->req = NULL;
	}

	/*
	 * if no matching web request, search for it in the ground truth file
	 * and update the flow data
	 */
	if (!f->req) {
		/*
		 * TLS: let only a TLS application packet to start a web request
		 */
		if (f->https && !tls_is_app(pkt)) {
			buffer_pkt(pp, f, pkt);
			return;
		}

		/* find matching request */
		f->req = find_req(pp, f->addr, f->https, ts);

		/* if not found */
		if (!f->req) {
			pp->no_req++;
			f->no_req++;
			return;
		}

		/* found! */
		dbg(5, "flow %d (%s:%d): pkt ts=%.6f: request found: ", lf->id, f->addr, f->port, ts);
		dbg(5, "start=%.6f length=%.6f appname=%s\n", f->req->start, f->req->stop - f->req->start, f->req->appname);

		/* select proper file on disk */
		dir = mmatic_sprintf(pp->mm, "%s/%s/%s", pp->dir, f->req->appname, f->req->type);
		uri = mmatic_sprintf(pp->mm, "pcapfile:%s/%s.pcap", dir, f->req->url);

		if (pjf_mkdir(dir) != 0)
			die("Creating directory '%s' failed\n", dir);

		/* get PCAP output file */
		out = thash_get(pp->out_files, uri);
		if (!out) {
			out = trace_create_output(uri);
			if (!out)
				die("trace_create_output(%s) failed\n", uri);

			if (trace_is_err_output(out)) {
				trace_perror_output(out, "Opening output trace file");
				die("trace_create_output(%s) failed\n", uri);
			}

			if (trace_start_output(out) == -1) {
				trace_perror_output(out, "Starting output trace");
				die("trace_start_output(%s) failed\n", uri);
			}

			thash_set(pp->out_files, uri, out);
		}

		mmatic_free(uri);
		mmatic_free(dir);

		f->out = out;

		/* write any buffered packets */
		if (f->buffer) {
			tlist_iter_loop(f->buffer, pkt2) {
				trace_write_packet(f->out, pkt2);
			}

			tlist_free(f->buffer);
			f->buffer = NULL;
		}
	}

	trace_write_packet(f->out, pkt);
	if (trace_is_err_output(f->out)) {
		trace_perror_output(f->out, "Writing packet to output trace file");
		die("trace_write_packet() failed\n");
	}

	pp->with_req++;
	f->req->pkts++;
}

static void flow(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data)
{
	struct pcapick *pp = pdata;
	struct flow *f = data;

	if (f->ignore)
		return;

	if (f->req) {
		dbg(4, "flow %d (%s:%d): matched %d packets\n",
			lf->id, f->addr, f->port, f->req->pkts);
		pp->with_pkts++;
		mmatic_free(f->req);
	} else if (f->no_req) {
		dbg(5, "flow %d (%s:%d): %d packets left\n",
			lf->id, f->addr, f->port, f->no_req);
	}

	if (f->buffer)
		tlist_free(f->buffer);
}

/*******************************/

int main(int argc, char *argv[])
{
	mmatic *mm;
	struct pcapick *pp;

	/*
	 * initialization
	 */
	mm = mmatic_create();
	pp = mmatic_zalloc(mm, sizeof *pp);
	pp->mm = mm;
	pp->http_reqs = thash_create_strkey(NULL, mm); /* NB: no free fn */
	pp->https_reqs = thash_create_strkey(NULL, mm); /* NB: no free fn */
	pp->out_files = thash_create_strkey(trace_destroy_output, mm);

	/* read options */
	if (parse_argv(pp, argc, argv))
		return 1;

	/* file-system init */
	{
		if (streq(pp->gt_file, "-")) {
			pp->gth = stdin;
		} else {
			pp->gth = fopen(pp->gt_file, "r");
			if (!pp->gth)
				die("Reading input ground truth file '%s' failed: %s\n", pp->gt_file, strerror(errno));
		}

		if (pjf_mkdir(pp->dir) != 0)
			die("Creating output directory '%s' failed\n", pp->dir);
		else
			printf("Storing output PCAP files in '%s' directory\n", pp->dir);
	}

	pp->lfc = lfc_init();
	lfc_register(pp->lfc, "pcapick", sizeof(struct flow), pkt, flow, pp);

	/* start TCP sessions with any packet, wait after FIN/ACK */
	lfc_enable(pp->lfc, LFC_OPT_TCP_ANYSTART);
	lfc_enable(pp->lfc, LFC_OPT_TCP_WAIT);

	if (!lfc_run(pp->lfc, pp->pcap_file, pp->filter))
		die("Reading file '%s' failed\n", pp->pcap_file);

	printf("Matched: %8d packets, %8d requests\n", pp->with_req, pp->with_pkts);
	printf("Dropped: %8d packets, %8d requests\n", pp->no_req, pp->no_pkts);
	printf("TOTAL:   %8d packets, %8d requests\n", pp->pktnum, pp->reqnum);

	lfc_deinit(pp->lfc);
	thash_free(pp->out_files);
	mmatic_destroy(mm);

	return 0;
}
