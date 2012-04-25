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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libpjf/main.h>
#include <libflowcalc.h>

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

	static char *short_opts = "hvVf:d:";
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
	pp->dir = ".";

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

	/* TODO: dont read everything once */

	while (fgets(buf, sizeof buf, pp->gth)) {
		if (!isdigit(buf[0]))
			continue;

		pp->reqnum++;

		/* read request data */
		req = mmatic_zalloc(pp->mm, sizeof *req);
		for (i = 0, tok = strtok(buf, ","); tok; tok = strtok(NULL, ","), i++) {
			switch (i) {
				case 0: /* start time */
					req->start = strtod(tok, NULL);
					break;
				case 1: /* first byte time offset */
					break;
				case 2: /* last byte time offset */
					length = strtod(tok, NULL);
					if (length > PCAPICK_MAX_LENGTH)
						length = PCAPICK_MAX_LENGTH;

					req->stop = req->start + length;
					break;
				case 3: /* remote IP address */
					addr = tok;
					break;
				case 4: /* type */
					/* support old format */
					if (strncmp(tok, "http", 4) == 0) {
						strncpy(req->appname, tok, sizeof(req->appname));
						i++;
					}

					break;
				case 5: /* tab address */
					strncpy(req->appname, tok, sizeof(req->appname));
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
			reqs = tlist_create(mmatic_free, pp->mm);
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

#if 0
		if (strcmp(addr, "173.194.65.18") == 0) {
			printf("list for chosen IP now:\n");
			tlist_iter_loop(reqs, req2) {
				printf("  %.6f -> %.6f: %s\n", req2->start, req2->stop, req2->appname);
			}
		}
#endif
	}

	if (feof(pp->gth)) {
		fclose(pp->gth);
		pp->gth = NULL;
	}
}

static struct req *find_appname(struct pcapick *pp, const char *addr, bool https, double ts)
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
		if (req->stop < ts) {
			if (req->pkts == 0) {
				dbg(5, "no packets in request: start=%.6f appname=%s\n",
					req->start, req->appname);
				pp->no_pkts++;
			} else {
				pp->with_pkts++;
			}

			tlist_remove(reqs);
			continue;
		}

		break;
	}

	/* if not yet started, return NULL */
	if (!req || ts < req->start - PCAPICK_TIMEDIFF)
		return NULL;
	else
		return req;
}

/*******************************/

static void pkt(struct lfc *lfc, void *pdata,
	struct lfc_flow *lf, void *data,
	double ts, bool up, bool is_new, libtrace_packet_t *pkt)
{
	struct pcapick *pp = pdata;
	struct flow *f = data;
	char *uri;
	libtrace_out_t *out;

	if (f->ignore)
		return;

	/*
	 * check if its a web app flow
	 */
	if (is_new) {
		if (lf->src.port == 80 || lf->src.port == 443) {
			f->https = (lf->src.port == 443);
			strncpy(f->addr, inet_ntoa(lf->src.addr.ip4), sizeof(f->addr));
		} else if (lf->dst.port == 80 || lf->dst.port == 443) {
			f->https = (lf->dst.port == 443);
			strncpy(f->addr, inet_ntoa(lf->dst.addr.ip4), sizeof(f->addr));
		} else {
			f->ignore = true;
			return;
		}
	}

	pp->pktnum++;

	/*
	 * check if the packet is still within a web request
	 */
	if (f->req && ts > f->req->stop)
		f->req = NULL;

	/*
	 * if no matching web request, search for it in the ground truth file
	 */
	if (!f->req) {
		/* find matching request */
		f->req = find_appname(pp, f->addr, f->https, ts);

		/* if not found */
		if (!f->req) {
			dbg(3, "no matching web request: ts=%.6f server=%s\n", ts, f->addr);
			pp->no_req++;
			return;
		}

#if 0
		/* get PCAP output file */
		out = thash_get(pp->out_files, f->req->appname);
		if (!out) {
			uri = mmatic_sprintf(pp->mm, "pcap:%s/%s.pcap", pp->dir, f->req->appname);

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

			thash_set(pp->out_files, f->req->appname, out);
		}

		f->out = out;
#endif
	}

#if 0
	trace_write_packet(f->out, pkt);
	if (trace_is_err_output(f->out)) {
		trace_perror_output(f->out, "Writing packet to output trace file");
		die("trace_write_packet() failed\n");
	}
#endif

	pp->with_req++;
	f->req->pkts++;
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
				die("Reading input ARFF file '%s' failed: %s\n", pp->gt_file, strerror(errno));
		}

		if (pjf_mkdir(pp->dir) != 0)
			die("Creating output directory '%s' failed\n", pp->dir);
	}

	pp->lfc = lfc_init();
	lfc_register(pp->lfc, "pcapick", sizeof(struct flow), pkt, NULL, pp);
	lfc_enable(pp->lfc, LFC_OPT_TCP_ANYSTART);

	if (!lfc_run(pp->lfc, pp->pcap_file, pp->filter))
		die("Reading file '%s' failed\n", pp->pcap_file);

	dbg(1, "Success: %8d packets, %8d requests\n", pp->with_req, pp->with_pkts);
	dbg(1, "Failed:  %8d packets, %8d requests\n", pp->no_req, pp->no_pkts);
	dbg(1, "TOTAL:   %8d packets, %8d requests\n", pp->pktnum, pp->reqnum);

	lfc_deinit(pp->lfc);
	thash_free(pp->out_files);
	mmatic_destroy(mm);

	return 0;
}
