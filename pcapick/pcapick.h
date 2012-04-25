/*
 * pcapick
 *
 * Author: Paweł Foremski
 * Copyright (c) 2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Licensed under GNU GPL v. 3
 */

#ifndef _PCAPICK_H_
#define _PCAPICK_H_

#include <stdio.h>
#include <libflowcalc.h>

#define PCAPICK_VER "0.1"

/* how much time [s] to subtract from ground truth web request start time */
#define PCAPICK_TIMEDIFF 0.1

/* cap web request length to this value */
#define PCAPICK_MAX_LENGTH 30.0

struct req {
	double start;            /**> web request start */
	double stop;             /**> web request stop */
	char appname[128];       /**> web request app name */
	uint32_t pkts;           /**> packet counter */
};

struct flow {
	bool ignore;             /**> if true, ignore this flow */
	bool https;              /**> if true, its a HTTPS flow */
	char addr[16];           /**> server address */

	struct req *req;         /**> currently matched web request */
	libtrace_out_t *out;     /**> output file handle */
};

struct pcapick {
	mmatic *mm;              /**> memory */
	struct lfc *lfc;         /**> libflowcalc handle */

	thash *http_reqs;        /**> HTTP requests: remote ip -> sorted tlist -> struct req */
	thash *https_reqs;       /**> HTTPS requests: remote ip -> sorted tlist -> struct req */

	const char *gt_file;     /**> gt-web ground truth file */
	FILE *gth;               /**> gt_file handle */

	const char *pcap_file;   /**> trace file */
	const char *filter;      /**> optional filter */

	const char *dir;         /**> output directory */
	thash *out_files;        /**> appname -> libtrace_out_t* */

	uint32_t pktnum;         /**> total number of packets */
	uint32_t with_req;       /**> no. of packets with a matching request */
	uint32_t no_req;         /**> no. of packets without a matching request */

	uint32_t reqnum;         /**> total number of requests */
	uint32_t with_pkts;      /**> no. of requests with matching packets */
	uint32_t no_pkts;        /**> no. of requests without matching packets */
};

#endif
