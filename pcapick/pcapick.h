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

/* web request time margin: start time [s] */
#define PCAPICK_TIMEDIFF_DOWN 0.1

/* web request time margin: stop time [s] */
#define PCAPICK_TIMEDIFF_UP 0.001

struct req {
	double start;            /**> web request start */
	double stop;             /**> web request stop */
	char type[32];           /**> request type */
	char appname[128];       /**> web request app name */
	char url[128];           /**> web request URL */
	uint32_t pkts;           /**> packet counter */
};

struct flow {
	bool ignore;             /**> if true, ignore this flow */
	bool https;              /**> if true, its a HTTPS flow */
	char addr[16];           /**> server address */
	int port;                /**> client port */

	struct req *req;         /**> currently matched web request */
	libtrace_out_t *out;     /**> output file handle */

	uint32_t no_req;         /**> number of packets without request */
};

struct pcapick {
	mmatic *mm;              /**> memory */
	struct lfc *lfc;         /**> libflowcalc handle */

	thash *http_reqs;        /**> HTTP requests: remote ip -> sorted tlist -> struct req */
	thash *https_reqs;       /**> HTTPS requests: remote ip -> sorted tlist -> struct req */

	const char *gt_file;     /**> gt-web ground truth file */
	FILE *gth;               /**> gt_file handle */
	const char *min_addr;    /**> remote IP address with the least number of requests */
	double min_ts;           /**> timestamp of first request to min_addr */

	const char *pcap_file;   /**> trace file */
	const char *filter;      /**> optional filter */

	bool all;                /**> if true, include HTTP traffic */
	double drift;            /**> ground truth timestamp offset (vs. PCAP) */

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
