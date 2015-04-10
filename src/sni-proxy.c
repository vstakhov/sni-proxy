/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>

#include "ev.h"
#include "ucl.h"
#include "util.h"

static const int default_backend_port = 443;

static int buflen = 16384;
static int port = 443;
static const char *cf_name = "/etc/sni-proxy.conf";

extern bool start_listen(struct ev_loop *loop, int port,
		const ucl_object_t *backends);

static void
usage(const char *error)
{
	if (error) {
		fprintf(stderr, "%s\n", error);
	}

	fprintf(stderr, "usage:"
	    "\tsni-proxy  [-c config] [-b buflen] [-h]\n");

	if (error) {
		exit(EXIT_FAILURE);
	}
	else {
		exit(EXIT_SUCCESS);
	}
}

static bool
backends_sane(ucl_object_t *obj)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur, *elt;
	struct addrinfo ai, *res;
	int port = default_backend_port, ret;
	ucl_object_t *be, *ai_obj;

	memset(&ai, 0, sizeof(ai));

	ai.ai_family = AF_UNSPEC;
	ai.ai_socktype = SOCK_STREAM;
	ai.ai_flags = AI_NUMERICSERV;

	while ((cur = ucl_iterate_object(obj, &it, true))) {
		be = ucl_object_ref(cur);
		elt = ucl_object_find_key(cur, "port");

		if (elt != NULL) {
			port = ucl_object_toint(elt);
			if (port <= 0 || port > 65535) {
				return false;
			}
		}

		elt = ucl_object_find_key(cur, "host");

		if (elt == NULL) {
			return false;
		}

		res = NULL;
		if ((ret = getaddrinfo(ucl_object_tostring(elt), port_to_str(port),
				&ai, &res)) != 0) {
			fprintf(stderr, "bad backend: %s:%d: %s\n", ucl_object_tostring(elt),
					port, gai_strerror(ret));
			return false;
		}

		/* Insert addrinfo as userdata */
		ai_obj = ucl_object_typed_new(UCL_USERDATA);
		ai_obj->value.ud = res;

		ucl_object_insert_key(be, ai_obj, "ai", 0, false);
		ucl_object_unref(be);
	}

	return true;
}

int
main(int argc, char **argv) {
	static struct option long_options[] = {
			{"config", 	required_argument, 0,  'c' },
			{"bufsize", 	required_argument, 0,  'b' },
			{"help", 	no_argument, 0,  'h' },
			{0,         0,                 0,  0 }
	};
	struct ucl_parser *parser;
	ucl_object_t *cfg, *backends;
	const ucl_object_t *elt;
	struct ev_loop *loop = EV_DEFAULT;

	char ch;

	while ((ch = getopt_long(argc, argv, "chb", long_options, NULL)) != -1) {
		switch (ch) {
		case 'c':
			cf_name = strdup(optarg);
			break;
		case 'b':
			buflen = strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			usage(NULL);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	parser = ucl_parser_new(0);

	if (!ucl_parser_add_file(parser, cf_name)) {
		fprintf(stderr, "cannot open file %s: %s\n", cf_name,
				ucl_parser_get_error(parser));
		exit(EXIT_FAILURE);
	}

	cfg = ucl_parser_get_object(parser);
	ucl_parser_free(parser);

	backends = ucl_object_ref(ucl_object_find_key(cfg, "backends"));

	if (backends == NULL || !backends_sane(backends)) {
		fprintf(stderr, "invalid or absent backends configuration\n");
		exit(EXIT_FAILURE);
	}

	elt = ucl_object_find_key(cfg, "port");
	if (elt) {
		port = ucl_object_toint(elt);
	}

	if (!start_listen(loop, port, backends)) {
		exit(EXIT_FAILURE);
	}

	ev_run(loop, 0);

	return 0;
}
