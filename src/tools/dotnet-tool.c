/*
 * dotnet-tool.c: IDPrime.NET card utility
 *
 * Copyright (C) 2017 Russell Howe <rhowe.opensc@siksai.co.uk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/compat_getopt.h"
#include "libopensc/opensc.h"
#include "libopensc/asn1.h"
#include "libopensc/cards.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/errors.h"
#include "util.h"
#include "libopensc/log.h"

#include "libopensc/card-idprimenet.h"

/* declare functions */
static void show_version(void);
static int decode_options(int argc, char **argv);

/* define global variables */
static int actions = 0;
static char *opt_reader = NULL;
static int opt_wait = 0;
static int verbose = 0;
static int opt_get_card_version = 0;
static int opt_get_challenge = 0;

static const char *app_name = "dotnet-tool";

enum {
	OPT_BASE = 0x100,
	OPT_GET_CARD_VERSION,
	OPT_GET_CHALLENGE,
};

static const struct option options[] = {
	{ "reader",           required_argument, NULL, 'r'                  },
	{ "get-card-version", no_argument,       NULL, OPT_GET_CARD_VERSION },
	{ "get-challenge",    no_argument,       NULL, OPT_GET_CHALLENGE    },
	{ "wait",             no_argument,       NULL, 'w'                  },
	{ "help",             no_argument,       NULL, 'h'                  },
	{ "verbose",          no_argument,       NULL, 'v'                  },
	{ "version",          no_argument,       NULL, 'V'                  },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
/* r */	"Use reader number <arg> [0]",
/*   */	"Get card version number",
/*   */	"Get challenge from card",
/* w */	"Wait for card insertion",
/* h */	"Print this help message",
/* v */	"Verbose operation. Use several times to enable debug output.",
/* V */	"Show version number"
};


static void show_version(void)
{
	fprintf(stderr,
		"dotnet-tool - IDPrime.NET card utility version " PACKAGE_VERSION "\n"
		"\n"
		"Copyright (c) 2017 Russell Howe <rhowe.opensc@siksai.co.uk>\n"
		"Licensed under LGPL v2\n");
}

static int get_challenge(struct sc_card *card) {
	dotnet_exception_t *exception = NULL;
	u8 challenge[255];
	size_t challenge_len = 255;
	if (idprimenet_op_mscm_getchallenge(card, &exception, challenge, &challenge_len)) {
		printf("Failure retrieving challenge\n");
		return 0;
	}
	if (exception != NULL) {
		printf("Exception %s retrieving challenge\n", exception->type->type_str);
		dotnet_exception_destroy(exception);
		return 0;
	} else {
		printf("Challenge: 0x");
		for (unsigned int i = 0; i < challenge_len; i++)
			printf("%02x", challenge[i]);
		printf("\n");
	}
	return -1;
}

static int get_card_version(struct sc_card *card) {
	dotnet_exception_t *exception = NULL;
	char version[255];
	size_t version_len = 255;
	if (idprimenet_op_mscm_getversion(card, &exception, version, &version_len)) {
		printf("Failure retrieving version\n");
		return 0;
	}
	if (exception != NULL) {
		printf("Exception %s retrieving version\n", exception->type->type_str);
		dotnet_exception_destroy(exception);
		return 0;
	} else {
		printf("Card version: %s\n", version);
	}
	return -1;
}


static int decode_options(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv,"r:x:CUG:L:EhwvVd:", options, (int *) 0)) != EOF) {
		switch (c) {
		case 'r':
			opt_reader = optarg;
			break;
		case 'h':
			util_print_usage_and_die(app_name, options, option_help, NULL);
			break;
		case 'w':
			opt_wait = 1;
			break;
		case OPT_GET_CARD_VERSION:
			opt_get_card_version = 1;
			break;
		case OPT_GET_CHALLENGE:
			opt_get_challenge = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
			break;
		default:
			util_print_usage_and_die(app_name, options, option_help, NULL);
		}
	}

	return optind;
}

int main(int argc, char **argv)
{
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	int r;
	int argind = 0;
	int exit_status = EXIT_SUCCESS;

	/* decode options */
	argind = decode_options(argc, argv);

	/* connect to the card */
	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		util_fatal("failed to establish context: %s\n",
			sc_strerror(r));
		return EXIT_FAILURE;
	}

	if (verbose > 1) {
		ctx->debug = verbose;
		sc_ctx_log_to_file(ctx, "stderr");
	}

	r = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
	if (r) {
		util_fatal("failed to connect to card: %s\n",
			sc_strerror(r));
		return EXIT_FAILURE;
	}

	/* check card type */
	if (card->type != SC_CARD_TYPE_IDPRIMENET_GENERIC) {
		util_error("not an IDPrime.NET card");
		fprintf(stderr, "Card type %X\n", card->type);
		exit_status = EXIT_FAILURE;
		goto out;
	}

	if (opt_get_card_version) {
		actions++;
		exit_status |= get_card_version(card);
	}

	if (opt_get_challenge) {
		actions++;
		exit_status |= get_challenge(card);
	}

	/* fail on too many arguments */
	if (argind > argc || !actions)
		util_print_usage_and_die(app_name, options, option_help, NULL);

out:
	sc_unlock(card);
	sc_disconnect_card(card);
	sc_release_context(ctx);

	exit(exit_status);
}
