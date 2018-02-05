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

#define DOTNET_TOOL_PRINT_EXCEPTION(msg, exception) util_error("%s: %s: %s\n", msg, exception->type->type_str, exception->message == NULL ? "(no message)" : exception->message)

/* declare functions */
static void show_version(void);
static int decode_options(int argc, char **argv);

/* define global variables */
static int actions = 0;
static char *opt_reader = NULL;
static int opt_wait = 0;
static int verbose = 0;
static int opt_ext_auth = 0;
static int opt_force_gc = 0;
static int opt_get_card_version = 0;
static int opt_get_challenge = 0;
static char *opt_get_files_path = NULL;
static int opt_get_free_space = 0;
static int opt_get_pin_retries = 0;
static char *opt_read_file_path = NULL;

static const char *app_name = "dotnet-tool";

enum {
	OPT_BASE = 0x100,
	OPT_EXT_AUTH,
	OPT_FORCE_GC,
	OPT_GET_CARD_VERSION,
	OPT_GET_CHALLENGE,
	OPT_GET_FILES,
	OPT_GET_FREESPACE,
	OPT_GET_PIN_RETRIES,
	OPT_READ_FILE,
};

static const struct option options[] = {
	{ "reader",                required_argument, NULL, 'r'                  },
	{ "external-authenticate", no_argument,       NULL, OPT_EXT_AUTH         },
	{ "force-gc",              no_argument,       NULL, OPT_FORCE_GC         },
	{ "get-card-version",      no_argument,       NULL, OPT_GET_CARD_VERSION },
	{ "get-challenge",         no_argument,       NULL, OPT_GET_CHALLENGE    },
	{ "get-files",             required_argument, NULL, OPT_GET_FILES        },
	{ "get-free-space",        no_argument,       NULL, OPT_GET_FREESPACE    },
	{ "get-pin-retries",       no_argument,       NULL, OPT_GET_PIN_RETRIES  },
	{ "read-file",             required_argument, NULL, OPT_READ_FILE        },
	{ "wait",                  no_argument,       NULL, 'w'                  },
	{ "help",                  no_argument,       NULL, 'h'                  },
	{ "verbose",               no_argument,       NULL, 'v'                  },
	{ "version",               no_argument,       NULL, 'V'                  },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
/* r */	"Use reader number <arg> [0]",
/*   */	"External authentication",
/*   */	"Force garbage collection on the card",
/*   */	"Get card version number",
/*   */	"Get challenge from card",
/*   */	"Get files for a given directory",
/*   */	"Query the free space on the card",
/*   */	"Query the PIN retry counter",
/*   */	"Read a file on the card",
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

static int external_authenticate(struct sc_card *card) {
	dotnet_exception_t *exception = NULL;
	u8 authresp[255];
	size_t authresp_len = 0;

	authresp_len = fread(authresp, 1, 255, stdin);
	if (ferror(stdin)) {
		util_error("Error reading input\n");
		return EXIT_FAILURE;
	}
	if (authresp_len == 255 || !feof(stdin)) {
		util_error("Input too long\n");
		return EXIT_FAILURE;
	}

	if (idprimenet_op_mscm_externalauthenticate(card, &exception, authresp, authresp_len)) {
		util_error("Failure sending auth response\n");
		return EXIT_FAILURE;
	}
	if (exception != NULL) {
		DOTNET_TOOL_PRINT_EXCEPTION("Exception sending auth response", exception);
		dotnet_exception_destroy(exception);
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}

static int get_challenge(struct sc_card *card) {
	dotnet_exception_t *exception = NULL;
	u8 challenge[255];
	size_t challenge_len = 255;
	if (idprimenet_op_mscm_getchallenge(card, &exception, challenge, &challenge_len)) {
		util_error("Failure retrieving challenge\n");
		return EXIT_FAILURE;
	}
	if (exception != NULL) {
		DOTNET_TOOL_PRINT_EXCEPTION("Exception retrieving challenge", exception);
		dotnet_exception_destroy(exception);
		return EXIT_FAILURE;
	} else {
		printf("Challenge: ");
		for (unsigned int i = 0; i < challenge_len; i++)
			printf("\\x%02x", challenge[i]);
		printf("\n");
	}
	return EXIT_SUCCESS;
}

static int get_card_version(struct sc_card *card) {
	dotnet_exception_t *exception = NULL;
	char version[255];
	size_t version_len = 255;
	if (idprimenet_op_mscm_getversion(card, &exception, version, &version_len)) {
		util_error("Failure retrieving version\n");
		return EXIT_FAILURE;
	}
	if (exception != NULL) {
		DOTNET_TOOL_PRINT_EXCEPTION("Exception retrieving version", exception);
		dotnet_exception_destroy(exception);
		return EXIT_FAILURE;
	} else {
		printf("Card version: %s\n", version);
	}
	return EXIT_SUCCESS;
}

static int get_files(struct sc_card *card, char *path) {
	dotnet_exception_t *exception = NULL;
	struct idprimenet_string_array *results = NULL;
	int rc = EXIT_SUCCESS;

	if (idprimenet_op_mscm_getfiles(card, &exception, path, &results)) {
		util_error("Failure querying files for '%s'\n", path);
		idprimenet_string_array_destroy(results);
		return EXIT_FAILURE;
	}
	if (exception != NULL) {
		if (exception->type->type == IDPRIME_EX_TYPE_SYSTEM_IO_DIRECTORYNOTFOUNDEXCEPTION) {
			printf("'%s': Directory not found on card\n", path);
		} else {
			DOTNET_TOOL_PRINT_EXCEPTION("Exception querying files", exception);
		}
		idprimenet_string_array_destroy(results);
		dotnet_exception_destroy(exception);
		return EXIT_FAILURE;
	} else {
		printf("Files on card in '%s':\n", path);
		for (struct idprimenet_string_array *elem = results; elem != NULL; elem = elem->next) {
			char *filepath = strdup(elem->value);
			size_t buf_len = 16384;
			u8 buf[buf_len];

			if (*path) {
				/* We need to prefix the supplied path with <dir>\ */
				size_t filepathlen = strlen(path) + 1 /* separator */ + strlen(elem->value) + 1 /* terminator */;
				free(filepath);
				filepath = malloc(filepathlen);
				if (filepath == NULL) {
					util_error("malloc failure in get_files()");
					rc = EXIT_FAILURE;
					goto err;
				}
				snprintf(filepath, filepathlen, "%s\\%s", path, elem->value);
			}
			if (idprimenet_op_mscm_readfile(card, &exception, filepath, buf, &buf_len)) {
				util_error("Failure reading '%s'\n", elem->value);
				rc = EXIT_FAILURE;
				free(filepath);
				goto err;
			}
			if (exception != NULL) {
				// TODO: Mention which file!
				printf("File: %s", filepath);
				DOTNET_TOOL_PRINT_EXCEPTION("Exception reading file", exception);
				dotnet_exception_destroy(exception);
				rc = EXIT_FAILURE;
				free(filepath);
				goto err;
			} else {
				printf(" - %s (%ld bytes)\n", filepath, buf_len);
				free(filepath);
			}
		}
err:
		idprimenet_string_array_destroy(results);
		return rc;
	}
}

static int get_free_space(struct sc_card *card) {
	dotnet_exception_t *exception = NULL;
	int freespace[255];
	size_t freespace_len = 255;
	if (idprimenet_op_mscm_queryfreespace(card, &exception, freespace, &freespace_len)) {
		util_error("Failure retrieving freespace\n");
		return EXIT_FAILURE;
	}
	if (exception != NULL) {
		DOTNET_TOOL_PRINT_EXCEPTION("Exception retrieving free space", exception);
		dotnet_exception_destroy(exception);
		return EXIT_FAILURE;
	} else {
		printf("Freespace: 0x");
		for (unsigned int i = 0; i < freespace_len; i++)
			printf("%04x", freespace[i]);
		printf("\n");
		return EXIT_SUCCESS;
	}
}
static int get_max_pin_retry_counter(struct sc_card *card) {
	dotnet_exception_t *exception = NULL;
	u8 maxpinretrycounter = 0;
	if (idprimenet_op_mscm_maxpinretrycounter(card, &exception, &maxpinretrycounter)) {
		util_error("Failure retrieving max pin retry counter\n");
			return EXIT_FAILURE;
	} else {
		if (exception != NULL) {
			DOTNET_TOOL_PRINT_EXCEPTION("Exception retrieving max pin retry counter", exception);
			dotnet_exception_destroy(exception);
			return EXIT_FAILURE;
		} else {
			printf("Max pin retry counter: 0x%02x\n", maxpinretrycounter);
			return EXIT_SUCCESS;
		}
	}
}

static int force_gc(struct sc_card *card) {
	dotnet_exception_t *exception = NULL;
	if (idprimenet_op_mscm_forcegarbagecollector(card, &exception)) {
		util_error("Failure forcing GC\n");
		return EXIT_FAILURE;
	}
	if (exception != NULL) {
		DOTNET_TOOL_PRINT_EXCEPTION("Exception forcing GC", exception);
		dotnet_exception_destroy(exception);
		return EXIT_FAILURE;
	} else {
		printf("GC forced\n");
		return EXIT_SUCCESS;
	}
}

static int read_file(struct sc_card *card, char *path) {
	dotnet_exception_t *exception = NULL;
	size_t buf_len = 16384;
	u8 buf[buf_len];
	if (idprimenet_op_mscm_readfile(card, &exception, path, buf, &buf_len)) {
		util_error("Failure reading '%s'\n", path);
		return EXIT_FAILURE;
	}
	if (exception != NULL) {
		switch (exception->type->type) {
		case IDPRIME_EX_TYPE_SYSTEM_IO_FILENOTFOUNDEXCEPTION:
			printf("'%s': File not found\n", path);
			break;
		default:
			DOTNET_TOOL_PRINT_EXCEPTION("Exception reading file", exception);
		}
		dotnet_exception_destroy(exception);
		return EXIT_FAILURE;
	} else {
		size_t bytes_remaining = buf_len;
		while (bytes_remaining > 0) {
			ssize_t written = write(1, buf + (buf_len - bytes_remaining), bytes_remaining);
			if (written == -1) {
				perror("Reading file");
			} else {
				bytes_remaining -= written;
			}
		}
		return EXIT_SUCCESS;
	}
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
		case OPT_EXT_AUTH:
			opt_ext_auth = 1;
			break;
		case OPT_FORCE_GC:
			opt_force_gc= 1;
			break;
		case OPT_GET_CARD_VERSION:
			opt_get_card_version = 1;
			break;
		case OPT_GET_CHALLENGE:
			opt_get_challenge = 1;
			break;
		case OPT_GET_FILES:
			opt_get_files_path = optarg;
			break;
		case OPT_GET_FREESPACE:
			opt_get_free_space = 1;
			break;
		case OPT_GET_PIN_RETRIES:
			opt_get_pin_retries = 1;
			break;
		case OPT_READ_FILE:
			opt_read_file_path = optarg;
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

	if (opt_ext_auth) {
		actions++;
		exit_status |= external_authenticate(card);
	}

	if (opt_force_gc) {
		actions++;
		exit_status |= force_gc(card);
	}

	if (opt_get_card_version) {
		actions++;
		exit_status |= get_card_version(card);
	}

	if (opt_get_challenge) {
		actions++;
		exit_status |= get_challenge(card);
	}

	if (opt_get_files_path != NULL) {
		actions++;
		exit_status |= get_files(card, opt_get_files_path);
	}

	if (opt_get_free_space) {
		actions++;
		exit_status |= get_free_space(card);
	}

	if (opt_get_pin_retries) {
		actions++;
		exit_status |= get_max_pin_retry_counter(card);
	}

	if (opt_read_file_path != NULL) {
		actions++;
		exit_status |= read_file(card, opt_read_file_path);
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
