/*
 * card-idprimenet.c: Support for Gemalto IDprime.NET cards
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <malloc.h>
#include <openssl/evp.h>
#include <string.h>

#include "internal.h"

typedef struct {
	unsigned char port[2];
	char *namespace;
	char *type;
	char *method;
	char *service;
} dotnet_op_t;

static struct sc_atr_table idprimenet_atrs[] = {
	{"3b:16:96:41:73:74:72:69:64", NULL, NULL, SC_CARD_TYPE_IDPRIMENET_GENERIC, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

struct idprimenet_namespace_hivecode {
	char *namespace;
	unsigned char hivecode[4];
};

/* From page 109 of the IDPrime.NET integration guide */
static struct idprimenet_namespace_hivecode idprimenet_namespace_hivecodes[] = {
	{"System",                            {0x00, 0xD2, 0x5D, 0x1C}},
	{"System.IO",                         {0x00, 0xD5, 0xE6, 0xDB}},
	{"System.Runtime.Remoting.Channels",  {0x00, 0x00, 0x88, 0x6E}},
	{"System.Runtime.Remoting",           {0x00, 0xEB, 0x3D, 0xD9}},
	{"System.Security.Cryptography",      {0x00, 0xAC, 0xF5, 0x3B}},
	{"System.Collections",                {0x00, 0xC5, 0xA0, 0x10}},
	{"System.Runtime.Remoting.Contexts",  {0x00, 0x1F, 0x49, 0x94}},
	{"System.Security",                   {0x00, 0x96, 0x41, 0x45}},
	{"System.Reflection",                 {0x00, 0x08, 0x75, 0x0F}},
	{"System.Runtime.remoting.Messaging", {0x00, 0xDE, 0xB9, 0x40}},
	{"System.Diagnostics",                {0x00, 0x97, 0x99, 0x5F}},
	{"System.Runtime.CompilerServices",   {0x00, 0xF6, 0x3E, 0x11}},
	{"System.Text",                       {0x00, 0x70, 0x27, 0x56}},
	{"SmartCard",                         {0x00, 0xF5, 0xEF, 0xBF}},
	/* Not really clear this is the real namespace name */
	{"MSCM",                              {0x00, 0xC0, 0x4B, 0x4E}},
	{NULL,                                {0,    0,    0,    0   }}
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations idprimenet_ops;
static struct sc_card_driver idprimenet_drv = {
	"Gemalto IDPrime.NET card",
	"idprimenet",
	&idprimenet_ops,
	NULL, 0, NULL
};

static int namespace_to_hivecode(const char *namespace, unsigned char hivecode[4]) {
	for (unsigned int i = 0; idprimenet_namespace_hivecodes[i].namespace; i++) {
		if (!strcmp(idprimenet_namespace_hivecodes[i].namespace, namespace)) {
			hivecode[0] = idprimenet_namespace_hivecodes[i].hivecode[0];
			hivecode[1] = idprimenet_namespace_hivecodes[i].hivecode[1];
			hivecode[2] = idprimenet_namespace_hivecodes[i].hivecode[2];
			hivecode[3] = idprimenet_namespace_hivecodes[i].hivecode[3];
			return 0;
		}
	}
	return -1;
}

/*

p107 of the IDPrime.NET Smart Card Integration Guide says:
	Type string consists of: [Type Name].
	For example, the Type string for a type called Company.Stuff.MyClass would be:
	'MyClass'.
	The corresponding hivecode would be the last 2 bytes of MD5('MyClass').
 	Note: If referring to an array of type, the array information should be ignored, i.e.
 	'MyClass[]' would become 'MyClass'

	However, looking at the reference table, it appears that array types are
	represented by hivecodes one higher than their base type.

	e.g. System.Int32 has a hivecode of 61C0 whereas System.Int32[] has a hivecode
	of 61C1
*/

static int type_to_hivecode(const char *type, unsigned char hivecode[2]) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	unsigned char is_array;
	const char *hivetype = strrchr(type, '.');
	size_t type_len;

	if (!type) return 1;

	type_len = strlen(type);

	is_array = (type_len > 2 && !strncmp("[]", &type[type_len - 3], 2)) ? 1 : 0;

	hivetype = hivetype == NULL ? type : hivetype + 1;

	/* TODO: Check OpenSSL return codes */
	md = EVP_md5();
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, hivetype, strlen(hivetype) - (is_array ? 2 : 0));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);

	hivecode[0] = md_value[1];
	hivecode[1] = is_array ? md_value[0] + 1 : md_value[0]; // TODO: What if it's 0xff?

	printf("Type %s%s (%s) = hivecode 0x%02x 0x%02x\n", type, is_array ? "[]" : "", hivetype, hivecode[0], hivecode[1]);
	return 0;
}

static int method_to_hivecode(const char *method, unsigned char hivecode[2]) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;

	if (!method) return 1;

	/* TODO: Check OpenSSL return codes */
	md = EVP_md5();
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, method, strlen(method));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);

	hivecode[0] = md_value[1];
	hivecode[1] = md_value[0];

	return 0;
}

static sc_apdu_t *dotnet_op_to_apdu(struct sc_card *card, const dotnet_op_t *op) {
	unsigned int service_len;
	unsigned char namespace[4], type[2], method[2];
	unsigned int apdu_prefix_len = 1 /* 0xD8 */ + 2 /* port */ + 1 /* 0x6F */ + 4 /* NS */ + 2 /* type */ + 2 /* method */ + 2 /* service length */;
	unsigned int apdu_data_len;
	unsigned char *apdu_data_ptr;
	sc_apdu_t *apdu;

	if (!op || !op->service)
		return NULL;

	apdu = malloc(sizeof(sc_apdu_t));
	if (!apdu) return NULL;

   sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, 0xc2, 0, 0);
	apdu->cla = 0x80;

	service_len = strlen(op->service);
	if (service_len > 0xffff) {
		free(apdu);
		return NULL;
	}

	/* TODO: Check lookups were successful */
	namespace_to_hivecode(op->namespace, namespace);
	type_to_hivecode(op->type, type);
	method_to_hivecode(op->method, method);

	apdu_data_len = apdu_prefix_len + service_len;
	apdu->data = malloc(apdu_data_len);
	apdu->lc = apdu->datalen = apdu_data_len;

	if (!apdu->data) {
		free(apdu);
		return NULL;
	}

	apdu_data_ptr = apdu->data;
	*(apdu_data_ptr++) = 0xd8; /* Because? */
	*(apdu_data_ptr++) = op->port[0];
	*(apdu_data_ptr++) = op->port[1];
	*(apdu_data_ptr++) = 0x6f; /* Pourquoi? */
	*(apdu_data_ptr++) = namespace[0];
	*(apdu_data_ptr++) = namespace[1];
	*(apdu_data_ptr++) = namespace[2];
	*(apdu_data_ptr++) = namespace[3];
	*(apdu_data_ptr++) = type[0];
	*(apdu_data_ptr++) = type[1];
	*(apdu_data_ptr++) = method[0];
	*(apdu_data_ptr++) = method[1];
	*(apdu_data_ptr++) = service_len & 0xff00; /* FIXME: endianness? */
	*(apdu_data_ptr++) = service_len & 0x00ff;
	memcpy(apdu_data_ptr, op->service, service_len);

	return apdu;
}

static int idprimenet_match_card(struct sc_card *card)
{
	int i, res = 0;
	dotnet_op_t op;
	sc_apdu_t *apdu;

	i = _sc_match_atr(card, idprimenet_atrs, &card->type);
   if (i < 0) return 0;

	op.port[0] = 0;
	op.port[1] = 0x05;
	op.namespace = "MSCM";
	op.type = "CardModuleService";
	op.method = "System.Byte[] GetChallenge()";
	op.service = "MSCM";

	apdu = dotnet_op_to_apdu(card, &op);
	res = sc_transmit_apdu(card, apdu);

	if (res != SC_SUCCESS) {
		LOG_TEST_RET(card->ctx, res, "APDU transmit failed");
	} else {
		printf("APDU transmitted OK: res=%d, sw1=%d, sw2=%d\n", res, apdu->sw1, apdu->sw2);
	}

	if (apdu) {
		free(apdu);
	}

	return 1;
}

static int
idprimenet_init(struct sc_card *card)
{
	LOG_FUNC_CALLED(card->ctx);

	card->name = "Gemalto IDPrime.NET card";
	card->drv_data = NULL;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	iso_ops = iso_drv->ops;
	idprimenet_ops = *iso_ops;

	idprimenet_ops.match_card = idprimenet_match_card;
	idprimenet_ops.init = idprimenet_init;

	return &idprimenet_drv;
}

struct sc_card_driver * sc_get_idprimenet_driver(void)
{
	return sc_get_driver();
}

#endif /* ENABLE_OPENSSL */
