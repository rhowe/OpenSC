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

/*
 * From: https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp1099.pdf:
 * The IDPrime.NET card from 2002 is based on the Infineon SLE 88CFX4000P
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <malloc.h>
#include <stdarg.h>
#include <string.h>

#include <openssl/evp.h>

#include "cardctl.h"
#include "errors.h"
#include "internal.h"
#include "log.h"
#include "card-idprimenet.h"

/* TODO: These are just a guess at this point */
#define IDPRIMENET_CARD_DEFAULT_FLAGS ( 0        \
      | SC_ALGORITHM_ONBOARD_KEY_GEN      \
      | SC_ALGORITHM_RSA_PAD_ISO9796      \
      | SC_ALGORITHM_RSA_PAD_PKCS1     \
      | SC_ALGORITHM_RSA_HASH_NONE     \
      | SC_ALGORITHM_RSA_HASH_SHA1     \
      | SC_ALGORITHM_RSA_HASH_SHA256)


/* From page 109 of the IDPrime.NET integration guide */
/* These could be calculated if we knew what the public key token
 * of the relevant assemblies were
 */

static const idprimenet_type_hivecode_t idprimenet_type_hivecodes[] = {
	{IDPRIME_TYPE_SYSTEM_VOID,              "System.Void",              {0xCE, 0xB1}},
	{IDPRIME_TYPE_SYSTEM_INT32,             "System.Int32",             {0x61, 0xC0}},
	{IDPRIME_TYPE_SYSTEM_INT32_ARRAY,       "System.Int32[]",           {0x61, 0xC1}},
	{IDPRIME_TYPE_SYSTEM_BOOLEAN,           "System.Boolean",           {0x22, 0x27}},
	{IDPRIME_TYPE_SYSTEM_BOOLEAN_ARRAY,     "System.Boolean[]",         {0x22, 0x28}},
	{IDPRIME_TYPE_SYSTEM_SBYTE,             "System.SByte",             {0x76, 0x7E}},
	{IDPRIME_TYPE_SYSTEM_SBYTE_ARRAY,       "System.SByte[]",           {0x76, 0x7F}},
	{IDPRIME_TYPE_SYSTEM_UINT16,            "System.UInt16",            {0xD9, 0x8B}},
	{IDPRIME_TYPE_SYSTEM_UINT16_ARRAY,      "System.UInt16[]",          {0xD9, 0x8C}},
	{IDPRIME_TYPE_SYSTEM_UINT32,            "System.UInt32",            {0x95, 0xE7}},
	{IDPRIME_TYPE_SYSTEM_UINT32_ARRAY,      "System.UInt32[]",          {0x95, 0xE8}},
	{IDPRIME_TYPE_SYSTEM_BYTE,              "System.Byte",              {0x45, 0xA2}},
	{IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,        "System.Byte[]",            {0x45, 0xA3}},
	{IDPRIME_TYPE_SYSTEM_CHAR,              "System.Char",              {0x95, 0x8E}},
	{IDPRIME_TYPE_SYSTEM_CHAR_ARRAY,        "System.Char[]",            {0x95, 0x8F}},
	{IDPRIME_TYPE_SYSTEM_INT16,             "System.Int16",             {0xBC, 0x39}},
	{IDPRIME_TYPE_SYSTEM_INT16_ARRAY,       "System.Int16[]",           {0xBC, 0x3A}},
	{IDPRIME_TYPE_SYSTEM_STRING,            "System.String",            {0x11, 0x27}},
	{IDPRIME_TYPE_SYSTEM_STRING_ARRAY,      "System.String[]",          {0x11, 0x28}},
	{IDPRIME_TYPE_SYSTEM_INT64,             "System.Int64",             {0xDE, 0xFB}},
	{IDPRIME_TYPE_SYSTEM_INT64_ARRAY,       "System.Int64[]",           {0xDE, 0xFC}},
	{IDPRIME_TYPE_SYSTEM_UINT64,            "System.UInt64",            {0x71, 0xAF}},
	{IDPRIME_TYPE_SYSTEM_UINT64_ARRAY,      "System.UInt64[]",          {0x71, 0xB0}},
	{IDPRIME_TYPE_SYSTEM_IO_MEMORYSTREAM,   "System.IO.MemoryStream",   {0xFE, 0xD7}},
	{IDPRIME_TYPE_SMARTCARD_CONTENTMANAGER, "SmartCard.ContentManager", {0xB1, 0x8C}},
	{IDPRIME_TYPE_NONE,                     NULL,                       {0,    0   }}
};

static const idprimenet_type_hivecode_t idprimenet_exception_type_hivecodes[] = {
	{IDPRIME_EX_TYPE_SYSTEM_EXCEPTION,      "System.Exception",         {0xD4, 0x80}},
	{IDPRIME_EX_TYPE_SYSTEM_SYSTEMEXCEPTION, "System.SystemException", {0x28, 0xAC}},
	{IDPRIME_EX_TYPE_SYSTEM_OUTOFMEMORYEXCEPTION, "System.OutOfMemoryException", {0xE1, 0x4E}},
	{IDPRIME_EX_TYPE_SYSTEM_ARGUMENTEXCEPTION, "System.ArgumentException", {0xAB, 0x8C}},
	{IDPRIME_EX_TYPE_SYSTEM_ARGUMENTNULLEXCEPTION, "System.ArgumentNullException", {0x21, 0x38}},
	{IDPRIME_EX_TYPE_SYSTEM_NULLREFERENCEEXCEPTION, "System.NullReferenceException", {0xC5, 0xB8}},
	{IDPRIME_EX_TYPE_SYSTEM_ARGUMENTOUTOFRANGEEXCEPTION, "System.ArgumentOutOfRangeException", {0x6B, 0x11}},
	{IDPRIME_EX_TYPE_SYSTEM_NOTSUPPORTEDEXCEPTION, "System.NotSupportedException", {0xAA, 0x74}},
	{IDPRIME_EX_TYPE_SYSTEM_INVALIDCASTEXCEPTION, "System.InvalidCastException", {0xD2, 0x4F}},
	{IDPRIME_EX_TYPE_SYSTEM_INVALIDOPERATIONEXCEPTION, "System.InvalidOperationException", {0xFA, 0xB4}},
	{IDPRIME_EX_TYPE_SYSTEM_NOTIMPLEMENTEDEXCEPTION, "System.NotImplementedException", {0x3C, 0xE5}},
	{IDPRIME_EX_TYPE_SYSTEM_OBJECTDISPOSEDEXCEPTION, "System.ObjectDisposedException", {0x0F, 0xAC}},
	{IDPRIME_EX_TYPE_SYSTEM_UNAUTHORIZEDACCESSEXCEPTION, "System.UnauthorizedAccessException", {0x46, 0x97}},
	{IDPRIME_EX_TYPE_SYSTEM_INDEXOUTOFRANGEEXCEPTION, "System.IndexOutOfRangeException", {0xBF, 0x1D}},
	{IDPRIME_EX_TYPE_SYSTEM_FORMATEXCEPTION, "System.FormatException", {0xF3, 0xBF}},
	{IDPRIME_EX_TYPE_SYSTEM_ARITHMETICEXCEPTION, "System.ArithmeticException", {0x66, 0x83}},
	{IDPRIME_EX_TYPE_SYSTEM_OVERFLOWEXCEPTION, "System.OverflowException", {0x20, 0xA0}},
	{IDPRIME_EX_TYPE_SYSTEM_BADIMAGEFORMATEXCEPTION, "System.BadImageFormatException", {0x53, 0x0A}},
	{IDPRIME_EX_TYPE_SYSTEM_APPLICATIONEXCEPTION, "System.ApplicationException", {0xB1, 0xEA}},
	{IDPRIME_EX_TYPE_SYSTEM_ARRAYTYPEMISMATCHEXCEPTION, "System.ArrayTypeMismatchException", {0x3F, 0x88}},
	{IDPRIME_EX_TYPE_SYSTEM_DIVIDEBYZEROEXCEPTION, "System.DivideByZeroException", {0xDF, 0xCF}},
	{IDPRIME_EX_TYPE_SYSTEM_MEMBERACCESSEXCEPTION, "System.MemberAccessException", {0xF5, 0xF3}},
	{IDPRIME_EX_TYPE_SYSTEM_MISSINGMEMBEREXCEPTION, "System.MissingMemberException", {0x20, 0xBB}},
	{IDPRIME_EX_TYPE_SYSTEM_MISSINGFIELDEXCEPTION, "System.MissingFieldException", {0x73, 0x66}},
	{IDPRIME_EX_TYPE_SYSTEM_MISSINGMETHODEXCEPTION, "System.MissingMethodException", {0x90, 0x5B}},
	{IDPRIME_EX_TYPE_SYSTEM_RANKEXCEPTION, "System.RankException", {0xB2, 0xAE}},
	{IDPRIME_EX_TYPE_SYSTEM_STACKOVERFLOWEXCEPTION, "System.StackOverflowException", {0x08, 0x44}},
	{IDPRIME_EX_TYPE_SYSTEM_TYPELOADEXCEPTION, "System.TypeLoadException", {0x04, 0x8E}},
	{IDPRIME_EX_TYPE_SYSTEM_IO_IOEXCEPTION, "System.IO.IOException", {0x3B, 0xBE}},
	{IDPRIME_EX_TYPE_SYSTEM_IO_DIRECTORYNOTFOUNDEXCEPTION, "System.IO.DirectoryNotFoundException", {0x97, 0x5A}},
	{IDPRIME_EX_TYPE_SYSTEM_IO_FILENOTFOUNDEXCEPTION, "System.IO.FileNotFoundException", {0x07, 0xEB}},
	{IDPRIME_EX_TYPE_SYSTEM_RUNTIME_REMOTING_REMOTINGEXCEPTION, "System.Runtime.Remoting.RemotingException", {0xD5, 0x2A}},
	{IDPRIME_EX_TYPE_SYSTEM_SECURITY_CRYPTOGRAPHY_CRYPTOGRAPHICEXCEPTION, "System.Security.Cryptography.CryptographicException", {0x8F, 0xEB}},
	{IDPRIME_TYPE_NONE,                     NULL,                       {0,    0,  }}
};

typedef struct {
	idprimenet_type_t type;
	size_t value_len;
	void *value;
} idprimenet_arg_t;

typedef struct idprimenet_arg_list {
	idprimenet_arg_t arg;
	struct idprimenet_arg_list *next;
} idprimenet_arg_list_t;

typedef struct {
	u8 port[2];
	char *namespace;
	char *type;
	char *method;
	char *service;
} dotnet_op_t;

typedef struct {
	char *namespace;
	char *type;
	u8 *data;
} dotnet_apdu_response_t;

static struct sc_atr_table idprimenet_atrs[] = {
	{"3b:16:96:41:73:74:72:69:64", NULL, NULL, SC_CARD_TYPE_IDPRIMENET_GENERIC, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

/* From http://support.gemalto.com/index.php?id=how_i_can_unblock_the_pin */
/*
static const u8 default_admin_key[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
*/

typedef enum {
	IDPRIME_NS_NONE,
	IDPRIME_NS_SYSTEM,
	IDPRIME_NS_SYSTEM_IO,
	IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_CHANNELS,
	IDPRIME_NS_SYSTEM_RUNTIME_REMOTING,
	IDPRIME_NS_SYSTEM_SECURITY_CRYPTOGRAPHY,
	IDPRIME_NS_SYSTEM_COLLECTIONS,
	IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_CONTEXTS,
	IDPRIME_NS_SYSTEM_SECURITY,
	IDPRIME_NS_SYSTEM_REFLECTION,
	IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_MESSAGING,
	IDPRIME_NS_SYSTEM_DIAGNOSTICS,
	IDPRIME_NS_SYSTEM_RUNTIME_COMPILERSERVICES,
	IDPRIME_NS_SYSTEM_RUNTIME_SERIALIZATION,
	IDPRIME_NS_SYSTEM_TEXT,
	IDPRIME_NS_SMARTCARD,
	IDPRIME_NS_CARDMODULESERVICE,
	IDPRIME_NS_NETCARDFILESYSTEM
} idprimenet_namespace_t;

typedef struct {
	idprimenet_namespace_t namespace_id;
	u8 pubkeytoken[8];
	char *namespace;
	u8 hivecode[3];
} idprimenet_namespace_hivecode_t;

/* From page 109 of the IDPrime.NET integration guide */

/* The IDPrime.NET integration guide states that namespace hivecodes
 * are the first 4 bytes of MD5("<publickeytoken>.<namespace>"), but
 * that doesn't match reality where the first byte is always 0.
 *
 * Reading US patent US 2011/0264669 A1  s. 0478, the hivecode
 * generation is described as taking the first 3 bytes from the
 * hash and adding a 4th 0 byte "for aligning the bytes" which
 * matches up with all observed real-world namespace hivecodes.
 *
 * Known public key tokens:
 * mscorlib.dll: 367DB8A346085E5D (screenshot on p63 of the IDPrime.NET
 *                                 Smart Card Integration Guide)
 * Made up public key tokens:
 * CardModuleService: 000000000026EF84 (it's a valid hash collision for
 *                                      the known hivecode and made-up
 *                                      namespace name)
 * NetcardFilesystem: 00000000024ACD4C (it's a valid hash collision for
 *                                      the known hivecode)
 */
static idprimenet_namespace_hivecode_t idprimenet_namespace_hivecodes[] = {
	{IDPRIME_NS_SYSTEM,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System",                            {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_IO,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.IO",                         {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_CHANNELS,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Runtime.Remoting.Channels",  {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_RUNTIME_REMOTING,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Runtime.Remoting",           {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_SECURITY_CRYPTOGRAPHY,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Security.Cryptography",      {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_COLLECTIONS,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Collections",                {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_CONTEXTS,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Runtime.Remoting.Contexts",  {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_SECURITY,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Security",                   {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_REFLECTION,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Reflection",                 {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_MESSAGING,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Runtime.Remoting.Messaging", {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_DIAGNOSTICS,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Diagnostics",                {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_RUNTIME_COMPILERSERVICES,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Runtime.CompilerServices",   {0, 0, 0}},
	{IDPRIME_NS_SYSTEM_RUNTIME_SERIALIZATION,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Runtime.Serialization",      {0, 0, 0}}, /* From libgtop11dotnet MarshallerCfg.h */
	{IDPRIME_NS_SYSTEM_TEXT,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "System.Text",                       {0, 0, 0}},
	{IDPRIME_NS_SMARTCARD,
		{0x36, 0x7D, 0xB8, 0xA3, 0x46, 0x08, 0x5E, 0x5D}, "SmartCard",                         {0, 0, 0}},
	/* Not really clear this is the real namespace name */
	{IDPRIME_NS_CARDMODULESERVICE,
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0xEF, 0x84}, "CardModuleService",                 {0, 0, 0}},
	{IDPRIME_NS_NETCARDFILESYSTEM,
		{0x00, 0x00, 0x00, 0x00, 0x02, 0x4a, 0xcd, 0x4c}, "NetcardFilesystem",                 {0, 0, 0}}, /* From libgtop11dotnet MarshallerCfg.h */
	{IDPRIME_NS_NONE,
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, NULL,                                {0, 0, 0}},
};

dotnet_exception_t *dotnet_exception_new() {
	dotnet_exception_t *res = malloc(sizeof(dotnet_exception_t));
	if (res == NULL) return NULL;

	res->type = NULL;
	res->message = NULL;

	return res;
}

void dotnet_exception_destroy(dotnet_exception_t *exception) {
	if (exception->message != NULL) free(exception->message);
	free(exception);
}

dotnet_exception_t *dotnet_exception_clone(dotnet_exception_t *src) {
	dotnet_exception_t *res = malloc(sizeof(dotnet_exception_t));
	if (res == NULL) return NULL;

	res->type = src->type;
	if (src->message == NULL)
		res->message = NULL;
	else {
		res->message = strdup(src->message);
		if (res->message == NULL) {
			free(res);
			res = NULL;
		}
	}

	return res;
}

typedef struct {
	dotnet_exception_t *exception;
	const idprimenet_namespace_hivecode_t *namespace;
	idprimenet_type_t data_type;
	u8 *data;
	size_t data_len;
} dotnet_op_response_t;

static dotnet_op_response_t *dotnet_op_response_new() {
	dotnet_op_response_t *res = malloc(sizeof(dotnet_op_response_t));
	if (res == NULL) return NULL;

	res->exception = NULL;

	res->data_type = IDPRIME_TYPE_NONE;
	res->data = NULL;
	res->data_len = 0;

	return res;
}

static void dotnet_op_response_destroy(dotnet_op_response_t *res) {
	if (res != NULL) {
		if (res->exception != NULL && res->exception->message != NULL)
			free(res->exception->message);

		if (res->data != NULL)
			free(res->data);
		free(res);
	}
}

static struct sc_card_operations *iso_ops;
static struct sc_card_operations idprimenet_ops;
static struct sc_card_driver idprimenet_drv = {
	"Gemalto IDPrime.NET card",
	"idprimenet",
	&idprimenet_ops,
	NULL, 0, NULL
};

static int generate_ns_hivecodes() {
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md;
	int rv = SC_ERROR_INTERNAL;

	md = EVP_md5();
	if (md == NULL || md == NID_undef) {
		return SC_ERROR_INTERNAL;
	}
	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		return SC_ERROR_INTERNAL;
	}
	for (unsigned int i = 0; idprimenet_namespace_hivecodes[i].namespace_id != IDPRIME_NS_NONE; i++) {
		u8 md_value[EVP_MAX_MD_SIZE];
		unsigned int md_len;
		char pubkeytokenstr[17];

		sprintf(pubkeytokenstr, "%02X%02X%02X%02X%02X%02X%02X%02X",
			idprimenet_namespace_hivecodes[i].pubkeytoken[0],
			idprimenet_namespace_hivecodes[i].pubkeytoken[1],
			idprimenet_namespace_hivecodes[i].pubkeytoken[2],
			idprimenet_namespace_hivecodes[i].pubkeytoken[3],
			idprimenet_namespace_hivecodes[i].pubkeytoken[4],
			idprimenet_namespace_hivecodes[i].pubkeytoken[5],
			idprimenet_namespace_hivecodes[i].pubkeytoken[6],
			idprimenet_namespace_hivecodes[i].pubkeytoken[7]);
		char *ns = malloc(16 + 1 + strlen(idprimenet_namespace_hivecodes[i].namespace) + 1);
		if (ns == NULL) return SC_ERROR_OUT_OF_MEMORY;
		strcpy(ns, pubkeytokenstr);
		strcat(ns, ".");
		strcat(ns, idprimenet_namespace_hivecodes[i].namespace);

		if (!EVP_DigestInit_ex(mdctx, md, NULL))
			goto err;
		if (!EVP_DigestUpdate(mdctx, ns, strlen(ns)))
			goto err;
		if (!EVP_DigestFinal_ex(mdctx, md_value, &md_len))
			goto err;

//		printf("Namespace hivecode for %s: 00%02X%02X%02X\n", ns, md_value[2], md_value[1], md_value[0]);

		idprimenet_namespace_hivecodes[i].hivecode[0] = md_value[2];
		idprimenet_namespace_hivecodes[i].hivecode[1] = md_value[1];
		idprimenet_namespace_hivecodes[i].hivecode[2] = md_value[0];
	}

	rv = SC_SUCCESS;

err:
	EVP_MD_CTX_free(mdctx);
	return rv;
}

static int namespace_to_hivecode(const char *namespace, u8 hivecode[4]) {
	for (unsigned int i = 0; idprimenet_namespace_hivecodes[i].namespace; i++) {
		if (!strcmp(idprimenet_namespace_hivecodes[i].namespace, namespace)) {
			hivecode[0] = 0;
			hivecode[1] = idprimenet_namespace_hivecodes[i].hivecode[0];
			hivecode[2] = idprimenet_namespace_hivecodes[i].hivecode[1];
			hivecode[3] = idprimenet_namespace_hivecodes[i].hivecode[2];
			return 0;
		}
	}
	return -1;
}

static const idprimenet_namespace_hivecode_t *hivecode_to_namespace(const u8 hivecode[4]) {
	if (hivecode[0] != 0) return NULL;
	for (unsigned int i = 0; idprimenet_namespace_hivecodes[i].namespace; i++) {
		if (idprimenet_namespace_hivecodes[i].hivecode[0] == hivecode[1]
		 && idprimenet_namespace_hivecodes[i].hivecode[1] == hivecode[2]
		 && idprimenet_namespace_hivecodes[i].hivecode[2] == hivecode[3]) {
			return &idprimenet_namespace_hivecodes[i];
		}
	}
	return NULL;
}

static const idprimenet_type_hivecode_t * hivecode_to_type(const u8 hivecode[2]) {
	for (unsigned int i = 0; idprimenet_type_hivecodes[i].type != IDPRIME_TYPE_NONE; i++) {
		if (idprimenet_type_hivecodes[i].hivecode[0] == hivecode[0]
		 && idprimenet_type_hivecodes[i].hivecode[1] == hivecode[1]) {
			return &idprimenet_type_hivecodes[i];
		}
	}
	return NULL;
}

static const idprimenet_type_hivecode_t * hivecode_to_exception_type(const u8 hivecode[2]) {
	for (unsigned int i = 0; idprimenet_exception_type_hivecodes[i].type != IDPRIME_TYPE_NONE; i++) {
		if (idprimenet_exception_type_hivecodes[i].hivecode[0] == hivecode[0]
		 && idprimenet_exception_type_hivecodes[i].hivecode[1] == hivecode[1]) {
			return &idprimenet_exception_type_hivecodes[i];
		}
	}
	return NULL;
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

static int type_to_hivecode(const char *type, u8 hivecode[2]) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	u8 md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	u8 is_array;
	const char *hivetype = strrchr(type, '.');
	size_t type_len;
	int rv = SC_ERROR_INTERNAL;

	if (!type) return SC_ERROR_INVALID_ARGUMENTS;

	type_len = strlen(type);

	is_array = (type_len > 2 && !strncmp("[]", &type[type_len - 3], 2)) ? 1 : 0;

	hivetype = hivetype == NULL ? type : hivetype + 1;

	md = EVP_md5();
	if (md == NULL || md == NID_undef) {
		return SC_ERROR_INTERNAL;
	}
	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		return SC_ERROR_INTERNAL;
	}
	if (!EVP_DigestInit_ex(mdctx, md, NULL))
		goto err;
	if (!EVP_DigestUpdate(mdctx, hivetype, strlen(hivetype) - (is_array ? 2 : 0)))
		goto err;
	if (!EVP_DigestFinal_ex(mdctx, md_value, &md_len))
		goto err;

	hivecode[0] = md_value[1];
	hivecode[1] = is_array ? md_value[0] + 1 : md_value[0]; // TODO: What if it's 0xff?

	rv = SC_SUCCESS;

err:
	EVP_MD_CTX_free(mdctx);
	return rv;
}

static int method_to_hivecode(const char *method, u8 hivecode[2]) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	u8 md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	int rv = SC_ERROR_INTERNAL;

	if (!method) return SC_ERROR_INVALID_ARGUMENTS;

	md = EVP_md5();
	if (md == NULL || md == NID_undef) {
		return SC_ERROR_INTERNAL;
	}
	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		return SC_ERROR_INTERNAL;
	}
	if (!EVP_DigestInit_ex(mdctx, md, NULL))
		goto err;
	if (!EVP_DigestUpdate(mdctx, method, strlen(method)))
		goto err;
	if (!EVP_DigestFinal_ex(mdctx, md_value, &md_len))
		goto err;

	hivecode[0] = md_value[1];
	hivecode[1] = md_value[0];

	rv = SC_SUCCESS;

err:
	EVP_MD_CTX_free(mdctx);
	return rv;
}

static int idprimenet_apdu_to_string(
		sc_context_t *ctx,
		const u8 *data,
		size_t data_len,
		char *dest,
		size_t *dest_len) {
	/* dest needs to be at least data_len+1 in size */
	unsigned int strlen;
	static const unsigned short header_len = 2;

	LOG_FUNC_CALLED(ctx);

	if (data_len < header_len) {
		sc_log(ctx, "Malformed data - too small for a string\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}
	strlen = (data[0] << 8) | data[1];
	if (*dest_len < strlen + 1) {
		sc_log(ctx, "Buffer isn't big enough for string\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}
	memcpy(dest, data + header_len, strlen);
	dest[strlen] = '\0';
	*dest_len = strlen + 1;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

idprimenet_string_array_t *idprimenet_string_array_new() {
	idprimenet_string_array_t *elem = malloc(sizeof(idprimenet_string_array_t));
	if (elem != NULL) {
		elem->value = NULL;
		elem->next = NULL;
	}
	return elem;
}

void idprimenet_string_array_destroy(idprimenet_string_array_t *list) {
	while (list != NULL) {
		if (list->value != NULL) { free(list->value); }
		list = list->next;
	}
}

static int idprimenet_apdu_to_string_array(
		sc_context_t *ctx,
		const u8 *data,
		size_t data_len,
		idprimenet_string_array_t **dest) {
	unsigned int array_len; // TODO: 4 bytes?
	const unsigned short header_len = 4;
	idprimenet_string_array_t **current = dest;

	LOG_FUNC_CALLED(ctx);

	if (data_len < header_len) {
		sc_log(ctx, "Malformed data - too small for a string array\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}
	if (dest == NULL) {
		sc_log(ctx, "dest cannot be null\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	array_len = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);
	data += 4;
	data_len -= 4;

	for (unsigned int i = 0; i < array_len; i++) {
		idprimenet_string_array_t *elem = idprimenet_string_array_new();
		size_t buf_len = 255; // FIXME: Fixed buffer :(
		elem->value = malloc(buf_len);
		if (idprimenet_apdu_to_string(ctx, data, data_len, elem->value, &buf_len)) {
			idprimenet_string_array_destroy(elem);
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA); // FIXME: Deallocate the partially-constructed list
		}
		data += buf_len + 2 - 1; /* 2 byte header, 1 byte terminator */
		data_len -= buf_len + 2 - 1;
		if (*current == NULL) {
			*current = elem;
		} else {
			(*current)->next = elem;
		}
		current = &(elem->next);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int idprimenet_apdu_to_u1array(
		sc_context_t *ctx,
		const u8 *data,
		size_t data_len,
		u8 *dest,
		size_t *dest_len) {
	size_t array_len;
	LOG_FUNC_CALLED(ctx);

	if (data_len < 4) {
		sc_log(ctx, "Malformed data - too small for a u1array\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}
	if ((data_len - 4) > *dest_len) {
		sc_log(ctx, "Buffer too small for %ld bytes\n", data_len);
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}

	array_len = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);

	memcpy(dest, data + 4, array_len);

	*dest_len = array_len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
static int idprimenet_apdu_to_byte(
		sc_context_t *ctx,
		const u8 *data,
		size_t data_len,
		u8 *dest) {
	LOG_FUNC_CALLED(ctx);

	if (!data_len) {
		sc_log(ctx, "Malformed data - too small for a byte\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}
	if (!dest) {
		sc_log(ctx, "Target buffer is null\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	*dest = *data;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
*/

static int idprimenet_apdu_to_boolean(
		sc_context_t *ctx,
		const u8 *data,
		size_t data_len,
		u8 *dest) {
	LOG_FUNC_CALLED(ctx);

	if (!data_len) {
		sc_log(ctx, "Malformed data - too small for a boolean\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}
	if (!dest) {
		sc_log(ctx, "Target buffer is null\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	*dest = *data ? 1 : 0;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int idprimenet_apdu_to_s4array(
		sc_context_t *ctx,
		const u8 *data,
		size_t data_len,
		int *dest,
		size_t *dest_len) {
	size_t array_len;

	LOG_FUNC_CALLED(ctx);

	if (data_len < 4) {
		sc_log(ctx, "Malformed data - too small for a s4array\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}
	if ((data_len - 4) / 4 > *dest_len) {
		sc_log(ctx,"Buffer of %ld ints too small for %ld bytes\n", *dest_len, data_len);
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	}
	if (data_len % 4) {
		sc_log(ctx, "Buffer not a multiple of 4 bytes\n");
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL); // No better code to use
	}

	array_len = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);

	for (size_t i = 0; i < data_len / 4; i++)
		dest[i] = (data[4 + (i * 4)] << 24 | data[5 + (i * 4)] << 16 | data[6 + (i * 4)] << 8 | data[7 + (i * 4)]);

	*dest_len = array_len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int args_to_adpu_data(
		sc_context_t *ctx,
		u8 **data,
		size_t *data_len,
		unsigned int n_args,
		va_list args) {
	size_t args_data_len = 0;
	struct arg_data {
		u8 *data;
		size_t data_len;
	};
	struct arg_data_list {
		struct arg_data entry;
		struct arg_data_list *next;
	};
	struct arg_data_list *args_data = NULL;
	struct arg_data_list *args_data_head = args_data;
	u8 *dest;
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);

	for (unsigned int i = 0; i < n_args; i++) {
		idprimenet_arg_t arg = va_arg(args, idprimenet_arg_t);
		size_t arg_data_len;
		struct arg_data_list *elem;

		elem = malloc(sizeof(struct arg_data_list));

		if (elem == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		elem->next = NULL;

		switch (arg.type) {
			// FIXME: goto error is wrong and doesn't clean up properly
			case IDPRIME_TYPE_SYSTEM_INT32:
				{
					int val;
					if (arg.value_len != 1) {
						rv = SC_ERROR_INVALID_DATA;
						goto err;
					}
					elem->entry.data = malloc(4);
					if (elem->entry.data == NULL) {
						rv = SC_ERROR_OUT_OF_MEMORY;
						goto err;
					}
					elem->entry.data_len = 4;
					val = *(int*)arg.value;
					// TODO: Is this byte ordering correct?!
					elem->entry.data[0] = (val >> 24) & 0xff;
					elem->entry.data[1] = (val >> 16) & 0xff;
					elem->entry.data[2] = (val >> 8 ) & 0xff;
					elem->entry.data[3] =  val        & 0xff;
					args_data_len += 4;
				}
				break;
			case IDPRIME_TYPE_SYSTEM_BYTE:
				{
					if (arg.value_len != 1) {
						rv = SC_ERROR_INVALID_DATA;
						goto err;
					}
					elem->entry.data = malloc(1);
					if (elem->entry.data == NULL) {
						rv = SC_ERROR_OUT_OF_MEMORY;
						goto err;
					}
					elem->entry.data_len = 1;
					*(elem->entry.data) = *((u8*)arg.value);
					args_data_len += 1;
				}
				break;
			case IDPRIME_TYPE_SYSTEM_BYTE_ARRAY:
				{
					unsigned int array_len = arg.value_len;
					arg_data_len = 4 + array_len;
					elem->entry.data = malloc(arg_data_len);
					if (elem->entry.data == NULL) {
						rv = SC_ERROR_OUT_OF_MEMORY;
						goto err;
					}
					elem->entry.data_len = arg_data_len;
					elem->entry.data[0] = (array_len >> 24) & 0xff;
					elem->entry.data[1] = (array_len >> 16) & 0xff;
					elem->entry.data[2] = (array_len >> 8 ) & 0xff;
					elem->entry.data[3] =  array_len        & 0xff;
					memcpy(elem->entry.data + 4, (u8*)(arg.value), arg.value_len);
					args_data_len += arg_data_len;
				}
				break;
			case IDPRIME_TYPE_SYSTEM_STRING:
				{
					unsigned int string_len = arg.value_len;
					const unsigned int header_len = 2;
					arg_data_len = header_len + string_len;
					elem->entry.data = malloc(arg_data_len);
					if (elem->entry.data == NULL) {
						rv = SC_ERROR_OUT_OF_MEMORY;
						goto err;
					}
					elem->entry.data_len = arg_data_len;
					elem->entry.data[0] = (string_len >> 8) & 0xff;
					elem->entry.data[1] =  string_len       & 0xff;
					if (string_len > 0) {
						memcpy(elem->entry.data + header_len, (char *)(arg.value), arg.value_len);
					}
					args_data_len += arg_data_len;
				}
				break;
			default:
				sc_log(ctx, "Don't know how to size arg type %d\n", arg.type);
				rv = SC_ERROR_INVALID_DATA;
				goto err;
		}
		if (args_data_head == NULL) {
			args_data_head = elem;
		} else {
			args_data->next = elem;
		}
		args_data = elem;
	}

	*data_len = args_data_len;
	dest = malloc(args_data_len);
	if (dest == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	*data = dest;
	for (struct arg_data_list *elem = args_data_head; elem != NULL; elem = elem->next) {
		memcpy(dest, elem->entry.data, elem->entry.data_len);
		dest += elem->entry.data_len;
		free(elem->entry.data);
	}
	LOG_FUNC_RETURN(ctx, rv);

err:
	for (struct arg_data_list *elem = args_data; elem != NULL; elem = elem->next) {
		free(elem->entry.data);
	}
	LOG_FUNC_RETURN(ctx, rv);
}

static sc_apdu_t *dotnet_op_to_apdu(
		struct sc_card *card,
		const dotnet_op_t *op,
		unsigned int n_args,
		va_list args
) {
	unsigned int service_len;
	u8 namespace[4], type[2], method[2];
	unsigned int apdu_prefix_len = 1 /* 0xD8 */ + 2 /* port */ + 1 /* 0x6F */ + 4 /* NS */ + 2 /* type */ + 2 /* method */ + 2 /* service length */;
	unsigned int apdu_data_len;
	u8 *apdu_data_ptr;
	sc_apdu_t *apdu = NULL;
	int cla;
	u8 *args_data;
	size_t args_data_len;

	LOG_FUNC_CALLED(card->ctx);

	if (!op || !op->service)
		return NULL;

	apdu = malloc(sizeof(sc_apdu_t));
	if (apdu == NULL) return NULL;

	/* Does this call return any data? */
	cla = strcmp("System.Void", op->type) ? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_3_SHORT;

   sc_format_apdu(card, apdu, cla, 0xc2, 0, 0);
	apdu->cla = 0x80;

	service_len = strlen(op->service);
	if (service_len > 0xffff) {
		sc_log(card->ctx, "Service length %d too long\n", service_len);
		goto err;
	}

	if (namespace_to_hivecode(op->namespace, namespace)) {
		sc_log(card->ctx, "Failed to calculate hivecode for namespace '%s'\n", op->namespace);
		goto err;
	}
	if (type_to_hivecode(op->type, type)) {
		sc_log(card->ctx, "Failed to calculate hivecode for type '%s'\n", op->type);
		goto err;
	}
	if (method_to_hivecode(op->method, method)) {
		sc_log(card->ctx, "Failed to calculate hivecode for method '%s'\n", op->method);
		goto err;
	}

	if (args_to_adpu_data(card->ctx, &args_data, &args_data_len, n_args, args)) {
		sc_log(card->ctx, "Failed to calculate APDU data for method arguments\n");
		goto err;
	}

	apdu_data_len = apdu_prefix_len + service_len + args_data_len;
	apdu_data_ptr = malloc(apdu_data_len);

	if (apdu_data_ptr == NULL)
		goto err;

	apdu->lc = apdu->datalen = apdu_data_len;
	apdu->data = apdu_data_ptr;

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
	memcpy(apdu_data_ptr + service_len, args_data, args_data_len);
	free(args_data);

	sc_log(card->ctx, "APDU generated for: svc:%s:0x%02x%02x [ns:%s] (t:%s) %s\n", op->service, op->port[0], op->port[1], op->namespace, op->type, op->method);

	return apdu;

err:
	if (apdu != NULL) free(apdu);
	return NULL;
}

static int idprimenet_parse_exception(dotnet_op_response_t *response, const unsigned char *resp, const size_t resplen) {
	const idprimenet_type_hivecode_t *r_type;
	const unsigned int resp_header_size = 6; // 4 bytes of namespace hivecode + 2 bytes of type hivecode

	if (resplen < resp_header_size) return 1;

	r_type = hivecode_to_exception_type(resp + 4);
	if (r_type) {
		response->exception = dotnet_exception_new();
		if (response->exception == NULL) { return 1; }

		response->namespace = hivecode_to_namespace(resp);
		response->exception->type = r_type;
		if (resplen > resp_header_size) {
			// There's a message to go with this exception
			response->exception->message = malloc(resplen - resp_header_size + 1);
			if (!response->exception->message) return 1;
			memcpy(response->exception->message, resp + resp_header_size, resplen - resp_header_size);
			response->exception->message[resplen - resp_header_size] = '\0';
		}
		return 0;
	} else {
		return 1;
	}
}

static int idprimenet_op_call(
		struct sc_card *card,
		const dotnet_op_t *op,
		dotnet_op_response_t *response,
		idprimenet_namespace_t expected_response_ns,
		idprimenet_type_t expected_response_type,
		const unsigned int n_args,
		...
	) {
	va_list args;
	int res;
	int rv = SC_SUCCESS;
	sc_apdu_t *apdu;
	u8 *resp = NULL;
	size_t resplen = 255; //FIXME: Be more flexible
	const unsigned int resp_header_size = 6; // 4 bytes of namespace hivecode + 2 bytes of type hivecode
	const idprimenet_type_hivecode_t *r_type;

	if (!card) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (!response) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	resp = malloc(resplen);
	if (resp == NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	va_start(args, n_args);
	apdu = dotnet_op_to_apdu(card, op, n_args, args);
	va_end(args);
	if (!apdu) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	apdu->resp = resp;
	apdu->resplen = resplen;
	apdu->le = resplen;

	res = sc_transmit_apdu(card, apdu);

	if (res != SC_SUCCESS) {
		sc_log(card->ctx, "APDU transmit failed");
		rv = res;
		goto out;
	}

	if (!strcmp("MSCM", op->service) && apdu->resplen < resp_header_size) {
		if (expected_response_type == IDPRIME_TYPE_SYSTEM_VOID) {
			// No data expected in the response
			response->data_type = IDPRIME_TYPE_SYSTEM_VOID;
			response->data_len = 0;
		} else {
			sc_log(card->ctx, "Response too short?!");
			rv = SC_ERROR_WRONG_LENGTH;
		}

		goto out;
	}

	if (!strcmp("MSCM", op->service)) {
		// MSCM has its own special response format
		if (idprimenet_parse_exception(response, apdu->resp, apdu->resplen)) {
			if (apdu->resplen < resp_header_size) {
				sc_log(card->ctx, "Response too short - only %ld bytes\n", apdu->resplen);
				rv = SC_ERROR_WRONG_LENGTH;
				goto out;
			}
			response->namespace = hivecode_to_namespace(resp);
			if (!response->namespace) {
				sc_log(card->ctx, "Couldn't determine response namespace for 0x%02x%02x%02x%02x\n",
					resp[0], resp[1], resp[2], resp[3]
				);
				rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
				goto out;
			}
			r_type = hivecode_to_type(apdu->resp + 4);
			if (!r_type) {
				sc_log(card->ctx, "Couldn't determine response data type for %02x %02x\n", *(apdu->resp + 4), *(apdu->resp + 5));
				rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
				goto out;
			}
			response->data_type = r_type->type;
			if (apdu->resplen > resp_header_size) {
				response->data = malloc(apdu->resplen - resp_header_size);
				if (response->data == NULL) {
					rv = SC_ERROR_OUT_OF_MEMORY;
					goto out;
				}
				response->data_len = apdu->resplen - resp_header_size;
				memcpy(response->data, apdu->resp + resp_header_size, response->data_len);
				if (response->namespace->namespace_id != expected_response_ns) {
					sc_log(card->ctx, "Response had unexpected namespace: %s\n", response->namespace->namespace);
					rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
					goto out;
				}

				if (response->data_type != expected_response_type) {
					sc_log(card->ctx, "Response had unexpected type: %s\n", r_type->type_str);
					rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
					goto out;
				}

				if (expected_response_type == IDPRIME_TYPE_SYSTEM_VOID && response->data) {
					sc_log(card->ctx, "Got some data in the response, but expected a void result\n");
					rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
					goto out;
				}
			}
		}
	} else {
		if (!apdu->resplen) {
			sc_log(card->ctx, "Empty response\n");
			rv = SC_ERROR_WRONG_LENGTH;
			goto out;
		}
		switch (*resp) {
			case 1:
				//TODO Data is [return value][output params] - handle output params
				response->data = malloc(apdu->resplen - 1);
				if (response->data == NULL) {
					rv = SC_ERROR_OUT_OF_MEMORY;
					goto out;
				}
				response->data_type = expected_response_type;
				response->data_len = apdu->resplen - 1;
				memcpy(response->data, apdu->resp + 1, response->data_len);
				break;
			case 0xff:
				if (idprimenet_parse_exception(response, apdu->resp + 1, apdu->resplen - 1)) {
					rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
					goto out;
				}
				break;
			default:
				sc_log(card->ctx, "Invalid first byte of non-MSCM response %02x\n", *resp);
				rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
				goto out;
		}
	}

out:
	free(apdu);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_getchallenge(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *challenge,
		size_t *challenge_len) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Byte[] GetChallenge()",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response;
	int rv;

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (challenge == NULL    ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (challenge_len == NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (exception == NULL    ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL   ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	response = dotnet_op_response_new();

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		0
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		rv = idprimenet_apdu_to_u1array(card->ctx, response->data, response->data_len, challenge, challenge_len);
		LOG_TEST_GOTO_ERR(card->ctx, rv, "Failed to process response\n");

		sc_log(card->ctx, "CardModuleService.GetChallenge() response: '%s'", sc_dump_hex(challenge, *challenge_len));
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_contentmanager_getserialnumber(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *serialnumber,
		size_t *serialnumber_len) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x01},
		.namespace = "SmartCard",
		.type      = "SmartCard.ContentManager",
		.method    = "System.Byte[] get_SerialNumber()",
		.service   = "ContentManager",
	};
	dotnet_op_response_t *response;
	int rv;

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (exception == NULL       ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (serialnumber == NULL    ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (serialnumber_len == NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL      ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	response = dotnet_op_response_new();

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		0
	);

	if (rv) {
		sc_log(card->ctx, "Failure talking to card\n");
		goto out;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	} else {
		if (idprimenet_apdu_to_u1array(card->ctx, response->data, response->data_len, serialnumber, serialnumber_len)) {
			rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
			sc_log(card->ctx, "Failed to process response\n");
			goto out;
		}
	}

out:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_getserialnumber(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *serialnumber,
		size_t *serialnumber_len) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Byte[] get_SerialNumber()",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response;
	int rv;

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (serialnumber == NULL    ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (serialnumber_len == NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (exception == NULL       ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL      ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	response = dotnet_op_response_new();

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		0
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		rv = idprimenet_apdu_to_u1array(card->ctx, response->data, response->data_len, serialnumber, serialnumber_len);
		LOG_TEST_GOTO_ERR(card->ctx, rv, "Failed to process response\n");

		sc_log(card->ctx, "CardModuleService.get_SerialNumber() response: '%s'", sc_dump_hex(serialnumber, *serialnumber_len));
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_externalauthenticate(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *authresp,
		size_t authresp_len) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Void ExternalAuthenticate(System.Byte[])",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response = dotnet_op_response_new();
	int rv;

	idprimenet_arg_t arg = {
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		authresp_len,
		authresp
	};

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (authresp == NULL  ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (exception == NULL ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(card->ctx, "External authentication cryptogram: '%s'", sc_dump_hex(authresp, authresp_len));

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_VOID,
		1,
		arg
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	}
err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_isauthenticated (
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 role,
		u8 *answer) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Boolean IsAuthenticated(System.Byte)",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response = dotnet_op_response_new();
	int rv;

	idprimenet_arg_t arg = {
		IDPRIME_TYPE_SYSTEM_BYTE,
		1,
		&role
	};

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (exception == NULL ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BOOLEAN,
		1,
		arg
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		rv = idprimenet_apdu_to_boolean(card->ctx, response->data, response->data_len, answer);
		LOG_TEST_GOTO_ERR(card->ctx, rv, "Failed to process response\n");

		sc_log(card->ctx, "CardModuleService.IsAuthenticated(System.Byte) response: '%02x'", *answer);
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_forcegarbagecollector(
		struct sc_card *card,
		dotnet_exception_t **exception) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Void ForceGarbageCollector()",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response = dotnet_op_response_new();
	int rv;

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (exception == NULL ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_VOID,
		0
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_getversion(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *version_str,
		size_t *version_str_len) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.String get_Version()",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response = dotnet_op_response_new();
	int rv;

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (exception == NULL ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_STRING,
		0
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		rv = idprimenet_apdu_to_string(card->ctx, response->data, response->data_len, version_str, version_str_len);
		LOG_TEST_GOTO_ERR(card->ctx, rv, "Failed to process response\n");

		sc_log(card->ctx, "CardModuleService.get_Version() response: '%s'", sc_dump_hex((u8 *)version_str, *version_str_len));
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_getfiles(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *path,
		idprimenet_string_array_t **dest) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.String[] GetFiles(System.String)",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response = dotnet_op_response_new();
	int rv;

	idprimenet_arg_t arg = {
		IDPRIME_TYPE_SYSTEM_STRING,
		strlen(path), /* Pretend the terminating byte isn't there */
		(u8*)path
	};

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (path == NULL      ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (dest == NULL      ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (exception == NULL ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_STRING_ARRAY,
		1,
		arg
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		rv = idprimenet_apdu_to_string_array(card->ctx, response->data, response->data_len, dest);
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_readfile(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *path,
		u8 *data,
		size_t *data_len) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Byte[] ReadFile(System.String,System.Int32)",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response;
	int rv;

	idprimenet_arg_t arg1 = {
		IDPRIME_TYPE_SYSTEM_STRING,
		strlen(path), /* Pretend the terminating byte isn't there */
		path
	};
	idprimenet_arg_t arg2 = {
		IDPRIME_TYPE_SYSTEM_INT32,
		1,
		data_len
	};

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (path == NULL      ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (data == NULL      ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (data_len == NULL  ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (exception == NULL ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	response = dotnet_op_response_new();

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		2,
		arg1,
		arg2
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		rv = idprimenet_apdu_to_u1array(card->ctx, response->data, response->data_len, data, data_len);
		LOG_TEST_GOTO_ERR(card->ctx, rv, "Failed to process response\n");

		sc_log(card->ctx, "CardModuleService.ReadFile(System.String,System.Int32) response: '%s'", sc_dump_hex(data, *data_len));
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_maxpinretrycounter(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *maxpinretrycounter) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Byte MaxPinRetryCounter()",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response = dotnet_op_response_new();
	int rv;

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (maxpinretrycounter == NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (exception  == NULL        ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL        ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE,
		0
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		if (response->data_len != 1) {
			sc_log(card->ctx, "Expected one byte, got %ld bytes\n", response->data_len);
			rv = SC_ERROR_INVALID_DATA;
		} else {
			*maxpinretrycounter = *response->data;
			sc_log(card->ctx, "CardModuleService.MaxPinRetryCounter() response: %02x\n", *response->data);
		}
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_queryfreespace(
		struct sc_card *card,
		dotnet_exception_t **exception,
		int *freespace,
		size_t *freespace_len) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Int32[] QueryFreeSpace()",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response = dotnet_op_response_new();
	int rv;

	if (card == NULL) return -1;

	LOG_FUNC_CALLED(card->ctx);

	if (freespace == NULL    ) return -1;
	if (freespace_len == NULL) return -1;
	if (exception  == NULL   ) return -1;
	if (*exception != NULL   ) return -1;

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_INT32_ARRAY,
		0
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		rv = idprimenet_apdu_to_s4array(card->ctx, response->data, response->data_len, freespace, freespace_len);
		LOG_TEST_GOTO_ERR(card->ctx, rv, "Failed to process response\n");
		// Response seen to be 3 ints: 0x0001, 0x000f, 0xb468

		/* From libgtop11dotnet cardmod.h:
		 * //
		 * // Function: CardQueryFreeSpace
		 * //
		 * #define CARD_FREE_SPACE_INFO_CURRENT_VERSION 1
		 * typedef struct _CARD_FREE_SPACE_INFO
		 * {
		 *  DWORD dwVersion;
		 *  DWORD dwBytesAvailable;
		 *  DWORD dwKeyContainersAvailable;
		 *  DWORD dwMaxKeyContainers;
		 * } CARD_FREE_SPACE_INFO, *PCARD_FREE_SPACE_INFO;
		 */

		// So what does the above mean? 1 key container available? 15 max key containers
		// and 0xb468 (46208) bytes free?
		// Integration guide specifies the card as supporting:
		// 50KB free Flash memory space for certificate and application loading
		// Number of 1024 / 2048 bits certificates and keys: 15
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

int idprimenet_op_mscm_querykeysizes(
		struct sc_card *card,
		dotnet_exception_t **exception,
		idprimenet_key_sizes_t *key_sizes) {
	const dotnet_op_t op = {
		.port      = {0x00, 0x05},
		.namespace = "CardModuleService",
		.type      = "CardModuleService",
		.method    = "System.Int32[] QueryKeySizes()",
		.service   = "MSCM",
	};
	dotnet_op_response_t *response = dotnet_op_response_new();
	int rv;

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if (key_sizes == NULL ) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (exception  == NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (*exception != NULL) LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = idprimenet_op_call(
		card,
		&op,
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_INT32_ARRAY,
		0
	);

	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failure talking to card\n");

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	} else {
		size_t key_sizes_data_len = 4;
		int key_sizes_data[key_sizes_data_len];

		rv = idprimenet_apdu_to_s4array(card->ctx, response->data, response->data_len, key_sizes_data, &key_sizes_data_len);
		LOG_TEST_GOTO_ERR(card->ctx, rv, "Unparseable response to QueryKeySizes().\n");

		if (key_sizes_data_len != 4) {
			rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
			LOG_TEST_GOTO_ERR(card->ctx, rv, "Incorrect length of QueryKeySizes() response.\n");
		}
		key_sizes->incrementalBitLen = key_sizes_data[0];
		key_sizes->maximumBitLen     = key_sizes_data[1];
		key_sizes->defaultBitLen     = key_sizes_data[2];
		key_sizes->minimumBitLen     = key_sizes_data[3];
	}

err:
	dotnet_op_response_destroy(response);
	LOG_FUNC_RETURN(card->ctx, rv);
}

static int idprimenet_match_card(struct sc_card *card) {
	int i;

	LOG_FUNC_CALLED(card->ctx);

	i = _sc_match_atr(card, idprimenet_atrs, &card->type);
	if (i < 0) LOG_FUNC_RETURN(card->ctx, 0);

	LOG_FUNC_RETURN(card->ctx, 1);
}

int idprimenet_list_files(sc_card_t *card, u8 *buf, size_t buflen) {
	char *path = "";
	dotnet_exception_t *exception = NULL;
	idprimenet_string_array_t *results = NULL;
	int rv;

	if (card == NULL) return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	if ((rv = idprimenet_op_mscm_getfiles(card, &exception, path, &results))) {
		sc_log(card->ctx, "Failure querying files for '%s'\n", path);
		idprimenet_string_array_destroy(results);

		LOG_FUNC_RETURN(card->ctx, rv);
	}

	if (exception != NULL) {
		DOTNET_PRINT_EXCEPTION("Exception querying files", exception);
		idprimenet_string_array_destroy(results);
		dotnet_exception_destroy(exception);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_CARD_CMD_FAILED);
	} else {
			printf("Files on card:\n");
		for (idprimenet_string_array_t *elem = results; elem != NULL; elem = elem->next) {
			printf(" - %s\n", elem->value);
		}
		idprimenet_string_array_destroy(results);
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/* TODO: Figure out wtf I'm supposed to do here */
int idprimenet_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **file) {
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int idprimenet_get_serialnr(struct sc_card *card, struct sc_serial_number *serial) {
	u8 serialnumber[255];
	size_t serialnumber_len = 255;
	struct sc_context *ctx = card->ctx;
	dotnet_exception_t *exception = NULL;

	LOG_FUNC_CALLED(ctx);
	/* There are several ways to retrieve this */
	//if (idprimenet_op_contentmanager_getserialnumber(card, &exception, serialnumber, &serialnumber_len)) {
	if (idprimenet_op_mscm_getserialnumber(card, &exception, serialnumber, &serialnumber_len)) {
		sc_log(card->ctx, "Failure retrieving serial number\n");
	} else {
		if (exception != NULL) {
			sc_log(card->ctx, "Exception %s retrieving serial number\n", exception->type->type_str);
			dotnet_exception_destroy(exception);
		} else {
			memcpy(serial->value, serialnumber, serialnumber_len);
			serial->len = serialnumber_len;
		}
	}
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int idprimenet_init(struct sc_card *card) {
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	card->name = "Gemalto IDPrime.NET card";
	card->drv_data = NULL;

	rv = generate_ns_hivecodes();
	if (rv != SC_SUCCESS) {
		sc_log(card->ctx, "Failed to generate namespace hivecode cache\n");
		LOG_FUNC_RETURN(card->ctx, rv);
	}

	idprimenet_key_sizes_t keysizes = {0, 0, 0, 0};
	dotnet_exception_t *exception = NULL;

	if (idprimenet_op_mscm_querykeysizes(card, &exception, &keysizes)) {
		sc_log(card->ctx, "Failure retrieving keysizes\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_CARD_CMD_FAILED);
	}
	if (exception != NULL) {
		sc_log(card->ctx, "Exception %s retrieving keysizes\n", exception->type->type_str);
		dotnet_exception_destroy(exception);
		rv = SC_ERROR_CARD_CMD_FAILED;
	} else {
		for (unsigned int keysize = keysizes.minimumBitLen;
		     keysize <= keysizes.maximumBitLen;
		     keysize += keysizes.incrementalBitLen)
			_sc_card_add_rsa_alg(card, keysize, IDPRIMENET_CARD_DEFAULT_FLAGS,/* exponent - TODO: understand */ 0);
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int idprimenet_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr) {
	LOG_FUNC_CALLED(card->ctx);
	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		LOG_FUNC_RETURN(card->ctx, idprimenet_get_serialnr(card, (struct sc_serial_number *)ptr));
	}
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

static struct sc_card_driver * sc_get_driver(void) {
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	iso_ops = iso_drv->ops;
	idprimenet_ops = *iso_ops;

	idprimenet_ops.card_ctl = idprimenet_card_ctl;
	idprimenet_ops.init = idprimenet_init;
	idprimenet_ops.list_files = idprimenet_list_files;
	idprimenet_ops.match_card = idprimenet_match_card;
	idprimenet_ops.select_file = idprimenet_select_file;

	return &idprimenet_drv;
}

struct sc_card_driver * sc_get_idprimenet_driver(void) {
	return sc_get_driver();
}

#endif /* ENABLE_OPENSSL */
