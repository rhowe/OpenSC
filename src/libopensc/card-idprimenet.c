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
#include "internal.h"
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

static const idprimenet_type_hivecode_t idprimenet_type_none = {
	IDPRIME_TYPE_NONE,                     NULL,                        {0,    0   }
};

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
	char *namespace;
	u8 hivecode[4];
} idprimenet_namespace_hivecode_t;

/* From page 109 of the IDPrime.NET integration guide */
/* These could be calculated if we knew what the public key token
 * of the relevant assemblies were
 */
static const idprimenet_namespace_hivecode_t idprimenet_namespace_hivecodes[] = {
	{IDPRIME_NS_SYSTEM,                            "System",                            {0x00, 0xD2, 0x5D, 0x1C}},
	{IDPRIME_NS_SYSTEM_IO,                         "System.IO",                         {0x00, 0xD5, 0xE6, 0xDB}},
	{IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_CHANNELS,  "System.Runtime.Remoting.Channels",  {0x00, 0x00, 0x88, 0x6E}},
	{IDPRIME_NS_SYSTEM_RUNTIME_REMOTING,           "System.Runtime.Remoting",           {0x00, 0xEB, 0x3D, 0xD9}},
	{IDPRIME_NS_SYSTEM_SECURITY_CRYPTOGRAPHY,      "System.Security.Cryptography",      {0x00, 0xAC, 0xF5, 0x3B}},
	{IDPRIME_NS_SYSTEM_COLLECTIONS,                "System.Collections",                {0x00, 0xC5, 0xA0, 0x10}},
	{IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_CONTEXTS,  "System.Runtime.Remoting.Contexts",  {0x00, 0x1F, 0x49, 0x94}},
	{IDPRIME_NS_SYSTEM_SECURITY,                   "System.Security",                   {0x00, 0x96, 0x41, 0x45}},
	{IDPRIME_NS_SYSTEM_REFLECTION,                 "System.Reflection",                 {0x00, 0x08, 0x75, 0x0F}},
	{IDPRIME_NS_SYSTEM_RUNTIME_REMOTING_MESSAGING, "System.Runtime.Remoting.Messaging", {0x00, 0xDE, 0xB9, 0x40}},
	{IDPRIME_NS_SYSTEM_DIAGNOSTICS,                "System.Diagnostics",                {0x00, 0x97, 0x99, 0x5F}},
	{IDPRIME_NS_SYSTEM_RUNTIME_COMPILERSERVICES,   "System.Runtime.CompilerServices",   {0x00, 0xF6, 0x3E, 0x11}},
	{IDPRIME_NS_SYSTEM_RUNTIME_SERIALIZATION,      "System.Runtime.Serialization",      {0x00, 0x8D, 0x3B, 0x3D}}, /* From libgtop11dotnet MarshallerCfg.h */
	{IDPRIME_NS_SYSTEM_TEXT,                       "System.Text",                       {0x00, 0x70, 0x27, 0x56}},
	{IDPRIME_NS_SMARTCARD,                         "SmartCard",                         {0x00, 0xF5, 0xEF, 0xBF}},
	/* Not really clear this is the real namespace name */
	{IDPRIME_NS_CARDMODULESERVICE,                 "CardModuleService",                 {0x00, 0xC0, 0x4B, 0x4E}},
	{IDPRIME_NS_NETCARDFILESYSTEM,                 "NetcardFilesystem",                 {0x00, 0xA1, 0xAC, 0x39}}, /* From libgtop11dotnet MarshallerCfg.h */
	{IDPRIME_NS_NONE,                              NULL,                                {0,    0,    0,    0   }}
};

dotnet_exception_t *dotnet_exception_new() {
	dotnet_exception_t *res = malloc(sizeof(dotnet_exception_t));
	if (res == NULL) return NULL;

	res->type = &idprimenet_type_none;
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

#define DOTNET_PRINT_EXCEPTION(msg, exception) printf("%s: %s: %s\n", msg, exception->type->type_str, exception->message == NULL ? "(no message)" : exception->message)

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

static int namespace_to_hivecode(const char *namespace, u8 hivecode[4]) {
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

static const idprimenet_namespace_hivecode_t *hivecode_to_namespace(const u8 hivecode[4]) {
	for (unsigned int i = 0; idprimenet_namespace_hivecodes[i].namespace; i++) {
		if (idprimenet_namespace_hivecodes[i].hivecode[0] == hivecode[0]
		 && idprimenet_namespace_hivecodes[i].hivecode[1] == hivecode[1]
		 && idprimenet_namespace_hivecodes[i].hivecode[2] == hivecode[2]
		 && idprimenet_namespace_hivecodes[i].hivecode[3] == hivecode[3]) {
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

	return 0;
}

static int method_to_hivecode(const char *method, u8 hivecode[2]) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	u8 md_value[EVP_MAX_MD_SIZE];
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

static int idprimenet_apdu_to_string(const u8 *data, size_t data_len, char *dest, size_t *dest_len) {
	/* dest needs to be at least data_len+1 in size */
	unsigned int strlen;
	static const unsigned short header_len = 2;
	if (data_len < header_len) {
		printf("Malformed data - too small for a string\n");
		return -1;
	}
	strlen = (data[0] << 8) | data[1];
	if (*dest_len < strlen + 1) {
		printf("Buffer isn't big enough for string\n");
		return 0;
	}
	memcpy(dest, data + header_len, strlen);
	dest[strlen] = '\0';
	*dest_len = strlen + 1;

	return 0;
}

struct idprimenet_string_array {
	char *value;
	struct idprimenet_string_array *next;
};

static struct idprimenet_string_array *idprimenet_string_array_new() {
	struct idprimenet_string_array *elem = malloc(sizeof(struct idprimenet_string_array));
	if (elem != NULL) {
		elem->value = NULL;
		elem->next = NULL;
	}
	return elem;
}

static void idprimenet_string_array_destroy(struct idprimenet_string_array *list) {
	while (list != NULL) {
		if (list->value != NULL) { free(list->value); }
		list = list->next;
	}
}

static int idprimenet_apdu_to_string_array(
		const u8 *data,
		size_t data_len,
		struct idprimenet_string_array **dest) {
	unsigned int array_len; // TODO: 4 bytes?
	const unsigned short header_len = 4;
	struct idprimenet_string_array **current = dest;
	if (data_len < header_len) {
		printf("Malformed data - too small for a string array\n");
		return -1;
	}
	if (dest == NULL) {
		printf("dest cannot be null\n");
		return -1;
	}

	array_len = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);
	data += 4;
	data_len -= 4;

	for (unsigned int i = 0; i < array_len; i++) {
		struct idprimenet_string_array *elem = idprimenet_string_array_new();
		size_t buf_len = 255; // FIXME: Fixed buffer :(
		elem->value = malloc(buf_len);
		if (idprimenet_apdu_to_string(data, data_len, elem->value, &buf_len)) {
			idprimenet_string_array_destroy(elem);
			return -1;
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

	return 0;
}

static int idprimenet_apdu_to_u1array(
		const u8 *data,
		size_t data_len,
		u8 *dest,
		size_t *dest_len) {
	size_t array_len;

	if (data_len < 4) {
		printf("Malformed data - too small for a u1array\n");
		return -1;
	}
	if ((data_len - 4) > *dest_len) {
		printf("Buffer too small for %ld bytes\n", data_len);
		return -1;
	}

	array_len = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);

	memcpy(dest, data + 4, array_len);

	*dest_len = array_len;

	return 0;
}

/*
static int idprimenet_apdu_to_byte(
		const u8 *data,
		size_t data_len,
		u8 *dest) {
	if (!data_len) {
		printf("Malformed data - too small for a byte\n");
		return -1;
	}
	if (!dest) {
		printf("Target buffer is null\n");
		return -1;
	}

	*dest = *data;

	return 0;
}
*/

static int idprimenet_apdu_to_boolean(
		const u8 *data,
		size_t data_len,
		u8 *dest) {
	if (!data_len) {
		printf("Malformed data - too small for a byte\n");
		return -1;
	}
	if (!dest) {
		printf("Target buffer is null\n");
		return -1;
	}

	*dest = *data ? 1 : 0;

	return 0;
}

static int idprimenet_apdu_to_s4array(
		const u8 *data,
		size_t data_len,
		int *dest,
		size_t *dest_len) {
	size_t array_len;

	if (data_len < 4) {
		printf("Malformed data - too small for a s4array\n");
		return -1;
	}
	if ((data_len - 4) / 4 > *dest_len) {
		printf("Buffer of %ld ints too small for %ld bytes\n", *dest_len, data_len);
		return -1;
	}
	if (data_len % 4) {
		printf("Buffer not a multiple of 4 bytes\n");
		return -1;
	}

	array_len = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]);

	for (size_t i = 0; i < data_len / 4; i++)
		dest[i] = (data[4 + (i * 4)] << 24 | data[5 + (i * 4)] << 16 | data[6 + (i * 4)] << 8 | data[7 + (i * 4)]);

	*dest_len = array_len;

	return 0;
}

static int args_to_adpu_data(u8 **data, size_t *data_len, unsigned int n_args, va_list args) {
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

	for (unsigned int i = 0; i < n_args; i++) {
		idprimenet_arg_t arg = va_arg(args, idprimenet_arg_t);
		size_t arg_data_len;
		struct arg_data_list *elem;

		elem = malloc(sizeof(struct arg_data_list));

		if (elem == NULL) {
			printf("malloc failure\n");
			goto error;
		}
		elem->next = NULL;

		switch (arg.type) {
			// FIXME: goto error is wrong and doesn't clean up properly
			case IDPRIME_TYPE_SYSTEM_INT32:
				{
					int val;
					if (arg.value_len != 1)
						goto error;
					elem->entry.data = malloc(4);
					if (elem->entry.data == NULL) {
						printf("malloc failure\n");
						goto error;
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
					if (arg.value_len != 1)
						goto error;
					elem->entry.data = malloc(1);
					if (elem->entry.data == NULL) {
						printf("malloc failure\n");
						goto error;
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
						printf("malloc failure\n");
						goto error;
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
						printf("malloc failure\n");
						goto error;
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
				printf("Don't know how to size arg type %d\n", arg.type);
				goto error;
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
	if (!dest) goto error;

	*data = dest;
	for (struct arg_data_list *elem = args_data_head; elem != NULL; elem = elem->next) {
		memcpy(dest, elem->entry.data, elem->entry.data_len);
		dest += elem->entry.data_len;
		free(elem->entry.data);
	}
	return 0;

error:
	va_end(args);
	for (struct arg_data_list *elem = args_data; elem != NULL; elem = elem->next) {
		free(elem->entry.data);
	}
	return 1;
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
	sc_apdu_t *apdu;
	int cla;
	u8 *args_data;
	size_t args_data_len;

	if (!op || !op->service)
		return NULL;

	apdu = malloc(sizeof(sc_apdu_t));
	if (!apdu) return NULL;

	/* Does this call return any data? */
	cla = strcmp("System.Void", op->type) ? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_3_SHORT;

   sc_format_apdu(card, apdu, cla, 0xc2, 0, 0);
	apdu->cla = 0x80;

	service_len = strlen(op->service);
	if (service_len > 0xffff) {
		free(apdu);
		return NULL;
	}

	if (namespace_to_hivecode(op->namespace, namespace)) {
		free(apdu);
		return NULL;
	}
	if (type_to_hivecode(op->type, type)) {
		free(apdu);
		return NULL;
	}
	if (method_to_hivecode(op->method, method)) {
		free(apdu);
		return NULL;
	}

	if (args_to_adpu_data(&args_data, &args_data_len, n_args, args)) {
		free(apdu);
		return NULL;
	}
	apdu_data_len = apdu_prefix_len + service_len + args_data_len;
	apdu_data_ptr = malloc(apdu_data_len);

	if (!apdu_data_ptr) {
		free(args_data);
		free(apdu);
		return NULL;
	}

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

	//printf("APDU generated for: %s:0x%02x%02x [%s] (%s) %s\n", op->service, op->port[0], op->port[1], op->namespace, op->type, op->method);

	return apdu;
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
		u8 port_msb,
		u8 port_lsb,
		char *namespace,
		char *type,
		char *method,
		char *service,
		dotnet_op_response_t *response,
		idprimenet_namespace_t expected_response_ns,
		idprimenet_type_t expected_response_type,
		const unsigned int n_args,
		...
	) {
	va_list args;
	int res;
	dotnet_op_t op;
	sc_apdu_t *apdu;
	u8 *resp = NULL;
	size_t resplen = 255; //FIXME: Be more flexible
	const unsigned int resp_header_size = 6; // 4 bytes of namespace hivecode + 2 bytes of type hivecode
	const idprimenet_type_hivecode_t *r_type;

	if (!card) return 0;
	if (!response) return 0;

	resp = malloc(resplen);
	if (!resp) return 0;

	op.port[0] = port_msb;
	op.port[1] = port_lsb;
	op.namespace = namespace;
	op.type = type,
	op.method = method,
	op.service = service;

	va_start(args, n_args);
	apdu = dotnet_op_to_apdu(card, &op, n_args, args);
	va_end(args);
	if (!apdu) return 0;

	apdu->resp = resp;
	apdu->resplen = resplen;
	apdu->le = resplen;

	res = sc_transmit_apdu(card, apdu);

	if (res != SC_SUCCESS) {
		free(apdu);
		LOG_TEST_RET(card->ctx, res, "APDU transmit failed"); // TODO: See if this does what we actually want */
	}

	if (!strcmp("MSCM", service) && apdu->resplen < resp_header_size) {
		if (expected_response_type == IDPRIME_TYPE_SYSTEM_VOID) {
			// No data expected in the response
			response->data_type = IDPRIME_TYPE_SYSTEM_VOID;
			response->data_len = 0;
		} else {
			printf("Response too short?!\n");
		}

		free(apdu);
		return 1;
	}

	if (!strcmp("MSCM", service)) {
		// MSCM has its own special response format
		if (idprimenet_parse_exception(response, apdu->resp, apdu->resplen)) {
			if (apdu->resplen < resp_header_size) {
				printf("Response too short - only %ld bytes\n", apdu->resplen);
				goto error;
			}
			response->namespace = hivecode_to_namespace(resp);
			if (!response->namespace) {
				printf("Couldn't determine response namespace\n");
				goto error;
			}
			r_type = hivecode_to_type(apdu->resp + 4); // TODO: Check for failed lookup
			if (!r_type) {
				printf("Couldn't determine response data type for %02x %02x\n", *(apdu->resp + 4), *(apdu->resp + 5));
				goto error;
			}
			response->data_type = r_type->type;
			if (apdu->resplen > resp_header_size) {
				response->data = malloc(apdu->resplen - resp_header_size);
				if (!response->data) goto error;
				response->data_len = apdu->resplen - resp_header_size;
				memcpy(response->data, apdu->resp + resp_header_size, response->data_len);
				if (response->namespace->namespace_id != expected_response_ns) {
					printf("Response had unexpected namespace: %s\n", response->namespace->namespace);
					goto error;
				}

				if (response->data_type != expected_response_type) {
					printf("Response had unexpected type: %s\n", r_type->type_str);
					goto error;
				}

				if (expected_response_type == IDPRIME_TYPE_SYSTEM_VOID && response->data) {
					printf("Got some data in the response, but expected a void result\n");
					goto error;
				}
			}
		}
	} else {
		if (!apdu->resplen) {
			printf("Empty response\n");
			goto error;
		}
		switch (*resp) {
			case 1:
				//TODO Data is [return value][output params] - handle output params
				response->data = malloc(apdu->resplen - 1);
				if (!response->data) goto error;
				response->data_type = expected_response_type;
				response->data_len = apdu->resplen - 1;
				memcpy(response->data, apdu->resp + 1, response->data_len);
				break;
			case 0xff:
				if (idprimenet_parse_exception(response, apdu->resp + 1, apdu->resplen - 1)) goto error;
				break;
			default:
				printf("Invalid first byte of non-MSCM response %02x\n", *resp);
				goto error;
		}
	}

	free(apdu);
	return 1;
error:
	free(apdu);
	return 0;
}

int idprimenet_op_mscm_getchallenge(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *challenge,
		size_t *challenge_len) {
	dotnet_op_response_t *response;
	int res;

	if (card == NULL         ) return -1;
	if (challenge == NULL    ) return -1;
	if (challenge_len == NULL) return -1;
	if (exception == NULL    ) return -1;
	if (*exception != NULL   ) return -1;

	response = dotnet_op_response_new();

	res = idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Byte[] GetChallenge()",
		"MSCM",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		0
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		if (idprimenet_apdu_to_u1array(response->data, response->data_len, challenge, challenge_len)) {
			printf("Failed to process response\n");
			goto error;
		}
	}

	dotnet_op_response_destroy(response);
	return 0;

error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_contentmanager_getserialnumber(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *serialnumber,
		size_t *serialnumber_len) {
	dotnet_op_response_t *response;
	int res;

	if (card == NULL            ) return -1;
	if (exception == NULL       ) return -1;
	if (serialnumber == NULL    ) return -1;
	if (serialnumber_len == NULL) return -1;
	if (*exception != NULL      ) return -1;

	response = dotnet_op_response_new();

	res = idprimenet_op_call(
		card,
		0, 0x01,
		"SmartCard",
		"SmartCard.ContentManager",
		"System.Byte[] get_SerialNumber()",
		"ContentManager",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		0
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		if (idprimenet_apdu_to_u1array(response->data, response->data_len, serialnumber, serialnumber_len)) {
			printf("Failed to process response\n");
			goto error;
		}
	}

	dotnet_op_response_destroy(response);
	return 0;

error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_mscm_getserialnumber(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *serialnumber,
		size_t *serialnumber_len) {
	dotnet_op_response_t *response;
	int res;

	if (card == NULL            ) return -1;
	if (serialnumber == NULL    ) return -1;
	if (serialnumber_len == NULL) return -1;
	if (exception == NULL       ) return -1;
	if (*exception != NULL      ) return -1;

	response = dotnet_op_response_new();

	res = idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Byte[] get_SerialNumber()",
		"MSCM",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		0
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		if (idprimenet_apdu_to_u1array(response->data, response->data_len, serialnumber, serialnumber_len)) {
			printf("Failed to process response\n");
			goto error;
		}
	}

	dotnet_op_response_destroy(response);
	return 0;

error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_mscm_externalauthenticate(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *authresp,
		size_t authresp_len) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	idprimenet_arg_t arg = {
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		authresp_len,
		authresp
	};

	if (card == NULL      ) return -1;
	if (authresp == NULL  ) return -1;
	if (exception == NULL ) return -1;
	if (*exception != NULL) return -1;

	res = idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Void ExternalAuthenticate(System.Byte[])",
		"MSCM",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_VOID,
		1,
		arg
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	}

	dotnet_op_response_destroy(response);
	return 0;
error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_mscm_isauthenticated (
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 role,
		u8 *answer) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	idprimenet_arg_t arg = {
		IDPRIME_TYPE_SYSTEM_BYTE,
		1,
		&role
	};

	if (card == NULL      ) return -1;
	if (exception == NULL ) return -1;
	if (*exception != NULL) return -1;

	res = idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Boolean IsAuthenticated(System.Byte)",
		"MSCM",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BOOLEAN,
		1,
		arg
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		if (idprimenet_apdu_to_boolean(response->data, response->data_len, answer)) {
			goto error;
		}
	}

	dotnet_op_response_destroy(response);
	return 0;
error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_mscm_forcegarbagecollector(
		struct sc_card *card,
		dotnet_exception_t **exception) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	if (card == NULL      ) return -1;
	if (exception == NULL ) return -1;
	if (*exception != NULL) return -1;

	res = idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Void ForceGarbageCollector()",
		"MSCM",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_VOID,
		0
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	}

	dotnet_op_response_destroy(response);
	return 0;
error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_mscm_getversion(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *version_str,
		size_t *version_str_len) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	if (card == NULL      ) return -1;
	if (exception == NULL ) return -1;
	if (*exception != NULL) return -1;

	res = idprimenet_op_call(
		card,
		0, 0x05, /* port */
		"CardModuleService",
		"CardModuleService",
		"System.String get_Version()", /* method */
		"MSCM", /* service name */
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_STRING,
		0
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		idprimenet_apdu_to_string(response->data, response->data_len, version_str, version_str_len);
	}

	dotnet_op_response_destroy(response);
	return 0;
error:
	dotnet_op_response_destroy(response);
	return -1;
}

// TODO: Return the data somehow
static int idprimenet_op_mscm_getfiles(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *path,
		struct idprimenet_string_array **dest) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	idprimenet_arg_t arg = {
		IDPRIME_TYPE_SYSTEM_STRING,
		strlen(path), /* Pretend the terminating byte isn't there */
		(u8*)path
	};

	if (card == NULL      ) return -1;
	if (path == NULL      ) return -1;
	if (dest == NULL      ) return -1;
	if (exception == NULL ) return -1;
	if (*exception != NULL) return -1;

	res = idprimenet_op_call(
		card,
		0, 0x05, /* port */
		"CardModuleService",
		"CardModuleService",
		"System.String[] GetFiles(System.String)", /* method */
		"MSCM", /* service name */
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_STRING_ARRAY,
		1,
		arg
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		idprimenet_apdu_to_string_array(response->data, response->data_len, dest);
	}

	dotnet_op_response_destroy(response);
	return 0;
error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_mscm_readfile(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *path,
		u8 *data,
		size_t *data_len) {
	dotnet_op_response_t *response;
	int res;
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

	if (card == NULL      ) return -1;
	if (path == NULL      ) return -1;
	if (data == NULL      ) return -1;
	if (data_len == NULL  ) return -1;
	if (exception == NULL ) return -1;
	if (*exception != NULL) return -1;

	response = dotnet_op_response_new();

	res = idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Byte[] ReadFile(System.String,System.Int32)",
		"MSCM",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
		2,
		arg1,
		arg2
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		if (idprimenet_apdu_to_u1array(response->data, response->data_len, data, data_len)) {
			printf("Failed to process response\n");
			goto error;
		}
	}

	dotnet_op_response_destroy(response);
	return 0;

error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_mscm_maxpinretrycounter(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *maxpinretrycounter) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	if (card == NULL              ) return -1;
	if (maxpinretrycounter == NULL) return -1;
	if (exception  == NULL        ) return -1;
	if (*exception != NULL        ) return -1;

	res = idprimenet_op_call(
		card,
		0, 0x05, /* port */
		"CardModuleService",
		"CardModuleService",
		"System.Byte MaxPinRetryCounter()", /* method */
		"MSCM", /* service name */
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_BYTE,
		0
	);

	if (!res) {
		printf("Failure talking to card\n");
		goto error;
	}

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		if (response->data_len == 1) {
			*maxpinretrycounter = *response->data;
		} else {
			printf("Expected one byte, got %ld bytes\n", response->data_len);
		}
	}

	dotnet_op_response_destroy(response);
	return 0;
error:
	dotnet_op_response_destroy(response);
	return -1;
}

static int idprimenet_op_mscm_queryfreespace(
		struct sc_card *card,
		dotnet_exception_t **exception,
		int *freespace,
		size_t *freespace_len) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	if (card == NULL         ) return -1;
	if (freespace == NULL    ) return -1;
	if (freespace_len == NULL) return -1;
	if (exception  == NULL   ) return -1;
	if (*exception != NULL   ) return -1;

	res = idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Int32[] QueryFreeSpace()",
		"MSCM",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_INT32_ARRAY,
		0
	);
	if (!res) goto error;

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		idprimenet_apdu_to_s4array(response->data, response->data_len, freespace, freespace_len);
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
	}

	dotnet_op_response_destroy(response);
	return 0;

error:
	dotnet_op_response_destroy(response);
	return 1;
}

typedef struct {
	unsigned int minimumBitLen;
	unsigned int defaultBitLen;
	unsigned int maximumBitLen;
	unsigned int incrementalBitLen;
} idprimenet_key_sizes_t;

static int idprimenet_op_mscm_querykeysizes(
		struct sc_card *card,
		dotnet_exception_t **exception,
		idprimenet_key_sizes_t *key_sizes) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	if (card == NULL      ) return -1;
	if (key_sizes == NULL ) return -1;
	if (exception  == NULL) return -1;
	if (*exception != NULL) return -1;

	res = idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Int32[] QueryKeySizes()",
		"MSCM",
		response,
		IDPRIME_NS_SYSTEM,
		IDPRIME_TYPE_SYSTEM_INT32_ARRAY,
		0
	);
	if (!res) goto error;

	if (response->exception != NULL) {
		*exception = dotnet_exception_clone(response->exception);
		if (*exception == NULL) goto error;
	} else {
		size_t key_sizes_data_len = 4;
		int key_sizes_data[key_sizes_data_len];

		idprimenet_apdu_to_s4array(response->data, response->data_len, key_sizes_data, &key_sizes_data_len);

		if (key_sizes_data_len != 4) {
			printf("Unexpected respones to QueryKeySizes(). Only %ld bytes\n", key_sizes_data_len);
			goto error;
		}
		key_sizes->incrementalBitLen = key_sizes_data[0];
		key_sizes->maximumBitLen     = key_sizes_data[1];
		key_sizes->defaultBitLen     = key_sizes_data[2];
		key_sizes->minimumBitLen     = key_sizes_data[3];
	}

	dotnet_op_response_destroy(response);
	return 0;

error:
	dotnet_op_response_destroy(response);
	return 1;
}

static int idprimenet_match_card(struct sc_card *card)
{
	int i;

	i = _sc_match_atr(card, idprimenet_atrs, &card->type);
	if (i < 0) return 0;

	{
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
			printf("Card version (%ld chars) %s\n", version_len, version);
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		u8 serialnumber[255];
		size_t serialnumber_len = 255;
		if (idprimenet_op_mscm_getserialnumber(card, &exception, serialnumber, &serialnumber_len)) {
			printf("Failure retrieving serial number\n");
			return 0;
		}
		if (exception != NULL) {
			printf("Exception %s retrieving serial number\n", exception->type->type_str);
			dotnet_exception_destroy(exception);
			return 0;
		} else {
			printf("Serial number: 0x");
			for (unsigned int i = 0; i < serialnumber_len; i++)
				printf("%02x", serialnumber[i]);
			printf("\n");
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		int freespace[255];
		size_t freespace_len = 255;
		if (idprimenet_op_mscm_queryfreespace(card, &exception, freespace, &freespace_len)) {
			printf("Failure retrieving freespace\n");
			return 0;
		}
		if (exception != NULL) {
			printf("Exception %s retrieving freespace\n", exception->type->type_str);
			dotnet_exception_destroy(exception);
			return 0;
		} else {
			printf("Freespace: 0x");
			for (unsigned int i = 0; i < freespace_len; i++)
				printf("%04x", freespace[i]);
			printf("\n");
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		idprimenet_key_sizes_t keysizes = {0, 0, 0, 0};
		if (idprimenet_op_mscm_querykeysizes(card, &exception, &keysizes)) {
			printf("Failure retrieving keysizes\n");
			return 0;
		}
		if (exception != NULL) {
			printf("Exception %s retrieving keysizes\n", exception->type->type_str);
			dotnet_exception_destroy(exception);
			return 0;
		} else {
			printf("Key sizes: min: %d, default: %d, max: %d, incremental: %d\n",
				keysizes.minimumBitLen,
				keysizes.defaultBitLen,
				keysizes.maximumBitLen,
				keysizes.incrementalBitLen
			);
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		u8 maxpinretrycounter = 0;
		if (idprimenet_op_mscm_maxpinretrycounter(card, &exception, &maxpinretrycounter)) {
			printf("Failure retrieving max pin retry counter\n");
		} else {
			if (exception != NULL) {
				DOTNET_PRINT_EXCEPTION("Exception retrieving max pin retry counter", exception);
				dotnet_exception_destroy(exception);
			} else {
				printf("Max pin retry counter: 0x%02x\n", maxpinretrycounter);
			}
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		if (idprimenet_op_mscm_forcegarbagecollector(card, &exception)) {
			printf("Failure forcing GC\n");
			return 0;
		}
		if (exception != NULL) {
			printf("Exception %s forcing GC\n", exception->type->type_str);
			dotnet_exception_destroy(exception);
			return 0;
		} else {
			printf("GC forced\n");
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		u8 serialnumber[255];
		size_t serialnumber_len = 255;
		if (idprimenet_op_contentmanager_getserialnumber(card, &exception, serialnumber, &serialnumber_len)) {
			printf("Failure retrieving serial number\n");
		} else {
			if (exception != NULL) {
				printf("Exception %s retrieving serial number\n", exception->type->type_str);
				dotnet_exception_destroy(exception);
			} else {
				printf("Serial number: 0x");
				for (unsigned int i = 0; i < serialnumber_len; i++)
					printf("%02x", serialnumber[i]);
				printf("\n");
			}
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		u8 authresp[1] = { 0 };
		if (idprimenet_op_mscm_externalauthenticate(card, &exception, authresp, sizeof(authresp))) {
			printf("Failure sending auth response\n");
		} else {
			if (exception != NULL) {
				printf("Exception %s sending auth response\n", exception->type->type_str);
				dotnet_exception_destroy(exception);
			} else {
				printf("External auth didn't raise an error\n");
			}
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		u8 role = 1, isauthenticated = 0;
		if (idprimenet_op_mscm_isauthenticated(card, &exception, role, &isauthenticated)) {
			printf("Failure querying auth status\n");
			return 0;
		}
		if (exception != NULL) {
			printf("Exception %s querying auth status\n", exception->type->type_str);
			dotnet_exception_destroy(exception);
			return 0;
		} else {
			printf("Is role %d authenticated? %d\n", role, isauthenticated);
		}
	}
	{
		dotnet_exception_t *exception = NULL;
		char *path = "";
		struct idprimenet_string_array *results = NULL;
		if (idprimenet_op_mscm_getfiles(card, &exception, path, &results)) {
			printf("Failure querying files for '%s'\n", path);
			idprimenet_string_array_destroy(results);
			return 0;
		}
		if (exception != NULL) {
			printf("Exception %s querying files for '%s'\n", exception->type->type_str, path);
			idprimenet_string_array_destroy(results);
			dotnet_exception_destroy(exception);
			return 0;
		} else {
			printf("Files on card:\n");
			for (struct idprimenet_string_array *elem = results; elem != NULL; elem = elem->next) {
				size_t buf_len = 16384;
				u8 buf[buf_len];
				if (idprimenet_op_mscm_readfile(card, &exception, elem->value, buf, &buf_len)) {
					printf("Failure reading '%s'\n", elem->value);
					return 0;
				}
				if (exception != NULL) {
					printf("Exception %s reading '%s'\n", exception->type->type_str, elem->value);
					dotnet_exception_destroy(exception);
					return 0;
				} else {
					printf(" - %s (%ld bytes)\n", elem->value, buf_len);
				}
			}
			idprimenet_string_array_destroy(results);
		}
	}

	return 1;
}

int idprimenet_list_files(sc_card_t *card, u8 *buf, size_t buflen) {
	char *path = "";
	dotnet_exception_t *exception = NULL;
	struct idprimenet_string_array *results = NULL;

	if (idprimenet_op_mscm_getfiles(card, &exception, path, &results)) {
		printf("Failure querying files for '%s'\n", path);
		idprimenet_string_array_destroy(results);
		return 0;
	}
	if (exception != NULL) {
		DOTNET_PRINT_EXCEPTION("Exception querying files", exception);
		idprimenet_string_array_destroy(results);
		dotnet_exception_destroy(exception);
		return 0;
	} else {
			printf("Files on card:\n");
		for (struct idprimenet_string_array *elem = results; elem != NULL; elem = elem->next) {
			printf(" - %s\n", elem->value);
		}
		idprimenet_string_array_destroy(results);
	}
	return 0;
}

/* TODO: Figure out wtf I'm supposed to do here */
int idprimenet_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **file) {
	struct sc_context *ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int idprimenet_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	u8 serialnumber[255];
	size_t serialnumber_len = 255;
	struct sc_context *ctx = card->ctx;
	dotnet_exception_t *exception = NULL;

	LOG_FUNC_CALLED(ctx);
	/* There are several ways to retrieve this */
	//if (idprimenet_op_contentmanager_getserialnumber(card, &exception, serialnumber, &serialnumber_len)) {
	if (idprimenet_op_mscm_getserialnumber(card, &exception, serialnumber, &serialnumber_len)) {
		printf("Failure retrieving serial number\n");
	} else {
		if (exception != NULL) {
			printf("Exception %s retrieving serial number\n", exception->type->type_str);
			dotnet_exception_destroy(exception);
		} else {
			memcpy(serial->value, serialnumber, serialnumber_len);
			serial->len = serialnumber_len;
		}
	}
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int idprimenet_init(struct sc_card *card)
{
	LOG_FUNC_CALLED(card->ctx);

	card->name = "Gemalto IDPrime.NET card";
	card->drv_data = NULL;

	{
		idprimenet_key_sizes_t keysizes = {0, 0, 0, 0};
		dotnet_exception_t *exception = NULL;

		if (idprimenet_op_mscm_querykeysizes(card, &exception, &keysizes)) {
			sc_log(card->ctx, "Failure retrieving keysizes\n");
			return 0;
		}
		if (exception != NULL) {
			printf("Exception %s retrieving keysizes\n", exception->type->type_str);
			dotnet_exception_destroy(exception);
			return 0;
		} else {
			for (unsigned int keysize = keysizes.minimumBitLen;
			     keysize <= keysizes.maximumBitLen;
			     keysize += keysizes.incrementalBitLen)
				_sc_card_add_rsa_alg(card, keysize, IDPRIMENET_CARD_DEFAULT_FLAGS,/* exponent - TODO: understand */ 0);
		}
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int idprimenet_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	LOG_FUNC_CALLED(card->ctx);
	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		// There are many ways to do this
		LOG_FUNC_RETURN(card->ctx, idprimenet_get_serialnr(card, (struct sc_serial_number *)ptr));
	}
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

static struct sc_card_driver * sc_get_driver(void)
{
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

struct sc_card_driver * sc_get_idprimenet_driver(void)
{
	return sc_get_driver();
}

#endif /* ENABLE_OPENSSL */
