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

typedef struct {
	char *namespace;
	char *type;
	unsigned char *data;
} dotnet_apdu_response_t;

static struct sc_atr_table idprimenet_atrs[] = {
	{"3b:16:96:41:73:74:72:69:64", NULL, NULL, SC_CARD_TYPE_IDPRIMENET_GENERIC, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

/* From http://support.gemalto.com/index.php?id=how_i_can_unblock_the_pin */
/*
static const unsigned char default_admin_key[] = {
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
	unsigned char hivecode[4];
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

typedef enum {
	IDPRIME_TYPE_NONE,
	IDPRIME_TYPE_SYSTEM_VOID,
	IDPRIME_TYPE_SYSTEM_INT32,
	IDPRIME_TYPE_SYSTEM_INT32_ARRAY,
	IDPRIME_TYPE_SYSTEM_BOOLEAN,
	IDPRIME_TYPE_SYSTEM_BOOLEAN_ARRAY,
	IDPRIME_TYPE_SYSTEM_SBYTE,
	IDPRIME_TYPE_SYSTEM_SBYTE_ARRAY,
	IDPRIME_TYPE_SYSTEM_UINT16,
	IDPRIME_TYPE_SYSTEM_UINT16_ARRAY,
	IDPRIME_TYPE_SYSTEM_UINT32,
	IDPRIME_TYPE_SYSTEM_UINT32_ARRAY,
	IDPRIME_TYPE_SYSTEM_BYTE,
	IDPRIME_TYPE_SYSTEM_BYTE_ARRAY,
	IDPRIME_TYPE_SYSTEM_CHAR,
	IDPRIME_TYPE_SYSTEM_CHAR_ARRAY,
	IDPRIME_TYPE_SYSTEM_INT16,
	IDPRIME_TYPE_SYSTEM_INT16_ARRAY,
	IDPRIME_TYPE_SYSTEM_STRING,
	IDPRIME_TYPE_SYSTEM_STRING_ARRAY,
	IDPRIME_TYPE_SYSTEM_INT64,
	IDPRIME_TYPE_SYSTEM_INT64_ARRAY,
	IDPRIME_TYPE_SYSTEM_UINT64,
	IDPRIME_TYPE_SYSTEM_UINT64_ARRAY,
	IDPRIME_TYPE_SYSTEM_IO_MEMORYSTREAM,
	IDPRIME_TYPE_SMARTCARD_CONTENTMANAGER,
	/* Exception types */
	IDPRIME_EX_TYPE_SYSTEM_EXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_SYSTEMEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_OUTOFMEMORYEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_ARGUMENTEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_ARGUMENTNULLEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_NULLREFERENCEEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_ARGUMENTOUTOFRANGEEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_NOTSUPPORTEDEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_INVALIDCASTEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_INVALIDOPERATIONEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_NOTIMPLEMENTEDEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_OBJECTDISPOSEDEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_UNAUTHORIZEDACCESSEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_INDEXOUTOFRANGEEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_FORMATEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_ARITHMETICEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_OVERFLOWEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_BADIMAGEFORMATEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_APPLICATIONEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_ARRAYTYPEMISMATCHEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_DIVIDEBYZEROEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_MEMBERACCESSEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_MISSINGMEMBEREXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_MISSINGFIELDEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_MISSINGMETHODEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_RANKEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_STACKOVERFLOWEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_TYPELOADEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_IO_IOEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_IO_DIRECTORYNOTFOUNDEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_IO_FILENOTFOUNDEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_RUNTIME_REMOTING_REMOTINGEXCEPTION,
	IDPRIME_EX_TYPE_SYSTEM_SECURITY_CRYPTOGRAPHY_CRYPTOGRAPHICEXCEPTION
} idprimenet_type_t;

typedef struct {
	idprimenet_type_t type;
	char *type_str;
	unsigned char hivecode[4];
} idprimenet_type_hivecode_t;

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
	{IDPRIME_TYPE_NONE,                     NULL,                       {0,    0,  }}
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
	idprimenet_type_t exception; /* IDPRIME_TYPE_NONE if no exception */
	char *exception_msg;
	const idprimenet_namespace_hivecode_t *namespace;
	idprimenet_type_t data_type;
	unsigned char *data;
	size_t data_len;
} dotnet_op_response_t;

static dotnet_op_response_t *dotnet_op_response_new() {
	dotnet_op_response_t *res = malloc(sizeof(dotnet_op_response_t));

	res->exception = IDPRIME_TYPE_NONE;
	res->exception_msg = NULL,
	res->data_type = IDPRIME_TYPE_NONE;
	res->data = NULL;
	res->data_len = 0;

	return res;
}

// TODO: Catch errors freeing
static void dotnet_op_response_destroy(dotnet_op_response_t *res) {
	if (res) {
		if (res->exception_msg) free(res->exception_msg);
		if (res->data)          free(res->data);
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

static const idprimenet_namespace_hivecode_t *hivecode_to_namespace(unsigned char hivecode[4]) {
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

static const idprimenet_type_hivecode_t * hivecode_to_type(unsigned char hivecode[2]) {
	for (unsigned int i = 0; idprimenet_type_hivecodes[i].type != IDPRIME_TYPE_NONE; i++) {
		if (idprimenet_type_hivecodes[i].hivecode[0] == hivecode[0]
		 && idprimenet_type_hivecodes[i].hivecode[1] == hivecode[1]) {
			return &idprimenet_type_hivecodes[i];
		}
	}
	return NULL;
}

static const idprimenet_type_hivecode_t * hivecode_to_exception_type(unsigned char hivecode[2]) {
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

static size_t idprimenet_apdu_strlen(const unsigned char *data) {
	return (data[0] << 8) | data[1];
}

static int idprimenet_apdu_to_string(const unsigned char *data, char *dest, size_t n) {
	memcpy(dest, data + 2, n);
	return 0;
}

static sc_apdu_t *dotnet_op_to_apdu(struct sc_card *card, const dotnet_op_t *op) {
	unsigned int service_len;
	unsigned char namespace[4], type[2], method[2];
	unsigned int apdu_prefix_len = 1 /* 0xD8 */ + 2 /* port */ + 1 /* 0x6F */ + 4 /* NS */ + 2 /* type */ + 2 /* method */ + 2 /* service length */;
	unsigned int apdu_data_len;
	unsigned char *apdu_data_ptr;
	sc_apdu_t *apdu;
	int cla;

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

	apdu_data_len = apdu_prefix_len + service_len;
	apdu_data_ptr = malloc(apdu_data_len);

	if (!apdu_data_ptr) {
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

	printf("APDU generated for: %s:0x%02x%02x [%s] (%s) %s\n", op->service, op->port[0], op->port[1], op->namespace, op->type, op->method);

	return apdu;
}

static int idprimenet_op_call(
		struct sc_card *card,
		unsigned char port_msb,
		unsigned char port_lsb,
		char *namespace,
		char *type,
		char *method,
		char *service,
		dotnet_op_response_t *response
	) {
	int res;
	dotnet_op_t op;
	sc_apdu_t *apdu;
	unsigned char *resp;
	size_t resplen = 255; //FIXME: Be more flexible
	unsigned int resp_header_size = 6; // 4 bytes of namespace hivecode + 2 bytes of type hivecode
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

	apdu = dotnet_op_to_apdu(card, &op);
	if (!apdu) return 0;

	if (resp) {
		apdu->resp = resp;
		apdu->resplen = resplen;
		apdu->le = resplen;
	}

	res = sc_transmit_apdu(card, apdu);

	if (res != SC_SUCCESS) {
		free(apdu);
		LOG_TEST_RET(card->ctx, res, "APDU transmit failed"); // TODO: See if this does what we actually want */
	}

	if (apdu->resplen < resp_header_size) {
		printf("Response too short?!");
		goto error;
	}

	response->namespace = hivecode_to_namespace(resp);

	r_type = hivecode_to_exception_type(resp + 4);
	if (r_type) {
		response->exception = r_type->type;
		if (apdu->resplen > resp_header_size) {
			// There's a message to go with this exception
			response->exception_msg = malloc(apdu->resplen - (resp_header_size - 1));
			if (!response->exception_msg) goto error;
			memcpy(response->exception_msg, apdu->resp + resp_header_size, apdu->resplen - resp_header_size);
			response->exception_msg[apdu->resplen - resp_header_size] = '\0';
		}
	} else {
		r_type = hivecode_to_type(resp + 4); // TODO: Check for failed lookup
		response->data_type = r_type->type;
		if (apdu->resplen > resp_header_size) {
			response->data = malloc(apdu->resplen - resp_header_size);
			if (!response->data) goto error;
			response->data_len = apdu->resplen - resp_header_size;
			memcpy(response->data, apdu->resp + resp_header_size, response->data_len);
		}
	}

	free(apdu);
	return 1;
error:
	free(apdu);
	return 0;
}

static int idprimenet_op_mscm_getchallenge(struct sc_card *card) {
	dotnet_op_response_t *response = dotnet_op_response_new();

	return idprimenet_op_call(
		card,
		0, 0x05,
		"CardModuleService",
		"CardModuleService",
		"System.Byte[] GetChallenge()",
		"MSCM",
		response
	);
	dotnet_op_response_destroy(response);
}

static int idprimenet_op_contentmanager_getserialnumber(struct sc_card *card) {
	dotnet_op_response_t *response = dotnet_op_response_new();

	return idprimenet_op_call(
		card,
		0, 0x01, /* port */
		"SmartCard", /* namespace */
		"SmartCard.ContentManager", /* type */
		"System.Byte[] get_SerialNumber()", /* method */
		"ContentManager", /* service name */
		response
	);
	dotnet_op_response_destroy(response);
}

static int idprimenet_op_mscm_getserialnumber(struct sc_card *card) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	res = idprimenet_op_call(
		card,
		0, 0x05, /* port */
		"CardModuleService",
		"CardModuleService",
		"System.Byte[] get_SerialNumber()", /* method */
		"MSCM", /* service name */
		response
	);

	if (!res) return 0;

	if (response->exception != IDPRIME_TYPE_NONE) {
		printf("Response raised an exception: %d: %s\n", response->exception, response->exception_msg ? response->exception_msg : "(no message)");
		return 0;
	}

	if (response->namespace->namespace_id != IDPRIME_NS_SYSTEM) {
		printf("Response had unexpected namespace: %s\n", response->namespace->namespace);
		return 0;
	}

	if (response->data_type != IDPRIME_TYPE_SYSTEM_BYTE_ARRAY) {
		printf("Response had unexpected type\n");
		return 0;
	}

	printf("Was a byte array\n");
	// Looks like data is len1, len2, len3, len4, [bytes]
	dotnet_op_response_destroy(response);
	return 1;
}

static char* idprimenet_op_mscm_getversion(struct sc_card *card) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;
	char *version_str = NULL;
	size_t version_str_len;

	res = idprimenet_op_call(
		card,
		0, 0x05, /* port */
		"CardModuleService",
		"CardModuleService",
		"System.String get_Version()", /* method */
		"MSCM", /* service name */
		response
	);
	if (!res) return NULL;

	if (response->exception != IDPRIME_TYPE_NONE) {
		printf("Response raised an exception: %d: %s\n", response->exception, response->exception_msg ? response->exception_msg : "(no message)");
		return NULL;
	}

	if (response->namespace->namespace_id != IDPRIME_NS_SYSTEM) {
		printf("Response had unexpected namespace: %s\n", response->namespace->namespace);
		return NULL;
	}

	if (response->data_type != IDPRIME_TYPE_SYSTEM_STRING) {
		printf("Response had unexpected type");
		return NULL;
	}

	version_str_len = idprimenet_apdu_strlen(response->data);
	/* TODO: check for errors */
	version_str = malloc(version_str_len);
	if (!version_str) return NULL;

	idprimenet_apdu_to_string(response->data, version_str, version_str_len);

	dotnet_op_response_destroy(response);
	return version_str;
}

static int idprimenet_op_mscm_queryfreespace(struct sc_card *card) {
	dotnet_op_response_t *response = dotnet_op_response_new();
	int res;

	res = idprimenet_op_call(
		card,
		0, 0x05, /* port */
		"CardModuleService",
		"CardModuleService",
		"System.Int[] QueryFreeSpace()", /* method */
		"MSCM", /* service name */
		response
	);
	if (!res) goto error;

	printf("Got response\n");
	if (response->exception != IDPRIME_TYPE_NONE) {
	printf("Got exception\n");
		printf("Response raised an exception: %d: %s\n", response->exception, response->exception_msg ? response->exception_msg : "(no message)");
		goto error;
	}

	printf("Checking namespace\n");
	if (response->namespace->namespace_id != IDPRIME_NS_SYSTEM) {
		printf("Response had unexpected namespace: %s\n", response->namespace->namespace);
		goto error;
	}

	printf("Checking data type\n");
	if (response->data_type != IDPRIME_TYPE_SYSTEM_INT16_ARRAY) {
		printf("Response had unexpected type");
		goto error;
	}

	printf("Was an int16 array\n");
	
	return 0;

error:
	dotnet_op_response_destroy(response);
	return 1;
}

static int idprimenet_match_card(struct sc_card *card)
{
	int i;
	char *version;

	i = _sc_match_atr(card, idprimenet_atrs, &card->type);
	if (i < 0) return 0;

	version = idprimenet_op_mscm_getversion(card);
	if (!version) return 0;
	printf("Card version %s\n", version);
	idprimenet_op_mscm_getserialnumber(card);
	idprimenet_op_mscm_queryfreespace(card);
	idprimenet_op_mscm_getchallenge(card);
	//idprimenet_op_contentmanager_getserialnumber(card);

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
