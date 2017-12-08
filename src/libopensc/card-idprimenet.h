/*
 * card-idprimenet.h: Support for IDPrime.NET smart cards.
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

#ifndef CARD_IDPRIMENET_H_
#define CARD_IDPRIMENET_H_

#include "opensc.h" 

#ifdef __cplusplus
extern "C" {
#endif

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
	u8 hivecode[4];
} idprimenet_type_hivecode_t;

typedef struct {
	const idprimenet_type_hivecode_t *type;
	char *message;
} dotnet_exception_t;

dotnet_exception_t *dotnet_exception_new();
void dotnet_exception_destroy(dotnet_exception_t *exception);
dotnet_exception_t *dotnet_exception_clone(dotnet_exception_t *src);

typedef struct idprimenet_string_array {
	char *value;
	struct idprimenet_string_array *next;
} idprimenet_string_array_t;

idprimenet_string_array_t *idprimenet_string_array_new();
void idprimenet_string_array_destroy(idprimenet_string_array_t *list);

typedef struct {
	unsigned int minimumBitLen;
	unsigned int defaultBitLen;
	unsigned int maximumBitLen;
	unsigned int incrementalBitLen;
} idprimenet_key_sizes_t;

/* System.Byte[] SmartCard.ContentManager.get_SerialNumber() */
int idprimenet_op_contentmanager_getserialnumber(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *serialnumber,
		size_t *serialnumber_len);

/* System.Void CardModuleService.ExternalAuthenticate(System.Byte[]) */
int idprimenet_op_mscm_externalauthenticate(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *authresp,
		size_t authresp_len);

/* System.Void CardModuleService.ForceGarbageCollector() */
int idprimenet_op_mscm_forcegarbagecollector(
		struct sc_card *card,
		dotnet_exception_t **exception);

/* System.String CardModuleService.get_Version() */
int idprimenet_op_mscm_getversion(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *version_str,
		size_t *version_str_len);

/* System.Byte[] CardModuleService.GetChallenge() */
int idprimenet_op_mscm_getchallenge(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *challenge,
		size_t *challenge_len);

/* System.String[] CardModuleService.GetFiles(System.String) */
int idprimenet_op_mscm_getfiles(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *path,
		idprimenet_string_array_t **dest);

/* System.Byte[] CardModuleService.get_SerialNumber() */
int idprimenet_op_mscm_getserialnumber(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *serialnumber,
		size_t *serialnumber_len);

/* System.Boolean CardModuleService.IsAuthenticated(System.Byte) */
int idprimenet_op_mscm_isauthenticated (
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 role,
		u8 *answer);

/* System.Byte CardModuleService.MaxPinRetryCounter() */
int idprimenet_op_mscm_maxpinretrycounter(
		struct sc_card *card,
		dotnet_exception_t **exception,
		u8 *maxpinretrycounter);

/* System.Int32[] CardModuleService.QueryFreeSpace() */
int idprimenet_op_mscm_queryfreespace(
		struct sc_card *card,
		dotnet_exception_t **exception,
		int *freespace,
		size_t *freespace_len);

/* System.Int32[] CardModuleService.QueryKeySizes() */
int idprimenet_op_mscm_querykeysizes(
		struct sc_card *card,
		dotnet_exception_t **exception,
		idprimenet_key_sizes_t *key_sizes);

/* System.Byte[] CardModuleService.ReadFile(System.String,System.Int32) */
int idprimenet_op_mscm_readfile(
		struct sc_card *card,
		dotnet_exception_t **exception,
		char *path,
		u8 *data,
		size_t *data_len);

#ifdef __cplusplus
}
#endif

#endif /* CARD_IDPRIMENET_H_ */
