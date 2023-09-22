/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_URA_IdentityList_H_
#define	_URA_IdentityList_H_


#include <asn_application.h>

/* Including external dependencies */
#include "URA-Identity.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* URA-IdentityList */
typedef struct URA_IdentityList {
	A_SEQUENCE_OF(URA_Identity_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} URA_IdentityList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_URA_IdentityList;

#ifdef __cplusplus
}
#endif

#endif	/* _URA_IdentityList_H_ */
#include <asn_internal.h>
