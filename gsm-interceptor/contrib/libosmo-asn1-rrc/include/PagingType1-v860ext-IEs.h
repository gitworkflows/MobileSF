/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PagingType1_v860ext_IEs_H_
#define	_PagingType1_v860ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ETWS_Information;

/* PagingType1-v860ext-IEs */
typedef struct PagingType1_v860ext_IEs {
	struct ETWS_Information	*etws_Information	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PagingType1_v860ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PagingType1_v860ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ETWS-Information.h"

#endif	/* _PagingType1_v860ext_IEs_H_ */
#include <asn_internal.h>
