/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RestrictedTrCH_InfoList_H_
#define	_RestrictedTrCH_InfoList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RestrictedTrCH;

/* RestrictedTrCH-InfoList */
typedef struct RestrictedTrCH_InfoList {
	A_SEQUENCE_OF(struct RestrictedTrCH) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RestrictedTrCH_InfoList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RestrictedTrCH_InfoList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RestrictedTrCH.h"

#endif	/* _RestrictedTrCH_InfoList_H_ */
#include <asn_internal.h>
