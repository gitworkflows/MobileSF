/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_E_RGCH_CombinationInfoList_H_
#define	_E_RGCH_CombinationInfoList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct E_RGCH_Combination_Info;

/* E-RGCH-CombinationInfoList */
typedef struct E_RGCH_CombinationInfoList {
	A_SEQUENCE_OF(struct E_RGCH_Combination_Info) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_RGCH_CombinationInfoList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_RGCH_CombinationInfoList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "E-RGCH-Combination-Info.h"

#endif	/* _E_RGCH_CombinationInfoList_H_ */
#include <asn_internal.h>
