/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_U_RNTI_Short_H_
#define	_U_RNTI_Short_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SRNC-Identity.h"
#include "S-RNTI-2.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* U-RNTI-Short */
typedef struct U_RNTI_Short {
	SRNC_Identity_t	 srnc_Identity;
	S_RNTI_2_t	 s_RNTI_2;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} U_RNTI_Short_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_U_RNTI_Short;

#ifdef __cplusplus
}
#endif

#endif	/* _U_RNTI_Short_H_ */
#include <asn_internal.h>
