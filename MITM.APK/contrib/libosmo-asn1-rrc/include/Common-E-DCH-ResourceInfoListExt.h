/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_Common_E_DCH_ResourceInfoListExt_H_
#define	_Common_E_DCH_ResourceInfoListExt_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TwoMsHarqConfiguration.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Common-E-DCH-ResourceInfoListExt */
typedef struct Common_E_DCH_ResourceInfoListExt {
	TwoMsHarqConfiguration_t	 twoMsHarqConfiguration;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Common_E_DCH_ResourceInfoListExt_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Common_E_DCH_ResourceInfoListExt;

#ifdef __cplusplus
}
#endif

#endif	/* _Common_E_DCH_ResourceInfoListExt_H_ */
#include <asn_internal.h>
