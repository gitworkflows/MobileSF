/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DynamicTFInformationCCCH_H_
#define	_DynamicTFInformationCCCH_H_


#include <asn_application.h>

/* Including external dependencies */
#include "OctetModeRLC-SizeInfoType2.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DynamicTFInformationCCCH */
typedef struct DynamicTFInformationCCCH {
	OctetModeRLC_SizeInfoType2_t	 octetModeRLC_SizeInfoType2;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DynamicTFInformationCCCH_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DynamicTFInformationCCCH;

#ifdef __cplusplus
}
#endif

#endif	/* _DynamicTFInformationCCCH_H_ */
#include <asn_internal.h>
