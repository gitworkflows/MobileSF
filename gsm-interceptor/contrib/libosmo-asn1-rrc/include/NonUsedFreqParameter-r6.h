/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_NonUsedFreqParameter_r6_H_
#define	_NonUsedFreqParameter_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Threshold-r6.h"
#include "W.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NonUsedFreqParameter-r6 */
typedef struct NonUsedFreqParameter_r6 {
	Threshold_r6_t	 nonUsedFreqThreshold;
	W_t	 nonUsedFreqW;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NonUsedFreqParameter_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NonUsedFreqParameter_r6;

#ifdef __cplusplus
}
#endif

#endif	/* _NonUsedFreqParameter_r6_H_ */
#include <asn_internal.h>
