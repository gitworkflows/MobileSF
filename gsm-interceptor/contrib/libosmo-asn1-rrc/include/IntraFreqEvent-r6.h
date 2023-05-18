/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_IntraFreqEvent_r6_H_
#define	_IntraFreqEvent_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Event1a-r4.h"
#include "Event1b-r4.h"
#include "Event1c.h"
#include "Event1d.h"
#include "Event1e-r6.h"
#include "Event1f-r6.h"
#include <NULL.h>
#include "ThresholdUsedFrequency-r6.h"
#include "Event1j-r6.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum IntraFreqEvent_r6_PR {
	IntraFreqEvent_r6_PR_NOTHING,	/* No components present */
	IntraFreqEvent_r6_PR_e1a,
	IntraFreqEvent_r6_PR_e1b,
	IntraFreqEvent_r6_PR_e1c,
	IntraFreqEvent_r6_PR_e1d,
	IntraFreqEvent_r6_PR_e1e,
	IntraFreqEvent_r6_PR_e1f,
	IntraFreqEvent_r6_PR_e1g,
	IntraFreqEvent_r6_PR_e1h,
	IntraFreqEvent_r6_PR_e1i,
	IntraFreqEvent_r6_PR_e1j
} IntraFreqEvent_r6_PR;

/* IntraFreqEvent-r6 */
typedef struct IntraFreqEvent_r6 {
	IntraFreqEvent_r6_PR present;
	union IntraFreqEvent_r6_u {
		Event1a_r4_t	 e1a;
		Event1b_r4_t	 e1b;
		Event1c_t	 e1c;
		Event1d_t	 e1d;
		Event1e_r6_t	 e1e;
		Event1f_r6_t	 e1f;
		NULL_t	 e1g;
		ThresholdUsedFrequency_r6_t	 e1h;
		ThresholdUsedFrequency_r6_t	 e1i;
		Event1j_r6_t	 e1j;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFreqEvent_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFreqEvent_r6;

#ifdef __cplusplus
}
#endif

#endif	/* _IntraFreqEvent_r6_H_ */
#include <asn_internal.h>
