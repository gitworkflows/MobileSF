/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InterFreqCell_LCR_r4_H_
#define	_InterFreqCell_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "FrequencyInfo.h"
#include "CellMeasurementEventResults-LCR-r4.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* InterFreqCell-LCR-r4 */
typedef struct InterFreqCell_LCR_r4 {
	FrequencyInfo_t	 frequencyInfo;
	CellMeasurementEventResults_LCR_r4_t	 nonFreqRelatedEventResults;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterFreqCell_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterFreqCell_LCR_r4;

#ifdef __cplusplus
}
#endif

#endif	/* _InterFreqCell_LCR_r4_H_ */
#include <asn_internal.h>
