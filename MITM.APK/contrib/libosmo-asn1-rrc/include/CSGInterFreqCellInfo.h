/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_CSGInterFreqCellInfo_H_
#define	_CSGInterFreqCellInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "FrequencyInfo.h"
#include "CSGCellInfoList.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CSGInterFreqCellInfo */
typedef struct CSGInterFreqCellInfo {
	FrequencyInfo_t	 frequencyInfo;
	CSGCellInfoList_t	 cSGInterFreqCellInfoListperFreq;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CSGInterFreqCellInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CSGInterFreqCellInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _CSGInterFreqCellInfo_H_ */
#include <asn_internal.h>
