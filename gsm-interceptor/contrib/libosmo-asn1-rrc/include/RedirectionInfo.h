/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RedirectionInfo_H_
#define	_RedirectionInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "FrequencyInfo.h"
#include "InterRATInfo.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RedirectionInfo_PR {
	RedirectionInfo_PR_NOTHING,	/* No components present */
	RedirectionInfo_PR_frequencyInfo,
	RedirectionInfo_PR_interRATInfo
} RedirectionInfo_PR;

/* RedirectionInfo */
typedef struct RedirectionInfo {
	RedirectionInfo_PR present;
	union RedirectionInfo_u {
		FrequencyInfo_t	 frequencyInfo;
		InterRATInfo_t	 interRATInfo;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RedirectionInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RedirectionInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _RedirectionInfo_H_ */
#include <asn_internal.h>
