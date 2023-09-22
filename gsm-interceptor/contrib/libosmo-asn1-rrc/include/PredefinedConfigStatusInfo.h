/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PredefinedConfigStatusInfo_H_
#define	_PredefinedConfigStatusInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include "PredefinedConfigValueTag.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PredefinedConfigStatusInfo_PR {
	PredefinedConfigStatusInfo_PR_NOTHING,	/* No components present */
	PredefinedConfigStatusInfo_PR_storedWithValueTagSameAsPrevius,
	PredefinedConfigStatusInfo_PR_other
} PredefinedConfigStatusInfo_PR;
typedef enum PredefinedConfigStatusInfo__other_PR {
	PredefinedConfigStatusInfo__other_PR_NOTHING,	/* No components present */
	PredefinedConfigStatusInfo__other_PR_notStored,
	PredefinedConfigStatusInfo__other_PR_storedWithDifferentValueTag
} PredefinedConfigStatusInfo__other_PR;

/* PredefinedConfigStatusInfo */
typedef struct PredefinedConfigStatusInfo {
	PredefinedConfigStatusInfo_PR present;
	union PredefinedConfigStatusInfo_u {
		NULL_t	 storedWithValueTagSameAsPrevius;
		struct PredefinedConfigStatusInfo__other {
			PredefinedConfigStatusInfo__other_PR present;
			union PredefinedConfigStatusInfo__other_u {
				NULL_t	 notStored;
				PredefinedConfigValueTag_t	 storedWithDifferentValueTag;
			} choice;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} other;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PredefinedConfigStatusInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PredefinedConfigStatusInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _PredefinedConfigStatusInfo_H_ */
#include <asn_internal.h>
