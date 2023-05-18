/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_InternalMeasuredResults_v770ext_H_
#define	_UE_InternalMeasuredResults_v770ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_InternalMeasuredResults_v770ext__modeSpecificInfo_PR {
	UE_InternalMeasuredResults_v770ext__modeSpecificInfo_PR_NOTHING,	/* No components present */
	UE_InternalMeasuredResults_v770ext__modeSpecificInfo_PR_tdd384_768,
	UE_InternalMeasuredResults_v770ext__modeSpecificInfo_PR_tdd128
} UE_InternalMeasuredResults_v770ext__modeSpecificInfo_PR;

/* Forward declarations */
struct EXT_UL_TimingAdvance;
struct T_ADVinfo_ext;

/* UE-InternalMeasuredResults-v770ext */
typedef struct UE_InternalMeasuredResults_v770ext {
	struct UE_InternalMeasuredResults_v770ext__modeSpecificInfo {
		UE_InternalMeasuredResults_v770ext__modeSpecificInfo_PR present;
		union UE_InternalMeasuredResults_v770ext__modeSpecificInfo_u {
			struct UE_InternalMeasuredResults_v770ext__modeSpecificInfo__tdd384_768 {
				struct EXT_UL_TimingAdvance	*appliedTA	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd384_768;
			struct UE_InternalMeasuredResults_v770ext__modeSpecificInfo__tdd128 {
				struct T_ADVinfo_ext	*t_ADVinfo	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd128;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_InternalMeasuredResults_v770ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_InternalMeasuredResults_v770ext;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "EXT-UL-TimingAdvance.h"
#include "T-ADVinfo-ext.h"

#endif	/* _UE_InternalMeasuredResults_v770ext_H_ */
#include <asn_internal.h>
