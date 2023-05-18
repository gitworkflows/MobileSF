/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DL_CommonInformation_r11_H_
#define	_DL_CommonInformation_r11_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include "DL-DPCH-InfoCommon-r6.h"
#include "DL-FDPCH-InfoCommon-r6.h"
#include <constr_CHOICE.h>
#include "DefaultDPCH-OffsetValueFDD.h"
#include "TX-DiversityMode.h"
#include <constr_SEQUENCE.h>
#include "DefaultDPCH-OffsetValueTDD.h"
#include <NULL.h>
#include <BOOLEAN.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DL_CommonInformation_r11__dl_dpchInfoCommon_PR {
	DL_CommonInformation_r11__dl_dpchInfoCommon_PR_NOTHING,	/* No components present */
	DL_CommonInformation_r11__dl_dpchInfoCommon_PR_dl_DPCH_InfoCommon,
	DL_CommonInformation_r11__dl_dpchInfoCommon_PR_dl_FDPCH_InfoCommon
} DL_CommonInformation_r11__dl_dpchInfoCommon_PR;
typedef enum DL_CommonInformation_r11__modeSpecificInfo_PR {
	DL_CommonInformation_r11__modeSpecificInfo_PR_NOTHING,	/* No components present */
	DL_CommonInformation_r11__modeSpecificInfo_PR_fdd,
	DL_CommonInformation_r11__modeSpecificInfo_PR_tdd
} DL_CommonInformation_r11__modeSpecificInfo_PR;
typedef enum DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption_PR {
	DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption_PR_NOTHING,	/* No components present */
	DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption_PR_tdd384,
	DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption_PR_tdd768,
	DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption_PR_tdd128
} DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption_PR;
typedef enum DL_CommonInformation_r11__mac_hsResetIndicator {
	DL_CommonInformation_r11__mac_hsResetIndicator_true	= 0
} e_DL_CommonInformation_r11__mac_hsResetIndicator;
typedef enum DL_CommonInformation_r11__postVerificationPeriod {
	DL_CommonInformation_r11__postVerificationPeriod_true	= 0
} e_DL_CommonInformation_r11__postVerificationPeriod;
typedef enum DL_CommonInformation_r11__mac_hsResetIndicator_assisting {
	DL_CommonInformation_r11__mac_hsResetIndicator_assisting_true	= 0
} e_DL_CommonInformation_r11__mac_hsResetIndicator_assisting;

/* Forward declarations */
struct DPCH_CompressedModeInfo_r10;

/* DL-CommonInformation-r11 */
typedef struct DL_CommonInformation_r11 {
	struct DL_CommonInformation_r11__dl_dpchInfoCommon {
		DL_CommonInformation_r11__dl_dpchInfoCommon_PR present;
		union DL_CommonInformation_r11__dl_dpchInfoCommon_u {
			DL_DPCH_InfoCommon_r6_t	 dl_DPCH_InfoCommon;
			DL_FDPCH_InfoCommon_r6_t	 dl_FDPCH_InfoCommon;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *dl_dpchInfoCommon;
	struct DL_CommonInformation_r11__modeSpecificInfo {
		DL_CommonInformation_r11__modeSpecificInfo_PR present;
		union DL_CommonInformation_r11__modeSpecificInfo_u {
			struct DL_CommonInformation_r11__modeSpecificInfo__fdd {
				DefaultDPCH_OffsetValueFDD_t	*defaultDPCH_OffsetValue	/* OPTIONAL */;
				struct DPCH_CompressedModeInfo_r10	*dpch_CompressedModeInfo	/* OPTIONAL */;
				TX_DiversityMode_t	*tx_DiversityMode	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct DL_CommonInformation_r11__modeSpecificInfo__tdd {
				struct DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption {
					DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption_PR present;
					union DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption_u {
						NULL_t	 tdd384;
						NULL_t	 tdd768;
						struct DL_CommonInformation_r11__modeSpecificInfo__tdd__tddOption__tdd128 {
							BOOLEAN_t	 tstd_Indicator;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} tdd128;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} tddOption;
				DefaultDPCH_OffsetValueTDD_t	*defaultDPCH_OffsetValue	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	long	*mac_hsResetIndicator	/* OPTIONAL */;
	long	*postVerificationPeriod	/* OPTIONAL */;
	long	*mac_hsResetIndicator_assisting	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_CommonInformation_r11_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_mac_hsResetIndicator_17;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_postVerificationPeriod_19;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_mac_hsResetIndicator_assisting_21;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_DL_CommonInformation_r11;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "DPCH-CompressedModeInfo-r10.h"

#endif	/* _DL_CommonInformation_r11_H_ */
#include <asn_internal.h>
