/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SysInfoType15_3bis_H_
#define	_SysInfoType15_3bis_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SysInfoType15-3bis-v860ext-IEs.h"
#include "SysInfoType15-3bis-va40ext-IEs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UE_Positioning_GANSS_Almanac;
struct UE_Positioning_GANSS_TimeModels;
struct UE_Positioning_GANSS_UTCModel;

/* SysInfoType15-3bis */
typedef struct SysInfoType15_3bis {
	struct UE_Positioning_GANSS_Almanac	*ue_positioning_GANSS_Almanac	/* OPTIONAL */;
	struct UE_Positioning_GANSS_TimeModels	*ue_positioning_GANSS_TimeModels	/* OPTIONAL */;
	struct UE_Positioning_GANSS_UTCModel	*ue_positioning_GANSS_UTC_Model	/* OPTIONAL */;
	struct SysInfoType15_3bis__v860NonCriticalExtensions {
		SysInfoType15_3bis_v860ext_IEs_t	 sysInfoType15_3bis_v860ext;
		struct SysInfoType15_3bis__v860NonCriticalExtensions__va40NonCriticalExtensions {
			SysInfoType15_3bis_va40ext_IEs_t	 sysInfoType15_3bis_va40ext;
			struct SysInfoType15_3bis__v860NonCriticalExtensions__va40NonCriticalExtensions__nonCriticalExtensions {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *nonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *va40NonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *v860NonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoType15_3bis_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoType15_3bis;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "UE-Positioning-GANSS-Almanac.h"
#include "UE-Positioning-GANSS-TimeModels.h"
#include "UE-Positioning-GANSS-UTCModel.h"

#endif	/* _SysInfoType15_3bis_H_ */
#include <asn_internal.h>
