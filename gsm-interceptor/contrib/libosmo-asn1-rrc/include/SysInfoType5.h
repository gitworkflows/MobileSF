/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SysInfoType5_H_
#define	_SysInfoType5_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include "PICH-PowerOffset.h"
#include "PRACH-SystemInformationList.h"
#include "SCCPCH-SystemInformationList.h"
#include "AICH-PowerOffset.h"
#include <constr_SEQUENCE.h>
#include "OpenLoopPowerControl-TDD.h"
#include <constr_CHOICE.h>
#include "SysInfoType5-v690ext-IEs.h"
#include "SysInfoType5-v770ext-IEs.h"
#include "SysInfoType5-v860ext-IEs.h"
#include "SysInfoType5-v890ext-IEs.h"
#include "SysInfoType5-v8b0ext-IEs.h"
#include "SysInfoType5-v8d0ext-IEs.h"
#include "SysInfoType5-va40ext-IEs.h"
#include "SysInfoType5-va80ext-IEs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SysInfoType5__modeSpecificInfo_PR {
	SysInfoType5__modeSpecificInfo_PR_NOTHING,	/* No components present */
	SysInfoType5__modeSpecificInfo_PR_fdd,
	SysInfoType5__modeSpecificInfo_PR_tdd
} SysInfoType5__modeSpecificInfo_PR;

/* Forward declarations */
struct PrimaryCCPCH_Info;
struct CBS_DRX_Level1Information;
struct PUSCH_SysInfoList_SFN;
struct PDSCH_SysInfoList_SFN;
struct SysInfoType5_v4b0ext_IEs;
struct SysInfoType5_v590ext_IEs;
struct SysInfoType5_v650ext_IEs;
struct SysInfoType5_v680ext_IEs;
struct SysInfoType5_NonCriticalExtensions_vb50_IEs;

/* SysInfoType5 */
typedef struct SysInfoType5 {
	BOOLEAN_t	 sib6indicator;
	PICH_PowerOffset_t	 pich_PowerOffset;
	struct SysInfoType5__modeSpecificInfo {
		SysInfoType5__modeSpecificInfo_PR present;
		union SysInfoType5__modeSpecificInfo_u {
			struct SysInfoType5__modeSpecificInfo__fdd {
				AICH_PowerOffset_t	 aich_PowerOffset;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct SysInfoType5__modeSpecificInfo__tdd {
				struct PUSCH_SysInfoList_SFN	*pusch_SysInfoList_SFN	/* OPTIONAL */;
				struct PDSCH_SysInfoList_SFN	*pdsch_SysInfoList_SFN	/* OPTIONAL */;
				OpenLoopPowerControl_TDD_t	 openLoopPowerControl_TDD;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	struct PrimaryCCPCH_Info	*primaryCCPCH_Info	/* OPTIONAL */;
	PRACH_SystemInformationList_t	 prach_SystemInformationList;
	SCCPCH_SystemInformationList_t	 sCCPCH_SystemInformationList;
	struct CBS_DRX_Level1Information	*cbs_DRX_Level1Information	/* OPTIONAL */;
	struct SysInfoType5__v4b0NonCriticalExtensions {
		struct SysInfoType5_v4b0ext_IEs	*sysInfoType5_v4b0ext	/* OPTIONAL */;
		struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions {
			struct SysInfoType5_v590ext_IEs	*sysInfoType5_v590ext	/* OPTIONAL */;
			struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions {
				struct SysInfoType5_v650ext_IEs	*sysInfoType5_v650ext	/* OPTIONAL */;
				struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions {
					struct SysInfoType5_v680ext_IEs	*sysInfoType5_v680ext	/* OPTIONAL */;
					struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions__v690NonCriticalExtensions {
						SysInfoType5_v690ext_IEs_t	 sysInfoType5_v690ext;
						struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions__v690NonCriticalExtensions__v770NonCriticalExtensions {
							SysInfoType5_v770ext_IEs_t	 sysInfoType5_v770ext;
							struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions__v690NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions {
								SysInfoType5_v860ext_IEs_t	 sysInfoType5_v860ext;
								struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions__v690NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions__v890NonCriticalExtensions {
									SysInfoType5_v890ext_IEs_t	 sysInfoType5_v890ext;
									struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions__v690NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions__v890NonCriticalExtensions__v8b0NonCriticalExtensions {
										SysInfoType5_v8b0ext_IEs_t	 sysInfoType5_v8b0ext;
										struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions__v690NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions__v890NonCriticalExtensions__v8b0NonCriticalExtensions__v8d0NonCriticalExtensions {
											SysInfoType5_v8d0ext_IEs_t	 sysInfoType5_v8d0ext;
											struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions__v690NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions__v890NonCriticalExtensions__v8b0NonCriticalExtensions__v8d0NonCriticalExtensions__va40NonCriticalExtensions {
												SysInfoType5_va40ext_IEs_t	 sysInfoType5_va40ext;
												struct SysInfoType5__v4b0NonCriticalExtensions__v590NonCriticalExtensions__v650NonCriticalExtensions__v680NonCriticalExtensions__v690NonCriticalExtensions__v770NonCriticalExtensions__v860NonCriticalExtensions__v890NonCriticalExtensions__v8b0NonCriticalExtensions__v8d0NonCriticalExtensions__va40NonCriticalExtensions__va80NonCriticalExtensions {
													SysInfoType5_va80ext_IEs_t	 sysInfoType5_va80ext;
													struct SysInfoType5_NonCriticalExtensions_vb50_IEs	*vb50NonCriticalExtensions	/* OPTIONAL */;
													
													/* Context for parsing across buffer boundaries */
													asn_struct_ctx_t _asn_ctx;
												} *va80NonCriticalExtensions;
												
												/* Context for parsing across buffer boundaries */
												asn_struct_ctx_t _asn_ctx;
											} *va40NonCriticalExtensions;
											
											/* Context for parsing across buffer boundaries */
											asn_struct_ctx_t _asn_ctx;
										} *v8d0NonCriticalExtensions;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} *v8b0NonCriticalExtensions;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *v890NonCriticalExtensions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *v860NonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v770NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *v690NonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *v680NonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *v650NonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *v590NonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *v4b0NonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SysInfoType5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SysInfoType5;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PrimaryCCPCH-Info.h"
#include "CBS-DRX-Level1Information.h"
#include "PUSCH-SysInfoList-SFN.h"
#include "PDSCH-SysInfoList-SFN.h"
#include "SysInfoType5-v4b0ext-IEs.h"
#include "SysInfoType5-v590ext-IEs.h"
#include "SysInfoType5-v650ext-IEs.h"
#include "SysInfoType5-v680ext-IEs.h"
#include "SysInfoType5-NonCriticalExtensions-vb50-IEs.h"

#endif	/* _SysInfoType5_H_ */
#include <asn_internal.h>
