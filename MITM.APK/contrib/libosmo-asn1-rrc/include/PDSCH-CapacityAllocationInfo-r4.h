/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PDSCH_CapacityAllocationInfo_r4_H_
#define	_PDSCH_CapacityAllocationInfo_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AllocationPeriodInfo.h"
#include "TFCS-IdentityPlain.h"
#include "PDSCH-Identity.h"
#include <constr_SEQUENCE.h>
#include "PDSCH-Info-r4.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PDSCH_CapacityAllocationInfo_r4__configuration_PR {
	PDSCH_CapacityAllocationInfo_r4__configuration_PR_NOTHING,	/* No components present */
	PDSCH_CapacityAllocationInfo_r4__configuration_PR_old_Configuration,
	PDSCH_CapacityAllocationInfo_r4__configuration_PR_new_Configuration
} PDSCH_CapacityAllocationInfo_r4__configuration_PR;

/* Forward declarations */
struct PDSCH_PowerControlInfo;

/* PDSCH-CapacityAllocationInfo-r4 */
typedef struct PDSCH_CapacityAllocationInfo_r4 {
	AllocationPeriodInfo_t	 pdsch_AllocationPeriodInfo;
	struct PDSCH_CapacityAllocationInfo_r4__configuration {
		PDSCH_CapacityAllocationInfo_r4__configuration_PR present;
		union PDSCH_CapacityAllocationInfo_r4__configuration_u {
			struct PDSCH_CapacityAllocationInfo_r4__configuration__old_Configuration {
				TFCS_IdentityPlain_t	*tfcs_ID	/* DEFAULT 1 */;
				PDSCH_Identity_t	 pdsch_Identity;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} old_Configuration;
			struct PDSCH_CapacityAllocationInfo_r4__configuration__new_Configuration {
				PDSCH_Info_r4_t	 pdsch_Info;
				PDSCH_Identity_t	*pdsch_Identity	/* OPTIONAL */;
				struct PDSCH_PowerControlInfo	*pdsch_PowerControlInfo	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} new_Configuration;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} configuration;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDSCH_CapacityAllocationInfo_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PDSCH_CapacityAllocationInfo_r4;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PDSCH-PowerControlInfo.h"

#endif	/* _PDSCH_CapacityAllocationInfo_r4_H_ */
#include <asn_internal.h>
