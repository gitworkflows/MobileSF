/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RRCConnectionSetup_r11_IEs_H_
#define	_RRCConnectionSetup_r11_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ActivationTime.h"
#include "U-RNTI.h"
#include "C-RNTI.h"
#include "H-RNTI.h"
#include "E-RNTI.h"
#include "RRC-StateIndicator.h"
#include "UTRAN-DRX-CycleLengthCoefficient-r7.h"
#include <BOOLEAN.h>
#include "MaxAllowedUL-TX-Power.h"
#include "SRB-InformationSetupList2-r8.h"
#include <constr_SEQUENCE.h>
#include "PredefinedConfigIdentity.h"
#include "DefaultConfigMode.h"
#include "DefaultConfigIdentity-r6.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RRCConnectionSetup_r11_IEs__specificationMode_PR {
	RRCConnectionSetup_r11_IEs__specificationMode_PR_NOTHING,	/* No components present */
	RRCConnectionSetup_r11_IEs__specificationMode_PR_complete,
	RRCConnectionSetup_r11_IEs__specificationMode_PR_preconfiguration
} RRCConnectionSetup_r11_IEs__specificationMode_PR;
typedef enum RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode_PR {
	RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode_PR_NOTHING,	/* No components present */
	RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode_PR_predefinedConfigIdentity,
	RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode_PR_defaultConfig
} RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode_PR;

/* Forward declarations */
struct CapabilityUpdateRequirement_r8;
struct DefaultConfigForCellFACH;
struct FrequencyInfo;
struct Multi_frequencyInfo_LCR_r7;
struct DTX_DRX_TimingInfo_r7;
struct DTX_DRX_Info_r7;
struct HS_SCCH_LessInfo_r7;
struct UL_DPCH_Info_r11;
struct UL_EDCH_Information_r11;
struct DL_HSPDSCH_Information_r11;
struct DL_CommonInformation_r10;
struct DL_InformationPerRL_List_r8;
struct DL_SecondaryCellInfoFDD_r11;
struct AdditionalDLSecCellInfoListFDD_r11;
struct CommonERGCHInfoFDD;
struct SPS_Information_TDD128_r8;
struct MU_MIMO_Info_TDD128;
struct UL_CommonTransChInfo_r4;
struct UL_AddReconfTransChInfoList_r8;
struct DL_CommonTransChInfo_r4;
struct DL_AddReconfTransChInfoList_r11;

/* RRCConnectionSetup-r11-IEs */
typedef struct RRCConnectionSetup_r11_IEs {
	ActivationTime_t	*activationTime	/* OPTIONAL */;
	U_RNTI_t	 new_U_RNTI;
	C_RNTI_t	*new_c_RNTI	/* OPTIONAL */;
	H_RNTI_t	*new_H_RNTI	/* OPTIONAL */;
	E_RNTI_t	*newPrimary_E_RNTI	/* OPTIONAL */;
	E_RNTI_t	*newSecondary_E_RNTI	/* OPTIONAL */;
	RRC_StateIndicator_t	 rrc_StateIndicator;
	UTRAN_DRX_CycleLengthCoefficient_r7_t	 utran_DRX_CycleLengthCoeff;
	struct CapabilityUpdateRequirement_r8	*capabilityUpdateRequirement	/* OPTIONAL */;
	BOOLEAN_t	 supportForChangeOfUE_Capability;
	struct DefaultConfigForCellFACH	*defaultConfigForCellFACH	/* OPTIONAL */;
	struct RRCConnectionSetup_r11_IEs__specificationMode {
		RRCConnectionSetup_r11_IEs__specificationMode_PR present;
		union RRCConnectionSetup_r11_IEs__specificationMode_u {
			struct RRCConnectionSetup_r11_IEs__specificationMode__complete {
				SRB_InformationSetupList2_r8_t	 srb_InformationSetupList;
				struct UL_CommonTransChInfo_r4	*ul_CommonTransChInfo	/* OPTIONAL */;
				struct UL_AddReconfTransChInfoList_r8	*ul_AddReconfTransChInfoList	/* OPTIONAL */;
				struct DL_CommonTransChInfo_r4	*dl_CommonTransChInfo	/* OPTIONAL */;
				struct DL_AddReconfTransChInfoList_r11	*dl_AddReconfTransChInfoList	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} complete;
			struct RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration {
				struct RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode {
					RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode_PR present;
					union RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode_u {
						PredefinedConfigIdentity_t	 predefinedConfigIdentity;
						struct RRCConnectionSetup_r11_IEs__specificationMode__preconfiguration__preConfigMode__defaultConfig {
							DefaultConfigMode_t	 defaultConfigMode;
							DefaultConfigIdentity_r6_t	 defaultConfigIdentity;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} defaultConfig;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} preConfigMode;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} preconfiguration;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} specificationMode;
	struct FrequencyInfo	*frequencyInfo	/* OPTIONAL */;
	struct Multi_frequencyInfo_LCR_r7	*multi_frequencyInfo	/* OPTIONAL */;
	struct DTX_DRX_TimingInfo_r7	*dtx_drx_TimingInfo	/* OPTIONAL */;
	struct DTX_DRX_Info_r7	*dtx_drx_Info	/* OPTIONAL */;
	struct HS_SCCH_LessInfo_r7	*hs_scch_LessInfo	/* OPTIONAL */;
	MaxAllowedUL_TX_Power_t	*maxAllowedUL_TX_Power	/* OPTIONAL */;
	struct UL_DPCH_Info_r11	*ul_DPCH_Info	/* OPTIONAL */;
	struct UL_EDCH_Information_r11	*ul_EDCH_Information	/* OPTIONAL */;
	struct DL_HSPDSCH_Information_r11	*dl_HSPDSCH_Information	/* OPTIONAL */;
	struct DL_CommonInformation_r10	*dl_CommonInformation	/* OPTIONAL */;
	struct DL_InformationPerRL_List_r8	*dl_InformationPerRL_List	/* OPTIONAL */;
	struct DL_SecondaryCellInfoFDD_r11	*dl_SecondaryCellInfoFDD	/* OPTIONAL */;
	struct AdditionalDLSecCellInfoListFDD_r11	*additionalDLSecCellInfoListFDD	/* OPTIONAL */;
	struct CommonERGCHInfoFDD	*commonERGCHInfoFDD	/* OPTIONAL */;
	struct SPS_Information_TDD128_r8	*sps_Information_TDD128	/* OPTIONAL */;
	struct MU_MIMO_Info_TDD128	*mu_MIMO_Info_TDD128	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionSetup_r11_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionSetup_r11_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CapabilityUpdateRequirement-r8.h"
#include "DefaultConfigForCellFACH.h"
#include "FrequencyInfo.h"
#include "Multi-frequencyInfo-LCR-r7.h"
#include "DTX-DRX-TimingInfo-r7.h"
#include "DTX-DRX-Info-r7.h"
#include "HS-SCCH-LessInfo-r7.h"
#include "UL-DPCH-Info-r11.h"
#include "UL-EDCH-Information-r11.h"
#include "DL-HSPDSCH-Information-r11.h"
#include "DL-CommonInformation-r10.h"
#include "DL-InformationPerRL-List-r8.h"
#include "DL-SecondaryCellInfoFDD-r11.h"
#include "AdditionalDLSecCellInfoListFDD-r11.h"
#include "CommonERGCHInfoFDD.h"
#include "SPS-Information-TDD128-r8.h"
#include "MU-MIMO-Info-TDD128.h"
#include "UL-CommonTransChInfo-r4.h"
#include "UL-AddReconfTransChInfoList-r8.h"
#include "DL-CommonTransChInfo-r4.h"
#include "DL-AddReconfTransChInfoList-r11.h"

#endif	/* _RRCConnectionSetup_r11_IEs_H_ */
#include <asn_internal.h>
