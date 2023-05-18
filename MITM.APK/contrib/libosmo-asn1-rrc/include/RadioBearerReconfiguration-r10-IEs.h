/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RadioBearerReconfiguration_r10_IEs_H_
#define	_RadioBearerReconfiguration_r10_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ActivationTime.h"
#include "DelayRestrictionFlag.h"
#include "C-RNTI.h"
#include "DSCH-RNTI.h"
#include "H-RNTI.h"
#include "E-RNTI.h"
#include "RRC-StateIndicator.h"
#include "High-MobilityDetected.h"
#include "URA-Identity.h"
#include <BOOLEAN.h>
#include <NativeEnumerated.h>
#include "MaxAllowedUL-TX-Power.h"
#include "MBMS-PL-ServiceRestrictInfo-r6.h"
#include "PDCP-ROHC-TargetMode.h"
#include <constr_SEQUENCE.h>
#include "PredefinedConfigIdentity.h"
#include "DefaultConfigMode.h"
#include "DefaultConfigIdentity-r6.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RadioBearerReconfiguration_r10_IEs__responseToChangeOfUE_Capability {
	RadioBearerReconfiguration_r10_IEs__responseToChangeOfUE_Capability_true	= 0
} e_RadioBearerReconfiguration_r10_IEs__responseToChangeOfUE_Capability;
typedef enum RadioBearerReconfiguration_r10_IEs__specificationMode_PR {
	RadioBearerReconfiguration_r10_IEs__specificationMode_PR_NOTHING,	/* No components present */
	RadioBearerReconfiguration_r10_IEs__specificationMode_PR_complete,
	RadioBearerReconfiguration_r10_IEs__specificationMode_PR_preconfiguration
} RadioBearerReconfiguration_r10_IEs__specificationMode_PR;
typedef enum RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode_PR {
	RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode_PR_NOTHING,	/* No components present */
	RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode_PR_predefinedConfigIdentity,
	RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode_PR_defaultConfig
} RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode_PR;

/* Forward declarations */
struct IntegrityProtectionModeInfo_r7;
struct CipheringModeInfo_r7;
struct U_RNTI;
struct UTRAN_DRX_CycleLengthCoefficient_r7;
struct CN_InformationInfo_r6;
struct DefaultConfigForCellFACH;
struct FrequencyInfo;
struct Multi_frequencyInfo_LCR_r7;
struct DTX_DRX_TimingInfo_r7;
struct DTX_DRX_Info_r7;
struct HS_SCCH_LessInfo_r7;
struct MIMO_Parameters_r9;
struct UL_DPCH_Info_r7;
struct UL_EDCH_Information_r9;
struct UL_SecondaryCellInfoFDD;
struct UL_MulticarrierEDCHInfo_TDD128;
struct DL_HSPDSCH_Information_r9;
struct DL_CommonInformation_r10;
struct DL_InformationPerRL_List_r8;
struct DL_SecondaryCellInfoFDD_r10;
struct AdditionalDLSecCellInfoListFDD;
struct ControlChannelDRXInfo_TDD128_r8;
struct SPS_Information_TDD128_r8;
struct MU_MIMO_Info_TDD128;
struct CellDCHMeasOccasionInfo_TDD128_r9;
struct RAB_InformationReconfigList_r8;
struct RAB_InformationMBMSPtpList;
struct RB_InformationReconfigList_r8;
struct RB_InformationAffectedList_r8;
struct RB_PDCPContextRelocationList;
struct UL_CommonTransChInfo_r4;
struct UL_DeletedTransChInfoList_r6;
struct UL_AddReconfTransChInfoList_r8;
struct DL_CommonTransChInfo_r4;
struct DL_DeletedTransChInfoList_r7;
struct DL_AddReconfTransChInfoList_r9;

/* RadioBearerReconfiguration-r10-IEs */
typedef struct RadioBearerReconfiguration_r10_IEs {
	struct IntegrityProtectionModeInfo_r7	*integrityProtectionModeInfo	/* OPTIONAL */;
	struct CipheringModeInfo_r7	*cipheringModeInfo	/* OPTIONAL */;
	ActivationTime_t	*activationTime	/* OPTIONAL */;
	DelayRestrictionFlag_t	*delayRestrictionFlag	/* OPTIONAL */;
	struct U_RNTI	*new_U_RNTI	/* OPTIONAL */;
	C_RNTI_t	*new_C_RNTI	/* OPTIONAL */;
	DSCH_RNTI_t	*new_DSCH_RNTI	/* OPTIONAL */;
	H_RNTI_t	*new_H_RNTI	/* OPTIONAL */;
	E_RNTI_t	*newPrimary_E_RNTI	/* OPTIONAL */;
	E_RNTI_t	*newSecondary_E_RNTI	/* OPTIONAL */;
	RRC_StateIndicator_t	 rrc_StateIndicator;
	High_MobilityDetected_t	*ueMobilityStateIndicator	/* OPTIONAL */;
	struct UTRAN_DRX_CycleLengthCoefficient_r7	*utran_DRX_CycleLengthCoeff	/* OPTIONAL */;
	struct CN_InformationInfo_r6	*cn_InformationInfo	/* OPTIONAL */;
	URA_Identity_t	*ura_Identity	/* OPTIONAL */;
	BOOLEAN_t	*supportForChangeOfUE_Capability	/* OPTIONAL */;
	long	*responseToChangeOfUE_Capability	/* OPTIONAL */;
	struct DefaultConfigForCellFACH	*defaultConfigForCellFACH	/* OPTIONAL */;
	struct RadioBearerReconfiguration_r10_IEs__specificationMode {
		RadioBearerReconfiguration_r10_IEs__specificationMode_PR present;
		union RadioBearerReconfiguration_r10_IEs__specificationMode_u {
			struct RadioBearerReconfiguration_r10_IEs__specificationMode__complete {
				struct RAB_InformationReconfigList_r8	*rab_InformationReconfigList	/* OPTIONAL */;
				struct RAB_InformationMBMSPtpList	*rab_InformationMBMSPtpList	/* OPTIONAL */;
				struct RB_InformationReconfigList_r8	*rb_InformationReconfigList	/* OPTIONAL */;
				struct RB_InformationAffectedList_r8	*rb_InformationAffectedList	/* OPTIONAL */;
				struct RB_PDCPContextRelocationList	*rb_PDCPContextRelocationList	/* OPTIONAL */;
				PDCP_ROHC_TargetMode_t	*pdcp_ROHC_TargetMode	/* OPTIONAL */;
				struct UL_CommonTransChInfo_r4	*ul_CommonTransChInfo	/* OPTIONAL */;
				struct UL_DeletedTransChInfoList_r6	*ul_deletedTransChInfoList	/* OPTIONAL */;
				struct UL_AddReconfTransChInfoList_r8	*ul_AddReconfTransChInfoList	/* OPTIONAL */;
				struct DL_CommonTransChInfo_r4	*dl_CommonTransChInfo	/* OPTIONAL */;
				struct DL_DeletedTransChInfoList_r7	*dl_DeletedTransChInfoList	/* OPTIONAL */;
				struct DL_AddReconfTransChInfoList_r9	*dl_AddReconfTransChInfoList	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} complete;
			struct RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration {
				struct RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode {
					RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode_PR present;
					union RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode_u {
						PredefinedConfigIdentity_t	 predefinedConfigIdentity;
						struct RadioBearerReconfiguration_r10_IEs__specificationMode__preconfiguration__preConfigMode__defaultConfig {
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
	struct MIMO_Parameters_r9	*mimoParameters	/* OPTIONAL */;
	MaxAllowedUL_TX_Power_t	*maxAllowedUL_TX_Power	/* OPTIONAL */;
	struct UL_DPCH_Info_r7	*ul_DPCH_Info	/* OPTIONAL */;
	struct UL_EDCH_Information_r9	*ul_EDCH_Information	/* OPTIONAL */;
	struct UL_SecondaryCellInfoFDD	*ul_SecondaryCellInfoFDD	/* OPTIONAL */;
	struct UL_MulticarrierEDCHInfo_TDD128	*ul_MulticarrierEDCHInfo_TDD128	/* OPTIONAL */;
	struct DL_HSPDSCH_Information_r9	*dl_HSPDSCH_Information	/* OPTIONAL */;
	struct DL_CommonInformation_r10	*dl_CommonInformation	/* OPTIONAL */;
	struct DL_InformationPerRL_List_r8	*dl_InformationPerRL_List	/* OPTIONAL */;
	struct DL_SecondaryCellInfoFDD_r10	*dl_SecondaryCellInfoFDD	/* OPTIONAL */;
	struct AdditionalDLSecCellInfoListFDD	*additionalDLSecCellInfoListFDD	/* OPTIONAL */;
	struct ControlChannelDRXInfo_TDD128_r8	*controlChannelDRXInfo_TDD128	/* OPTIONAL */;
	struct SPS_Information_TDD128_r8	*sps_Information_TDD128	/* OPTIONAL */;
	struct MU_MIMO_Info_TDD128	*mu_MIMO_Info_TDD128	/* OPTIONAL */;
	MBMS_PL_ServiceRestrictInfo_r6_t	*mbms_PL_ServiceRestrictInfo	/* OPTIONAL */;
	struct CellDCHMeasOccasionInfo_TDD128_r9	*cellDCHMeasOccasionInfo_TDD128	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RadioBearerReconfiguration_r10_IEs_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_responseToChangeOfUE_Capability_18;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_RadioBearerReconfiguration_r10_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "IntegrityProtectionModeInfo-r7.h"
#include "CipheringModeInfo-r7.h"
#include "U-RNTI.h"
#include "UTRAN-DRX-CycleLengthCoefficient-r7.h"
#include "CN-InformationInfo-r6.h"
#include "DefaultConfigForCellFACH.h"
#include "FrequencyInfo.h"
#include "Multi-frequencyInfo-LCR-r7.h"
#include "DTX-DRX-TimingInfo-r7.h"
#include "DTX-DRX-Info-r7.h"
#include "HS-SCCH-LessInfo-r7.h"
#include "MIMO-Parameters-r9.h"
#include "UL-DPCH-Info-r7.h"
#include "UL-EDCH-Information-r9.h"
#include "UL-SecondaryCellInfoFDD.h"
#include "UL-MulticarrierEDCHInfo-TDD128.h"
#include "DL-HSPDSCH-Information-r9.h"
#include "DL-CommonInformation-r10.h"
#include "DL-InformationPerRL-List-r8.h"
#include "DL-SecondaryCellInfoFDD-r10.h"
#include "AdditionalDLSecCellInfoListFDD.h"
#include "ControlChannelDRXInfo-TDD128-r8.h"
#include "SPS-Information-TDD128-r8.h"
#include "MU-MIMO-Info-TDD128.h"
#include "CellDCHMeasOccasionInfo-TDD128-r9.h"
#include "RAB-InformationReconfigList-r8.h"
#include "RAB-InformationMBMSPtpList.h"
#include "RB-InformationReconfigList-r8.h"
#include "RB-InformationAffectedList-r8.h"
#include "RB-PDCPContextRelocationList.h"
#include "UL-CommonTransChInfo-r4.h"
#include "UL-DeletedTransChInfoList-r6.h"
#include "UL-AddReconfTransChInfoList-r8.h"
#include "DL-CommonTransChInfo-r4.h"
#include "DL-DeletedTransChInfoList-r7.h"
#include "DL-AddReconfTransChInfoList-r9.h"

#endif	/* _RadioBearerReconfiguration_r10_IEs_H_ */
#include <asn_internal.h>
