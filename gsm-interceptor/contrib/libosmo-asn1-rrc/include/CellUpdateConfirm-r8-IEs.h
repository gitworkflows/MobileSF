/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_CellUpdateConfirm_r8_IEs_H_
#define	_CellUpdateConfirm_r8_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ActivationTime.h"
#include "C-RNTI.h"
#include "DSCH-RNTI.h"
#include "H-RNTI.h"
#include "E-RNTI.h"
#include "RRC-StateIndicator.h"
#include "WaitTime.h"
#include <BOOLEAN.h>
#include "URA-Identity.h"
#include "PDCP-ROHC-TargetMode.h"
#include "MaxAllowedUL-TX-Power.h"
#include "MBMS-PL-ServiceRestrictInfo-r6.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IntegrityProtectionModeInfo_r7;
struct CipheringModeInfo_r7;
struct U_RNTI;
struct UTRAN_DRX_CycleLengthCoefficient_r7;
struct CN_InformationInfo_r6;
struct DefaultConfigForCellFACH;
struct RAB_InformationSetup_r8;
struct RB_InformationReleaseList;
struct RB_InformationReconfigList_r8;
struct RB_InformationAffectedList_r8;
struct DL_CounterSynchronisationInfo_r5;
struct UL_CommonTransChInfo_r4;
struct UL_DeletedTransChInfoList_r6;
struct UL_AddReconfTransChInfoList_r8;
struct DL_CommonTransChInfo_r4;
struct DL_DeletedTransChInfoList_r7;
struct DL_AddReconfTransChInfoList_r7;
struct FrequencyInfo;
struct Multi_frequencyInfo_LCR_r7;
struct DTX_DRX_TimingInfo_r7;
struct DTX_DRX_Info_r7;
struct HS_SCCH_LessInfo_r7;
struct MIMO_Parameters_r8;
struct UL_DPCH_Info_r7;
struct UL_EDCH_Information_r8;
struct DL_HSPDSCH_Information_r8;
struct DL_CommonInformation_r8;
struct DL_InformationPerRL_List_r8;
struct DL_SecondaryCellInfoFDD;
struct ControlChannelDRXInfo_TDD128_r8;
struct SPS_Information_TDD128_r8;

/* CellUpdateConfirm-r8-IEs */
typedef struct CellUpdateConfirm_r8_IEs {
	struct IntegrityProtectionModeInfo_r7	*integrityProtectionModeInfo	/* OPTIONAL */;
	struct CipheringModeInfo_r7	*cipheringModeInfo	/* OPTIONAL */;
	ActivationTime_t	*activationTime	/* OPTIONAL */;
	struct U_RNTI	*new_U_RNTI	/* OPTIONAL */;
	C_RNTI_t	*new_C_RNTI	/* OPTIONAL */;
	DSCH_RNTI_t	*new_DSCH_RNTI	/* OPTIONAL */;
	H_RNTI_t	*new_H_RNTI	/* OPTIONAL */;
	E_RNTI_t	*newPrimary_E_RNTI	/* OPTIONAL */;
	E_RNTI_t	*newSecondary_E_RNTI	/* OPTIONAL */;
	RRC_StateIndicator_t	 rrc_StateIndicator;
	struct UTRAN_DRX_CycleLengthCoefficient_r7	*utran_DRX_CycleLengthCoeff	/* OPTIONAL */;
	WaitTime_t	*waitTime	/* OPTIONAL */;
	BOOLEAN_t	 rlc_Re_establishIndicatorRb2_3or4;
	BOOLEAN_t	 rlc_Re_establishIndicatorRb5orAbove;
	struct CN_InformationInfo_r6	*cn_InformationInfo	/* OPTIONAL */;
	URA_Identity_t	*ura_Identity	/* OPTIONAL */;
	BOOLEAN_t	*supportForChangeOfUE_Capability	/* OPTIONAL */;
	struct DefaultConfigForCellFACH	*dummy	/* OPTIONAL */;
	struct RAB_InformationSetup_r8	*rab_InformationSetup	/* OPTIONAL */;
	struct RB_InformationReleaseList	*rb_InformationReleaseList	/* OPTIONAL */;
	struct RB_InformationReconfigList_r8	*rb_InformationReconfigList	/* OPTIONAL */;
	struct RB_InformationAffectedList_r8	*rb_InformationAffectedList	/* OPTIONAL */;
	struct DL_CounterSynchronisationInfo_r5	*dl_CounterSynchronisationInfo	/* OPTIONAL */;
	PDCP_ROHC_TargetMode_t	*pdcp_ROHC_TargetMode	/* OPTIONAL */;
	struct UL_CommonTransChInfo_r4	*ul_CommonTransChInfo	/* OPTIONAL */;
	struct UL_DeletedTransChInfoList_r6	*ul_deletedTransChInfoList	/* OPTIONAL */;
	struct UL_AddReconfTransChInfoList_r8	*ul_AddReconfTransChInfoList	/* OPTIONAL */;
	struct DL_CommonTransChInfo_r4	*dl_CommonTransChInfo	/* OPTIONAL */;
	struct DL_DeletedTransChInfoList_r7	*dl_DeletedTransChInfoList	/* OPTIONAL */;
	struct DL_AddReconfTransChInfoList_r7	*dl_AddReconfTransChInfoList	/* OPTIONAL */;
	struct FrequencyInfo	*frequencyInfo	/* OPTIONAL */;
	struct Multi_frequencyInfo_LCR_r7	*multi_frequencyInfo	/* OPTIONAL */;
	struct DTX_DRX_TimingInfo_r7	*dtx_drx_TimingInfo	/* OPTIONAL */;
	struct DTX_DRX_Info_r7	*dtx_drx_Info	/* OPTIONAL */;
	struct HS_SCCH_LessInfo_r7	*hs_scch_LessInfo	/* OPTIONAL */;
	struct MIMO_Parameters_r8	*mimoParameters	/* OPTIONAL */;
	MaxAllowedUL_TX_Power_t	*maxAllowedUL_TX_Power	/* OPTIONAL */;
	struct UL_DPCH_Info_r7	*ul_DPCH_Info	/* OPTIONAL */;
	struct UL_EDCH_Information_r8	*ul_EDCH_Information	/* OPTIONAL */;
	struct DL_HSPDSCH_Information_r8	*dl_HSPDSCH_Information	/* OPTIONAL */;
	struct DL_CommonInformation_r8	*dl_CommonInformation	/* OPTIONAL */;
	struct DL_InformationPerRL_List_r8	*dl_InformationPerRL_List	/* OPTIONAL */;
	struct DL_SecondaryCellInfoFDD	*dl_SecondaryCellInfoFDD	/* OPTIONAL */;
	struct ControlChannelDRXInfo_TDD128_r8	*controlChannelDRXInfo_TDD128	/* OPTIONAL */;
	struct SPS_Information_TDD128_r8	*sps_Information_TDD128	/* OPTIONAL */;
	MBMS_PL_ServiceRestrictInfo_r6_t	*mbms_PL_ServiceRestrictInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellUpdateConfirm_r8_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellUpdateConfirm_r8_IEs;

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
#include "RAB-InformationSetup-r8.h"
#include "RB-InformationReleaseList.h"
#include "RB-InformationReconfigList-r8.h"
#include "RB-InformationAffectedList-r8.h"
#include "DL-CounterSynchronisationInfo-r5.h"
#include "UL-CommonTransChInfo-r4.h"
#include "UL-DeletedTransChInfoList-r6.h"
#include "UL-AddReconfTransChInfoList-r8.h"
#include "DL-CommonTransChInfo-r4.h"
#include "DL-DeletedTransChInfoList-r7.h"
#include "DL-AddReconfTransChInfoList-r7.h"
#include "FrequencyInfo.h"
#include "Multi-frequencyInfo-LCR-r7.h"
#include "DTX-DRX-TimingInfo-r7.h"
#include "DTX-DRX-Info-r7.h"
#include "HS-SCCH-LessInfo-r7.h"
#include "MIMO-Parameters-r8.h"
#include "UL-DPCH-Info-r7.h"
#include "UL-EDCH-Information-r8.h"
#include "DL-HSPDSCH-Information-r8.h"
#include "DL-CommonInformation-r8.h"
#include "DL-InformationPerRL-List-r8.h"
#include "DL-SecondaryCellInfoFDD.h"
#include "ControlChannelDRXInfo-TDD128-r8.h"
#include "SPS-Information-TDD128-r8.h"

#endif	/* _CellUpdateConfirm_r8_IEs_H_ */
#include <asn_internal.h>
