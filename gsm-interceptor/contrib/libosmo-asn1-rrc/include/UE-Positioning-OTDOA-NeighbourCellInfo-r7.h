/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_Positioning_OTDOA_NeighbourCellInfo_r7_H_
#define	_UE_Positioning_OTDOA_NeighbourCellInfo_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SFN-SFN-RelTimeDifference1.h"
#include "SFN-Offset-Validity.h"
#include "SFN-SFN-Drift.h"
#include "OTDOA-SearchWindowSize.h"
#include "PrimaryCPICH-Info.h"
#include <constr_SEQUENCE.h>
#include "CellAndChannelIdentity.h"
#include <constr_CHOICE.h>
#include <NativeInteger.h>
#include "FineSFN-SFN.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo_PR {
	UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo_PR_NOTHING,	/* No components present */
	UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo_PR_fdd,
	UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo_PR_tdd
} UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo_PR;
typedef enum UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode_PR {
	UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode_PR_NOTHING,	/* No components present */
	UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode_PR_ueBased,
	UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode_PR_ueAssisted
} UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode_PR;

/* Forward declarations */
struct FrequencyInfo;
struct UE_Positioning_IPDL_Parameters_r4;

/* UE-Positioning-OTDOA-NeighbourCellInfo-r7 */
typedef struct UE_Positioning_OTDOA_NeighbourCellInfo_r7 {
	struct UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo {
		UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo_PR present;
		union UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo_u {
			struct UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo__fdd {
				PrimaryCPICH_Info_t	 primaryCPICH_Info;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct UE_Positioning_OTDOA_NeighbourCellInfo_r7__modeSpecificInfo__tdd {
				CellAndChannelIdentity_t	 cellAndChannelIdentity;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	struct FrequencyInfo	*frequencyInfo	/* OPTIONAL */;
	struct UE_Positioning_IPDL_Parameters_r4	*ue_positioning_IPDL_Paremeters	/* OPTIONAL */;
	SFN_SFN_RelTimeDifference1_t	 sfn_SFN_RelTimeDifference;
	SFN_Offset_Validity_t	*sfn_Offset_Validity	/* OPTIONAL */;
	SFN_SFN_Drift_t	*sfn_SFN_Drift	/* OPTIONAL */;
	OTDOA_SearchWindowSize_t	 searchWindowSize;
	struct UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode {
		UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode_PR present;
		union UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode_u {
			struct UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode__ueBased {
				long	*relativeNorth	/* OPTIONAL */;
				long	*relativeEast	/* OPTIONAL */;
				long	*relativeAltitude	/* OPTIONAL */;
				FineSFN_SFN_t	*fineSFN_SFN	/* OPTIONAL */;
				long	*roundTripTime	/* OPTIONAL */;
				long	*roundTripTimeExtension	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} ueBased;
			struct UE_Positioning_OTDOA_NeighbourCellInfo_r7__positioningMode__ueAssisted {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} ueAssisted;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} positioningMode;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_OTDOA_NeighbourCellInfo_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_r7;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "FrequencyInfo.h"
#include "UE-Positioning-IPDL-Parameters-r4.h"

#endif	/* _UE_Positioning_OTDOA_NeighbourCellInfo_r7_H_ */
#include <asn_internal.h>
