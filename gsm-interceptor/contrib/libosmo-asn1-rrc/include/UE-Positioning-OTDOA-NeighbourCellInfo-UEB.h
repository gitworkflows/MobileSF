/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_Positioning_OTDOA_NeighbourCellInfo_UEB_H_
#define	_UE_Positioning_OTDOA_NeighbourCellInfo_UEB_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SFN-SFN-RelTimeDifference1.h"
#include "SFN-SFN-Drift.h"
#include "OTDOA-SearchWindowSize.h"
#include <NativeInteger.h>
#include "FineSFN-SFN.h"
#include "PrimaryCPICH-Info.h"
#include <constr_SEQUENCE.h>
#include "CellAndChannelIdentity.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo_PR {
	UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo_PR_NOTHING,	/* No components present */
	UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo_PR_fdd,
	UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo_PR_tdd
} UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo_PR;

/* Forward declarations */
struct FrequencyInfo;
struct UE_Positioning_IPDL_Parameters;

/* UE-Positioning-OTDOA-NeighbourCellInfo-UEB */
typedef struct UE_Positioning_OTDOA_NeighbourCellInfo_UEB {
	struct UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo {
		UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo_PR present;
		union UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo_u {
			struct UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo__fdd {
				PrimaryCPICH_Info_t	 primaryCPICH_Info;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct UE_Positioning_OTDOA_NeighbourCellInfo_UEB__modeSpecificInfo__tdd {
				CellAndChannelIdentity_t	 cellAndChannelIdentity;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	struct FrequencyInfo	*frequencyInfo	/* OPTIONAL */;
	struct UE_Positioning_IPDL_Parameters	*ue_positioning_IPDL_Paremeters	/* OPTIONAL */;
	SFN_SFN_RelTimeDifference1_t	 sfn_SFN_RelTimeDifference;
	SFN_SFN_Drift_t	*sfn_SFN_Drift	/* OPTIONAL */;
	OTDOA_SearchWindowSize_t	 searchWindowSize;
	long	*relativeNorth	/* OPTIONAL */;
	long	*relativeEast	/* OPTIONAL */;
	long	*relativeAltitude	/* OPTIONAL */;
	FineSFN_SFN_t	 fineSFN_SFN;
	long	*roundTripTime	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_OTDOA_NeighbourCellInfo_UEB_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_OTDOA_NeighbourCellInfo_UEB;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "FrequencyInfo.h"
#include "UE-Positioning-IPDL-Parameters.h"

#endif	/* _UE_Positioning_OTDOA_NeighbourCellInfo_UEB_H_ */
#include <asn_internal.h>
