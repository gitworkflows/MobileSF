/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_GANSSGenericData_r9_H_
#define	_GANSSGenericData_r9_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include "UE-Positioning-GANSS-SBAS-ID.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GANSSTimeModelsList;
struct UE_Positioning_DGANSSCorrections_r9;
struct UE_Positioning_GANSS_NavigationModel;
struct UE_Positioning_GANSS_AddNavigationModels;
struct UE_Positioning_GANSS_RealTimeIntegrity;
struct UE_Positioning_GANSS_Data_Bit_Assistance;
struct UE_Positioning_GANSS_ReferenceMeasurementInfo;
struct UE_Positioning_GANSS_Almanac_r8;
struct UE_Positioning_GANSS_UTCModel;
struct UE_Positioning_GANSS_AddUTCModels;
struct UE_Positioning_GANSS_AuxiliaryInfo;

/* GANSSGenericData-r9 */
typedef struct GANSSGenericData_r9 {
	long	*ganssId	/* OPTIONAL */;
	UE_Positioning_GANSS_SBAS_ID_t	*uePositiningGANSSsbasID	/* OPTIONAL */;
	struct GANSSTimeModelsList	*ganssTimeModelsList	/* OPTIONAL */;
	struct UE_Positioning_DGANSSCorrections_r9	*uePositioningDGANSSCorrections	/* OPTIONAL */;
	struct UE_Positioning_GANSS_NavigationModel	*uePositioningGANSSNavigationModel	/* OPTIONAL */;
	struct UE_Positioning_GANSS_AddNavigationModels	*uePositioningGANSSAddNavigationModels	/* OPTIONAL */;
	struct UE_Positioning_GANSS_RealTimeIntegrity	*uePositioningGANSSRealTimeIntegrity	/* OPTIONAL */;
	struct UE_Positioning_GANSS_Data_Bit_Assistance	*uePositioningGANSSDataBitAssistance	/* OPTIONAL */;
	struct UE_Positioning_GANSS_ReferenceMeasurementInfo	*uePositioningGANSSReferenceMeasurementInfo	/* OPTIONAL */;
	struct UE_Positioning_GANSS_Almanac_r8	*uePositioningGANSSAlmanac	/* OPTIONAL */;
	struct UE_Positioning_GANSS_UTCModel	*uePositioningGANSSUTCModel	/* OPTIONAL */;
	struct UE_Positioning_GANSS_AddUTCModels	*uePositioningGANSSAddUTCModels	/* OPTIONAL */;
	struct UE_Positioning_GANSS_AuxiliaryInfo	*uePositioningGANSSAuxiliaryInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GANSSGenericData_r9_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GANSSGenericData_r9;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "GANSSTimeModelsList.h"
#include "UE-Positioning-DGANSSCorrections-r9.h"
#include "UE-Positioning-GANSS-NavigationModel.h"
#include "UE-Positioning-GANSS-AddNavigationModels.h"
#include "UE-Positioning-GANSS-RealTimeIntegrity.h"
#include "UE-Positioning-GANSS-Data-Bit-Assistance.h"
#include "UE-Positioning-GANSS-ReferenceMeasurementInfo.h"
#include "UE-Positioning-GANSS-Almanac-r8.h"
#include "UE-Positioning-GANSS-UTCModel.h"
#include "UE-Positioning-GANSS-AddUTCModels.h"
#include "UE-Positioning-GANSS-AuxiliaryInfo.h"

#endif	/* _GANSSGenericData_r9_H_ */
#include <asn_internal.h>
