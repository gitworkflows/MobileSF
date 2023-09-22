/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_AcquisitionSatInfo_r10_H_
#define	_AcquisitionSatInfo_r10_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SatID.h"
#include <NativeInteger.h>
#include "CodePhaseSearchWindow.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ExtraDopplerInfo;
struct AzimuthAndElevation_r10;

/* AcquisitionSatInfo-r10 */
typedef struct AcquisitionSatInfo_r10 {
	SatID_t	 satID;
	long	 doppler0thOrder;
	struct ExtraDopplerInfo	*extraDopplerInfo	/* OPTIONAL */;
	long	 codePhase;
	long	 integerCodePhase;
	long	 gps_BitNumber;
	CodePhaseSearchWindow_t	 codePhaseSearchWindow;
	struct AzimuthAndElevation_r10	*azimuthAndElevation	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AcquisitionSatInfo_r10_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AcquisitionSatInfo_r10;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ExtraDopplerInfo.h"
#include "AzimuthAndElevation-r10.h"

#endif	/* _AcquisitionSatInfo_r10_H_ */
#include <asn_internal.h>
