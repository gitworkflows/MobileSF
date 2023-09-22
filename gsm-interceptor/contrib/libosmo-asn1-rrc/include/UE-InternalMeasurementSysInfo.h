/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UE_InternalMeasurementSysInfo_H_
#define	_UE_InternalMeasurementSysInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementIdentity.h"
#include "UE-InternalMeasQuantity.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UE-InternalMeasurementSysInfo */
typedef struct UE_InternalMeasurementSysInfo {
	MeasurementIdentity_t	*ue_InternalMeasurementID	/* DEFAULT 5 */;
	UE_InternalMeasQuantity_t	 ue_InternalMeasQuantity;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_InternalMeasurementSysInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_InternalMeasurementSysInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _UE_InternalMeasurementSysInfo_H_ */
#include <asn_internal.h>
