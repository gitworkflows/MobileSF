/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_AssistanceDataDelivery_v920ext_IEs_H_
#define	_AssistanceDataDelivery_v920ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UE_Positioning_GPS_AssistanceData_v920ext;
struct UE_Positioning_GANSS_AssistanceData_v920ext;

/* AssistanceDataDelivery-v920ext-IEs */
typedef struct AssistanceDataDelivery_v920ext_IEs {
	struct UE_Positioning_GPS_AssistanceData_v920ext	*ue_positioning_GPS_AssistanceData_v920ext	/* OPTIONAL */;
	struct UE_Positioning_GANSS_AssistanceData_v920ext	*ue_positioning_GANSS_AssistanceData_v920ext	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AssistanceDataDelivery_v920ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AssistanceDataDelivery_v920ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "UE-Positioning-GPS-AssistanceData-v920ext.h"
#include "UE-Positioning-GANSS-AssistanceData-v920ext.h"

#endif	/* _AssistanceDataDelivery_v920ext_IEs_H_ */
#include <asn_internal.h>
