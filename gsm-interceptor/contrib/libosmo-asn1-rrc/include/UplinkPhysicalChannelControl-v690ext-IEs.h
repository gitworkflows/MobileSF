/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UplinkPhysicalChannelControl_v690ext_IEs_H_
#define	_UplinkPhysicalChannelControl_v690ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "BEACON-PL-Est.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UplinkPhysicalChannelControl-v690ext-IEs */
typedef struct UplinkPhysicalChannelControl_v690ext_IEs {
	BEACON_PL_Est_t	*beaconPLEst	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UplinkPhysicalChannelControl_v690ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UplinkPhysicalChannelControl_v690ext_IEs;

#ifdef __cplusplus
}
#endif

#endif	/* _UplinkPhysicalChannelControl_v690ext_IEs_H_ */
#include <asn_internal.h>
