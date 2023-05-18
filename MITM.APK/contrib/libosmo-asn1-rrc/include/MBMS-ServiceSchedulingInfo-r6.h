/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMS_ServiceSchedulingInfo_r6_H_
#define	_MBMS_ServiceSchedulingInfo_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMS-TransmissionIdentity.h"
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_ServiceTransmInfoList;

/* MBMS-ServiceSchedulingInfo-r6 */
typedef struct MBMS_ServiceSchedulingInfo_r6 {
	MBMS_TransmissionIdentity_t	 mbms_TransmissionIdentity;
	struct MBMS_ServiceTransmInfoList	*mbms_ServiceTransmInfoList	/* OPTIONAL */;
	long	 nextSchedulingperiod;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_ServiceSchedulingInfo_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_ServiceSchedulingInfo_r6;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBMS-ServiceTransmInfoList.h"

#endif	/* _MBMS_ServiceSchedulingInfo_r6_H_ */
#include <asn_internal.h>
