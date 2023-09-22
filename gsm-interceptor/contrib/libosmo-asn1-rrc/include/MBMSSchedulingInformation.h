/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMSSchedulingInformation_H_
#define	_MBMSSchedulingInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMS-ServiceSchedulingInfoList-r6.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MBMSSchedulingInformation */
typedef struct MBMSSchedulingInformation {
	MBMS_ServiceSchedulingInfoList_r6_t	 serviceSchedulingInfoList;
	struct MBMSSchedulingInformation__nonCriticalExtensions {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMSSchedulingInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMSSchedulingInformation;

#ifdef __cplusplus
}
#endif

#endif	/* _MBMSSchedulingInformation_H_ */
#include <asn_internal.h>
