/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMSUnmodifiedServicesInformation_H_
#define	_MBMSUnmodifiedServicesInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMSUnmodifiedServicesInformation-v770ext-IEs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_UnmodifiedServiceList_r6;

/* MBMSUnmodifiedServicesInformation */
typedef struct MBMSUnmodifiedServicesInformation {
	struct MBMS_UnmodifiedServiceList_r6	*unmodifiedServiceList	/* OPTIONAL */;
	struct MBMSUnmodifiedServicesInformation__v770NonCriticalExtensions {
		MBMSUnmodifiedServicesInformation_v770ext_IEs_t	 mbmsUnmodifiedServicesInformation_v770ext;
		struct MBMSUnmodifiedServicesInformation__v770NonCriticalExtensions__nonCriticalExtensions {
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *nonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *v770NonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMSUnmodifiedServicesInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMSUnmodifiedServicesInformation;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBMS-UnmodifiedServiceList-r6.h"

#endif	/* _MBMSUnmodifiedServicesInformation_H_ */
#include <asn_internal.h>
