/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMSModificationRequest_H_
#define	_MBMSModificationRequest_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMSModificationRequest-v6b0ext-IEs.h"
#include "MBMSModificationRequest-v6f0ext-IEs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_ServiceIdentity_r6;
struct RB_InformationReleaseList;

/* MBMSModificationRequest */
typedef struct MBMSModificationRequest {
	struct MBMS_ServiceIdentity_r6	*mbms_PreferredFreqRequest	/* OPTIONAL */;
	struct RB_InformationReleaseList	*rb_InformationReleaseList	/* OPTIONAL */;
	struct MBMSModificationRequest__v6b0NonCriticalExtensions {
		MBMSModificationRequest_v6b0ext_IEs_t	 mbmsModificationRequest_v6b0ext;
		struct MBMSModificationRequest__v6b0NonCriticalExtensions__v6f0NonCriticalExtensions {
			MBMSModificationRequest_v6f0ext_IEs_t	 mbmsModificationRequest_v6f0ext;
			struct MBMSModificationRequest__v6b0NonCriticalExtensions__v6f0NonCriticalExtensions__nonCriticalExtensions {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *nonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *v6f0NonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *v6b0NonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMSModificationRequest_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMSModificationRequest;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBMS-ServiceIdentity-r6.h"
#include "RB-InformationReleaseList.h"

#endif	/* _MBMSModificationRequest_H_ */
#include <asn_internal.h>
