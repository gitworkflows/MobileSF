/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMS_UnmodifiedService_r6_H_
#define	_MBMS_UnmodifiedService_r6_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MBMS-TransmissionIdentity.h"
#include "MBMS-RequiredUEAction-UMod.h"
#include "MBMS-PFLIndex.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MBMS-UnmodifiedService-r6 */
typedef struct MBMS_UnmodifiedService_r6 {
	MBMS_TransmissionIdentity_t	 mbms_TransmissionIdentity;
	MBMS_RequiredUEAction_UMod_t	 mbms_RequiredUEAction;
	MBMS_PFLIndex_t	*mbms_PreferredFrequency	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_UnmodifiedService_r6_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_UnmodifiedService_r6;

#ifdef __cplusplus
}
#endif

#endif	/* _MBMS_UnmodifiedService_r6_H_ */
#include <asn_internal.h>
