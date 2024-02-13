/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UECapabilityInformation_r3_add_ext_IEs_H_
#define	_UECapabilityInformation_r3_add_ext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "UECapabilityInformation-v680ext-IEs.h"
#include "UECapabilityInformation-v7e0ext-IEs.h"
#include "UECapabilityInformation-v7f0ext-IEs.h"
#include "UECapabilityInformation-va40ext-IEs.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UECapabilityInformation_v650ext_IEs;

/* UECapabilityInformation-r3-add-ext-IEs */
typedef struct UECapabilityInformation_r3_add_ext_IEs {
	struct UECapabilityInformation_v650ext_IEs	*ueCapabilityInformation_v650ext	/* OPTIONAL */;
	struct UECapabilityInformation_r3_add_ext_IEs__v680NonCriticalExtensions {
		UECapabilityInformation_v680ext_IEs_t	 ueCapabilityInformation_v680ext;
		struct UECapabilityInformation_r3_add_ext_IEs__v680NonCriticalExtensions__v7e0NonCriticalExtensions {
			UECapabilityInformation_v7e0ext_IEs_t	 ueCapabilityInformation_v7e0ext;
			struct UECapabilityInformation_r3_add_ext_IEs__v680NonCriticalExtensions__v7e0NonCriticalExtensions__v7f0NonCriticalExtensions {
				UECapabilityInformation_v7f0ext_IEs_t	 ueCapabilityInformation_v7f0ext;
				struct UECapabilityInformation_r3_add_ext_IEs__v680NonCriticalExtensions__v7e0NonCriticalExtensions__v7f0NonCriticalExtensions__va40NonCriticalExtensions {
					UECapabilityInformation_va40ext_IEs_t	 ueCapabilityInformation_va40ext;
					struct UECapabilityInformation_r3_add_ext_IEs__v680NonCriticalExtensions__v7e0NonCriticalExtensions__v7f0NonCriticalExtensions__va40NonCriticalExtensions__nonCriticalExtensions {
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *nonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *va40NonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *v7f0NonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *v7e0NonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *v680NonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UECapabilityInformation_r3_add_ext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UECapabilityInformation_r3_add_ext_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "UECapabilityInformation-v650ext-IEs.h"

#endif	/* _UECapabilityInformation_r3_add_ext_IEs_H_ */
#include <asn_internal.h>
