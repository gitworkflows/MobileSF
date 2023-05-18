/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InterRATHandoverInfoWithInterRATCapabilities_r3_H_
#define	_InterRATHandoverInfoWithInterRATCapabilities_r3_H_


#include <asn_application.h>

/* Including external dependencies */
#include "InterRATHandoverInfoWithInterRATCapabilities-r3-IEs.h"
#include "InterRATHandoverInfoWithInterRATCapabilities-v390ext-IEs.h"
#include "InterRATHandoverInfoWithInterRATCapabilities-v690ext-IEs.h"
#include "InterRATHandoverInfoWithInterRATCapabilities-v860ext-IEs.h"
#include "InterRATHandoverInfoWithInterRATCapabilities-v920ext-IEs.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum InterRATHandoverInfoWithInterRATCapabilities_r3_PR {
	InterRATHandoverInfoWithInterRATCapabilities_r3_PR_NOTHING,	/* No components present */
	InterRATHandoverInfoWithInterRATCapabilities_r3_PR_r3,
	InterRATHandoverInfoWithInterRATCapabilities_r3_PR_criticalExtensions
} InterRATHandoverInfoWithInterRATCapabilities_r3_PR;

/* InterRATHandoverInfoWithInterRATCapabilities-r3 */
typedef struct InterRATHandoverInfoWithInterRATCapabilities_r3 {
	InterRATHandoverInfoWithInterRATCapabilities_r3_PR present;
	union InterRATHandoverInfoWithInterRATCapabilities_r3_u {
		struct InterRATHandoverInfoWithInterRATCapabilities_r3__r3 {
			InterRATHandoverInfoWithInterRATCapabilities_r3_IEs_t	 interRATHandoverInfo_r3;
			struct InterRATHandoverInfoWithInterRATCapabilities_r3__r3__v390NonCriticalExtensions {
				InterRATHandoverInfoWithInterRATCapabilities_v390ext_IEs_t	 interRATHandoverInfoWithInterRATCapabilities_v390ext;
				struct InterRATHandoverInfoWithInterRATCapabilities_r3__r3__v390NonCriticalExtensions__v690NonCriticalExtensions {
					InterRATHandoverInfoWithInterRATCapabilities_v690ext_IEs_t	 interRATHandoverInfoWithInterRATCapabilities_v690ext;
					struct InterRATHandoverInfoWithInterRATCapabilities_r3__r3__v390NonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions {
						InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_t	 interRATHandoverInfoWithInterRATCapabilities_v860ext;
						struct InterRATHandoverInfoWithInterRATCapabilities_r3__r3__v390NonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions__v920NonCriticalExtensions {
							InterRATHandoverInfoWithInterRATCapabilities_v920ext_IEs_t	 interRATHandoverInfoWithInterRATCapabilities_v920ext;
							struct InterRATHandoverInfoWithInterRATCapabilities_r3__r3__v390NonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions__v920NonCriticalExtensions__nonCriticalExtensions {
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *nonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v920NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *v860NonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *v690NonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *v390NonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} r3;
		struct InterRATHandoverInfoWithInterRATCapabilities_r3__criticalExtensions {
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} criticalExtensions;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRATHandoverInfoWithInterRATCapabilities_r3_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_r3;

#ifdef __cplusplus
}
#endif

#endif	/* _InterRATHandoverInfoWithInterRATCapabilities_r3_H_ */
#include <asn_internal.h>
