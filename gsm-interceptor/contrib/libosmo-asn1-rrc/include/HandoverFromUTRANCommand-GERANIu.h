/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_HandoverFromUTRANCommand_GERANIu_H_
#define	_HandoverFromUTRANCommand_GERANIu_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-TransactionIdentifier.h"
#include "HandoverFromUTRANCommand-GERANIu-r5-IEs.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu_PR {
	HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu_PR_NOTHING,	/* No components present */
	HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu_PR_r5,
	HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu_PR_later_than_r5
} HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu_PR;

/* HandoverFromUTRANCommand-GERANIu */
typedef struct HandoverFromUTRANCommand_GERANIu {
	RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
	struct HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu {
		HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu_PR present;
		union HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu_u {
			struct HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu__r5 {
				HandoverFromUTRANCommand_GERANIu_r5_IEs_t	 handoverFromUTRANCommand_GERANIu_r5;
				struct HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu__r5__nonCriticalExtensions {
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *nonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} r5;
			struct HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu__later_than_r5 {
				struct HandoverFromUTRANCommand_GERANIu__handoverFromUTRANCommand_GERANIu__later_than_r5__criticalExtensions {
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} criticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} later_than_r5;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} handoverFromUTRANCommand_GERANIu;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HandoverFromUTRANCommand_GERANIu_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HandoverFromUTRANCommand_GERANIu;

#ifdef __cplusplus
}
#endif

#endif	/* _HandoverFromUTRANCommand_GERANIu_H_ */
#include <asn_internal.h>
