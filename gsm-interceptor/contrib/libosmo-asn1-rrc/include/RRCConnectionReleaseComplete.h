/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RRCConnectionReleaseComplete_H_
#define	_RRCConnectionReleaseComplete_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-TransactionIdentifier.h"
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct FailureCauseWithProtErr;

/* RRCConnectionReleaseComplete */
typedef struct RRCConnectionReleaseComplete {
	RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
	struct FailureCauseWithProtErr	*errorIndication	/* OPTIONAL */;
	struct RRCConnectionReleaseComplete__laterNonCriticalExtensions {
		BIT_STRING_t	*rrcConnectionReleaseComplete_r3_add_ext	/* OPTIONAL */;
		struct RRCConnectionReleaseComplete__laterNonCriticalExtensions__nonCriticalExtensions {
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *nonCriticalExtensions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *laterNonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionReleaseComplete_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionReleaseComplete;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "FailureCauseWithProtErr.h"

#endif	/* _RRCConnectionReleaseComplete_H_ */
#include <asn_internal.h>
