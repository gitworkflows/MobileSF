/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SignallingConnectionReleaseIndication_H_
#define	_SignallingConnectionReleaseIndication_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CN-DomainIdentity.h"
#include <BIT_STRING.h>
#include "SignallingConnectionReleaseIndication-v860ext.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SignallingConnectionReleaseIndication */
typedef struct SignallingConnectionReleaseIndication {
	CN_DomainIdentity_t	 cn_DomainIdentity;
	struct SignallingConnectionReleaseIndication__laterNonCriticalExtensions {
		BIT_STRING_t	*signallingConnectionReleaseIndication_r3_add_ext	/* OPTIONAL */;
		struct SignallingConnectionReleaseIndication__laterNonCriticalExtensions__v860nonCriticalExtentions {
			SignallingConnectionReleaseIndication_v860ext_t	 signallingConnectionReleaseIndication_v860ext;
			struct SignallingConnectionReleaseIndication__laterNonCriticalExtensions__v860nonCriticalExtentions__nonCriticalExtensions {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *nonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *v860nonCriticalExtentions;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *laterNonCriticalExtensions;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SignallingConnectionReleaseIndication_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SignallingConnectionReleaseIndication;

#ifdef __cplusplus
}
#endif

#endif	/* _SignallingConnectionReleaseIndication_H_ */
#include <asn_internal.h>
