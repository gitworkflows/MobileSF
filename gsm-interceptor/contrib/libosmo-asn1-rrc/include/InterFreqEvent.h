/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InterFreqEvent_H_
#define	_InterFreqEvent_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Event2a.h"
#include "Event2b.h"
#include "Event2c.h"
#include "Event2d.h"
#include "Event2e.h"
#include "Event2f.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum InterFreqEvent_PR {
	InterFreqEvent_PR_NOTHING,	/* No components present */
	InterFreqEvent_PR_event2a,
	InterFreqEvent_PR_event2b,
	InterFreqEvent_PR_event2c,
	InterFreqEvent_PR_event2d,
	InterFreqEvent_PR_event2e,
	InterFreqEvent_PR_event2f
} InterFreqEvent_PR;

/* InterFreqEvent */
typedef struct InterFreqEvent {
	InterFreqEvent_PR present;
	union InterFreqEvent_u {
		Event2a_t	 event2a;
		Event2b_t	 event2b;
		Event2c_t	 event2c;
		Event2d_t	 event2d;
		Event2e_t	 event2e;
		Event2f_t	 event2f;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterFreqEvent_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterFreqEvent;

#ifdef __cplusplus
}
#endif

#endif	/* _InterFreqEvent_H_ */
#include <asn_internal.h>
