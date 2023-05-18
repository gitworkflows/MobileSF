/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InterFreqReportingCriteria_H_
#define	_InterFreqReportingCriteria_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct InterFreqEventList;

/* InterFreqReportingCriteria */
typedef struct InterFreqReportingCriteria {
	struct InterFreqEventList	*interFreqEventList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterFreqReportingCriteria_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterFreqReportingCriteria;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "InterFreqEventList.h"

#endif	/* _InterFreqReportingCriteria_H_ */
#include <asn_internal.h>
