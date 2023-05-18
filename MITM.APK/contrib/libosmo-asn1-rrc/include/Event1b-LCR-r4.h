/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_Event1b_LCR_r4_H_
#define	_Event1b_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TriggeringCondition1.h"
#include "ReportingRange.h"
#include "W.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ForbiddenAffectCellList_LCR_r4;

/* Event1b-LCR-r4 */
typedef struct Event1b_LCR_r4 {
	TriggeringCondition1_t	 triggeringCondition;
	ReportingRange_t	 reportingRange;
	struct ForbiddenAffectCellList_LCR_r4	*forbiddenAffectCellList	/* OPTIONAL */;
	W_t	 w;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Event1b_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Event1b_LCR_r4;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ForbiddenAffectCellList-LCR-r4.h"

#endif	/* _Event1b_LCR_r4_H_ */
#include <asn_internal.h>
