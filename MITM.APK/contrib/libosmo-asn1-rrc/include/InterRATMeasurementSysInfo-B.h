/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InterRATMeasurementSysInfo_B_H_
#define	_InterRATMeasurementSysInfo_B_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct InterRATCellInfoList_B;

/* InterRATMeasurementSysInfo-B */
typedef struct InterRATMeasurementSysInfo_B {
	struct InterRATCellInfoList_B	*interRATCellInfoList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRATMeasurementSysInfo_B_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRATMeasurementSysInfo_B;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "InterRATCellInfoList-B.h"

#endif	/* _InterRATMeasurementSysInfo_B_H_ */
#include <asn_internal.h>
