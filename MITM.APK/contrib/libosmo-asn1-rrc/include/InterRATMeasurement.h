/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InterRATMeasurement_H_
#define	_InterRATMeasurement_H_


#include <asn_application.h>

/* Including external dependencies */
#include "InterRATReportCriteria.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct InterRATCellInfoList;
struct InterRATMeasQuantity;
struct InterRATReportingQuantity;

/* InterRATMeasurement */
typedef struct InterRATMeasurement {
	struct InterRATCellInfoList	*interRATCellInfoList	/* OPTIONAL */;
	struct InterRATMeasQuantity	*interRATMeasQuantity	/* OPTIONAL */;
	struct InterRATReportingQuantity	*interRATReportingQuantity	/* OPTIONAL */;
	InterRATReportCriteria_t	 reportCriteria;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRATMeasurement_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRATMeasurement;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "InterRATCellInfoList.h"
#include "InterRATMeasQuantity.h"
#include "InterRATReportingQuantity.h"

#endif	/* _InterRATMeasurement_H_ */
#include <asn_internal.h>
