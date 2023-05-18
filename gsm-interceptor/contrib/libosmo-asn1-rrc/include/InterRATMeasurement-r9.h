/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InterRATMeasurement_r9_H_
#define	_InterRATMeasurement_r9_H_


#include <asn_application.h>

/* Including external dependencies */
#include "InterRATReportCriteria.h"
#include "InterRATCellInfoList-r6.h"
#include "EUTRA-FrequencyList-r9.h"
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum InterRATMeasurement_r9__interRATMeasurementObjects_PR {
	InterRATMeasurement_r9__interRATMeasurementObjects_PR_NOTHING,	/* No components present */
	InterRATMeasurement_r9__interRATMeasurementObjects_PR_interRATCellInfoList,
	InterRATMeasurement_r9__interRATMeasurementObjects_PR_eutra_FrequencyList
} InterRATMeasurement_r9__interRATMeasurementObjects_PR;

/* Forward declarations */
struct InterRATMeasQuantity_r8;
struct InterRATReportingQuantity_r8;
struct IdleIntervalInfo;

/* InterRATMeasurement-r9 */
typedef struct InterRATMeasurement_r9 {
	struct InterRATMeasurement_r9__interRATMeasurementObjects {
		InterRATMeasurement_r9__interRATMeasurementObjects_PR present;
		union InterRATMeasurement_r9__interRATMeasurementObjects_u {
			InterRATCellInfoList_r6_t	 interRATCellInfoList;
			EUTRA_FrequencyList_r9_t	 eutra_FrequencyList;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *interRATMeasurementObjects;
	struct InterRATMeasQuantity_r8	*interRATMeasQuantity	/* OPTIONAL */;
	struct InterRATReportingQuantity_r8	*interRATReportingQuantity	/* OPTIONAL */;
	InterRATReportCriteria_t	 reportCriteria;
	struct IdleIntervalInfo	*idleIntervalInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterRATMeasurement_r9_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterRATMeasurement_r9;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "InterRATMeasQuantity-r8.h"
#include "InterRATReportingQuantity-r8.h"
#include "IdleIntervalInfo.h"

#endif	/* _InterRATMeasurement_r9_H_ */
#include <asn_internal.h>
