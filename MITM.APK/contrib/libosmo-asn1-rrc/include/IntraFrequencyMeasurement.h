/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_IntraFrequencyMeasurement_H_
#define	_IntraFrequencyMeasurement_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IntraFreqCellInfoList;
struct IntraFreqMeasQuantity;
struct IntraFreqReportingQuantity;
struct MeasurementValidity;
struct IntraFreqReportCriteria;

/* IntraFrequencyMeasurement */
typedef struct IntraFrequencyMeasurement {
	struct IntraFreqCellInfoList	*intraFreqCellInfoList	/* OPTIONAL */;
	struct IntraFreqMeasQuantity	*intraFreqMeasQuantity	/* OPTIONAL */;
	struct IntraFreqReportingQuantity	*intraFreqReportingQuantity	/* OPTIONAL */;
	struct MeasurementValidity	*measurementValidity	/* OPTIONAL */;
	struct IntraFreqReportCriteria	*reportCriteria	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFrequencyMeasurement_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFrequencyMeasurement;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "IntraFreqCellInfoList.h"
#include "IntraFreqMeasQuantity.h"
#include "IntraFreqReportingQuantity.h"
#include "MeasurementValidity.h"
#include "IntraFreqReportCriteria.h"

#endif	/* _IntraFrequencyMeasurement_H_ */
#include <asn_internal.h>
