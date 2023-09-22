/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_IntraFrequencyMeasurement_r10_H_
#define	_IntraFrequencyMeasurement_r10_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IntraFreqCellInfoList_r10;
struct IntraFreqCellInfoListOnSecULFreq;
struct IntraFreqMeasQuantity;
struct IntraFreqReportingQuantity;
struct MeasurementValidity;
struct IntraFreqReportCriteria_r9;

/* IntraFrequencyMeasurement-r10 */
typedef struct IntraFrequencyMeasurement_r10 {
	struct IntraFreqCellInfoList_r10	*intraFreqCellInfoList	/* OPTIONAL */;
	struct IntraFreqCellInfoListOnSecULFreq	*intraFreqCellInfoListOnSecULFreq	/* OPTIONAL */;
	struct IntraFreqMeasQuantity	*intraFreqMeasQuantity	/* OPTIONAL */;
	struct IntraFreqReportingQuantity	*intraFreqReportingQuantity	/* OPTIONAL */;
	struct MeasurementValidity	*measurementValidity	/* OPTIONAL */;
	struct IntraFreqReportCriteria_r9	*reportCriteria	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFrequencyMeasurement_r10_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFrequencyMeasurement_r10;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "IntraFreqCellInfoList-r10.h"
#include "IntraFreqCellInfoListOnSecULFreq.h"
#include "IntraFreqMeasQuantity.h"
#include "IntraFreqReportingQuantity.h"
#include "MeasurementValidity.h"
#include "IntraFreqReportCriteria-r9.h"

#endif	/* _IntraFrequencyMeasurement_r10_H_ */
#include <asn_internal.h>
