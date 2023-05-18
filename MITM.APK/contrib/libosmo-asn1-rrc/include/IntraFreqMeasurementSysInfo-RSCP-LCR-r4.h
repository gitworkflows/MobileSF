/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_IntraFreqMeasurementSysInfo_RSCP_LCR_r4_H_
#define	_IntraFreqMeasurementSysInfo_RSCP_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementIdentity.h"
#include "MaxReportedCellsOnRACH.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IntraFreqCellInfoSI_List_RSCP_LCR_r4;
struct IntraFreqMeasQuantity;
struct IntraFreqReportingQuantityForRACH;
struct ReportingInfoForCellDCH_LCR_r4;

/* IntraFreqMeasurementSysInfo-RSCP-LCR-r4 */
typedef struct IntraFreqMeasurementSysInfo_RSCP_LCR_r4 {
	MeasurementIdentity_t	*intraFreqMeasurementID	/* DEFAULT 1 */;
	struct IntraFreqCellInfoSI_List_RSCP_LCR_r4	*intraFreqCellInfoSI_List	/* OPTIONAL */;
	struct IntraFreqMeasQuantity	*intraFreqMeasQuantity	/* OPTIONAL */;
	struct IntraFreqReportingQuantityForRACH	*intraFreqReportingQuantityForRACH	/* OPTIONAL */;
	MaxReportedCellsOnRACH_t	*maxReportedCellsOnRACH	/* OPTIONAL */;
	struct ReportingInfoForCellDCH_LCR_r4	*reportingInfoForCellDCH	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFreqMeasurementSysInfo_RSCP_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFreqMeasurementSysInfo_RSCP_LCR_r4;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "IntraFreqCellInfoSI-List-RSCP-LCR-r4.h"
#include "IntraFreqMeasQuantity.h"
#include "IntraFreqReportingQuantityForRACH.h"
#include "ReportingInfoForCellDCH-LCR-r4.h"

#endif	/* _IntraFreqMeasurementSysInfo_RSCP_LCR_r4_H_ */
#include <asn_internal.h>
