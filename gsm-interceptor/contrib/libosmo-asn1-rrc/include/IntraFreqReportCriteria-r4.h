/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_IntraFreqReportCriteria_r4_H_
#define	_IntraFreqReportCriteria_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IntraFreqReportingCriteria-r4.h"
#include "PeriodicalWithReportingCellStatus.h"
#include "ReportingCellStatusOpt.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum IntraFreqReportCriteria_r4_PR {
	IntraFreqReportCriteria_r4_PR_NOTHING,	/* No components present */
	IntraFreqReportCriteria_r4_PR_intraFreqReportingCriteria,
	IntraFreqReportCriteria_r4_PR_periodicalReportingCriteria,
	IntraFreqReportCriteria_r4_PR_noReporting
} IntraFreqReportCriteria_r4_PR;

/* IntraFreqReportCriteria-r4 */
typedef struct IntraFreqReportCriteria_r4 {
	IntraFreqReportCriteria_r4_PR present;
	union IntraFreqReportCriteria_r4_u {
		IntraFreqReportingCriteria_r4_t	 intraFreqReportingCriteria;
		PeriodicalWithReportingCellStatus_t	 periodicalReportingCriteria;
		ReportingCellStatusOpt_t	 noReporting;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFreqReportCriteria_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFreqReportCriteria_r4;

#ifdef __cplusplus
}
#endif

#endif	/* _IntraFreqReportCriteria_r4_H_ */
#include <asn_internal.h>
