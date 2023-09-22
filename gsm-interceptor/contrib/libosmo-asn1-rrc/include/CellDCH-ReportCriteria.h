/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_CellDCH_ReportCriteria_H_
#define	_CellDCH_ReportCriteria_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IntraFreqReportingCriteria.h"
#include "PeriodicalReportingCriteria.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CellDCH_ReportCriteria_PR {
	CellDCH_ReportCriteria_PR_NOTHING,	/* No components present */
	CellDCH_ReportCriteria_PR_intraFreqReportingCriteria,
	CellDCH_ReportCriteria_PR_periodicalReportingCriteria
} CellDCH_ReportCriteria_PR;

/* CellDCH-ReportCriteria */
typedef struct CellDCH_ReportCriteria {
	CellDCH_ReportCriteria_PR present;
	union CellDCH_ReportCriteria_u {
		IntraFreqReportingCriteria_t	 intraFreqReportingCriteria;
		PeriodicalReportingCriteria_t	 periodicalReportingCriteria;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellDCH_ReportCriteria_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellDCH_ReportCriteria;

#ifdef __cplusplus
}
#endif

#endif	/* _CellDCH_ReportCriteria_H_ */
#include <asn_internal.h>
