/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MeasurementControl_r11_IEs_H_
#define	_MeasurementControl_r11_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementIdentity-r9.h"
#include "MeasurementCommand-r11.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MeasurementReportingMode;
struct AdditionalMeasurementID_List_r9;
struct CellDCHMeasOccasionInfo_TDD128_r9;
struct DPCH_CompressedModeStatusInfo_r10;

/* MeasurementControl-r11-IEs */
typedef struct MeasurementControl_r11_IEs {
	MeasurementIdentity_r9_t	 measurementIdentity;
	MeasurementCommand_r11_t	 measurementCommand;
	struct MeasurementReportingMode	*measurementReportingMode	/* OPTIONAL */;
	struct AdditionalMeasurementID_List_r9	*additionalMeasurementList	/* OPTIONAL */;
	struct CellDCHMeasOccasionInfo_TDD128_r9	*cellDCHMeasOccasionInfo_TDD128	/* OPTIONAL */;
	struct DPCH_CompressedModeStatusInfo_r10	*dpch_CompressedModeStatusInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementControl_r11_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementControl_r11_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MeasurementReportingMode.h"
#include "AdditionalMeasurementID-List-r9.h"
#include "CellDCHMeasOccasionInfo-TDD128-r9.h"
#include "DPCH-CompressedModeStatusInfo-r10.h"

#endif	/* _MeasurementControl_r11_IEs_H_ */
#include <asn_internal.h>
