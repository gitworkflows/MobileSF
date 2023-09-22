/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_OngoingMeasRep_r10_H_
#define	_OngoingMeasRep_r10_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementIdentity.h"
#include "MeasurementCommandWithType-r10.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MeasurementReportingMode;
struct AdditionalMeasurementID_List;

/* OngoingMeasRep-r10 */
typedef struct OngoingMeasRep_r10 {
	MeasurementIdentity_t	 measurementIdentity;
	MeasurementCommandWithType_r10_t	 measurementCommandWithType;
	struct MeasurementReportingMode	*measurementReportingMode	/* OPTIONAL */;
	struct AdditionalMeasurementID_List	*additionalMeasurementID_List	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} OngoingMeasRep_r10_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OngoingMeasRep_r10;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MeasurementReportingMode.h"
#include "AdditionalMeasurementID-List.h"

#endif	/* _OngoingMeasRep_r10_H_ */
#include <asn_internal.h>
