/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_LoggedMeasServingCellMeas_TDD128_H_
#define	_LoggedMeasServingCellMeas_TDD128_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CellIdentity.h"
#include "PrimaryCCPCH-RSCP.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* LoggedMeasServingCellMeas-TDD128 */
typedef struct LoggedMeasServingCellMeas_TDD128 {
	CellIdentity_t	 cellIdentity;
	PrimaryCCPCH_RSCP_t	 primaryCCPCH_RSCP;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LoggedMeasServingCellMeas_TDD128_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LoggedMeasServingCellMeas_TDD128;

#ifdef __cplusplus
}
#endif

#endif	/* _LoggedMeasServingCellMeas_TDD128_H_ */
#include <asn_internal.h>
