/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PrimaryCCPCH_InfoPostTDD_LCR_r4_H_
#define	_PrimaryCCPCH_InfoPostTDD_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include "CellParametersID.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PrimaryCCPCH-InfoPostTDD-LCR-r4 */
typedef struct PrimaryCCPCH_InfoPostTDD_LCR_r4 {
	BOOLEAN_t	 tstd_Indicator;
	CellParametersID_t	 cellParametersID;
	BOOLEAN_t	 sctd_Indicator;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PrimaryCCPCH_InfoPostTDD_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PrimaryCCPCH_InfoPostTDD_LCR_r4;

#ifdef __cplusplus
}
#endif

#endif	/* _PrimaryCCPCH_InfoPostTDD_LCR_r4_H_ */
#include <asn_internal.h>
