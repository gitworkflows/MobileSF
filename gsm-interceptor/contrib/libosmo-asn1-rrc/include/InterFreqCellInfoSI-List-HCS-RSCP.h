/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_InterFreqCellInfoSI_List_HCS_RSCP_H_
#define	_InterFreqCellInfoSI_List_HCS_RSCP_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RemovedInterFreqCellList;
struct NewInterFreqCellSI_List_HCS_RSCP;

/* InterFreqCellInfoSI-List-HCS-RSCP */
typedef struct InterFreqCellInfoSI_List_HCS_RSCP {
	struct RemovedInterFreqCellList	*removedInterFreqCellList	/* OPTIONAL */;
	struct NewInterFreqCellSI_List_HCS_RSCP	*newInterFreqCellList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterFreqCellInfoSI_List_HCS_RSCP_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterFreqCellInfoSI_List_HCS_RSCP;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RemovedInterFreqCellList.h"
#include "NewInterFreqCellSI-List-HCS-RSCP.h"

#endif	/* _InterFreqCellInfoSI_List_HCS_RSCP_H_ */
#include <asn_internal.h>
