/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_MBMS_NeighbouringCellSCCPCHList_v770ext_H_
#define	_MBMS_NeighbouringCellSCCPCHList_v770ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MBMS_NeighbouringCellSCCPCH_v770ext;

/* MBMS-NeighbouringCellSCCPCHList-v770ext */
typedef struct MBMS_NeighbouringCellSCCPCHList_v770ext {
	A_SEQUENCE_OF(struct MBMS_NeighbouringCellSCCPCH_v770ext) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMS_NeighbouringCellSCCPCHList_v770ext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMS_NeighbouringCellSCCPCHList_v770ext;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MBMS-NeighbouringCellSCCPCH-v770ext.h"

#endif	/* _MBMS_NeighbouringCellSCCPCHList_v770ext_H_ */
#include <asn_internal.h>
