/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_IntraFreqCellInfoList_H_
#define	_IntraFreqCellInfoList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RemovedIntraFreqCellList;
struct NewIntraFreqCellList;
struct CellsForIntraFreqMeasList;

/* IntraFreqCellInfoList */
typedef struct IntraFreqCellInfoList {
	struct RemovedIntraFreqCellList	*removedIntraFreqCellList	/* OPTIONAL */;
	struct NewIntraFreqCellList	*newIntraFreqCellList	/* OPTIONAL */;
	struct CellsForIntraFreqMeasList	*cellsForIntraFreqMeasList	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFreqCellInfoList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFreqCellInfoList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RemovedIntraFreqCellList.h"
#include "NewIntraFreqCellList.h"
#include "CellsForIntraFreqMeasList.h"

#endif	/* _IntraFreqCellInfoList_H_ */
#include <asn_internal.h>
