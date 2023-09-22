/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_E_DCH_ReconfigurationInfo_SecULFrequency_H_
#define	_E_DCH_ReconfigurationInfo_SecULFrequency_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct E_DCH_RL_InfoNewSecServingCell;
struct E_DCH_RL_InfoOtherCell_SecULFreq;

/* E-DCH-ReconfigurationInfo-SecULFrequency */
typedef struct E_DCH_ReconfigurationInfo_SecULFrequency {
	struct E_DCH_RL_InfoNewSecServingCell	*e_DCH_RL_InfoNewSecServingCell	/* OPTIONAL */;
	struct E_DCH_ReconfigurationInfo_SecULFrequency__e_DCH_RL_InfoOtherCellList_SecULFreq {
		A_SEQUENCE_OF(struct E_DCH_RL_InfoOtherCell_SecULFreq) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *e_DCH_RL_InfoOtherCellList_SecULFreq;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E_DCH_ReconfigurationInfo_SecULFrequency_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E_DCH_ReconfigurationInfo_SecULFrequency;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "E-DCH-RL-InfoNewSecServingCell.h"
#include "E-DCH-RL-InfoOtherCell-SecULFreq.h"

#endif	/* _E_DCH_ReconfigurationInfo_SecULFrequency_H_ */
#include <asn_internal.h>
