/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DL_InformationPerRL_List_r5bis_H_
#define	_DL_InformationPerRL_List_r5bis_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DL_InformationPerRL_r5bis;

/* DL-InformationPerRL-List-r5bis */
typedef struct DL_InformationPerRL_List_r5bis {
	A_SEQUENCE_OF(struct DL_InformationPerRL_r5bis) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_InformationPerRL_List_r5bis_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_InformationPerRL_List_r5bis;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "DL-InformationPerRL-r5bis.h"

#endif	/* _DL_InformationPerRL_List_r5bis_H_ */
#include <asn_internal.h>
