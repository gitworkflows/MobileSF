/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_NonUsedFreq2aParameterList_r10_H_
#define	_NonUsedFreq2aParameterList_r10_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NonUsedFreq2aParameter_r10;

/* NonUsedFreq2aParameterList-r10 */
typedef struct NonUsedFreq2aParameterList_r10 {
	A_SEQUENCE_OF(struct NonUsedFreq2aParameter_r10) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NonUsedFreq2aParameterList_r10_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NonUsedFreq2aParameterList_r10;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NonUsedFreq2aParameter-r10.h"

#endif	/* _NonUsedFreq2aParameterList_r10_H_ */
#include <asn_internal.h>
