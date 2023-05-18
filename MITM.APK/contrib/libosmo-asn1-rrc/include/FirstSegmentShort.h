/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_FirstSegmentShort_H_
#define	_FirstSegmentShort_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SIB-Type.h"
#include "SegCount.h"
#include "SIB-Data-variable.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* FirstSegmentShort */
typedef struct FirstSegmentShort {
	SIB_Type_t	 sib_Type;
	SegCount_t	 seg_Count;
	SIB_Data_variable_t	 sib_Data_variable;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} FirstSegmentShort_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_FirstSegmentShort;

#ifdef __cplusplus
}
#endif

#endif	/* _FirstSegmentShort_H_ */
#include <asn_internal.h>
