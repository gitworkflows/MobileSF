/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SecondaryCellMIMOparametersFDD_v950ext_H_
#define	_SecondaryCellMIMOparametersFDD_v950ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SecondaryCellMIMOparametersFDD_v950ext__precodingWeightSetRestriction {
	SecondaryCellMIMOparametersFDD_v950ext__precodingWeightSetRestriction_true	= 0
} e_SecondaryCellMIMOparametersFDD_v950ext__precodingWeightSetRestriction;

/* SecondaryCellMIMOparametersFDD-v950ext */
typedef struct SecondaryCellMIMOparametersFDD_v950ext {
	long	*precodingWeightSetRestriction	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SecondaryCellMIMOparametersFDD_v950ext_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_precodingWeightSetRestriction_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_SecondaryCellMIMOparametersFDD_v950ext;

#ifdef __cplusplus
}
#endif

#endif	/* _SecondaryCellMIMOparametersFDD_v950ext_H_ */
#include <asn_internal.h>
