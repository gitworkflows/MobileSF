/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_CellAccessRestriction_v870ext_H_
#define	_CellAccessRestriction_v870ext_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CellAccessRestriction_v870ext__cellReservedForCSG {
	CellAccessRestriction_v870ext__cellReservedForCSG_true	= 0
} e_CellAccessRestriction_v870ext__cellReservedForCSG;

/* CellAccessRestriction-v870ext */
typedef struct CellAccessRestriction_v870ext {
	long	*cellReservedForCSG	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellAccessRestriction_v870ext_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_cellReservedForCSG_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_CellAccessRestriction_v870ext;

#ifdef __cplusplus
}
#endif

#endif	/* _CellAccessRestriction_v870ext_H_ */
#include <asn_internal.h>
