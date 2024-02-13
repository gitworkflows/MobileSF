/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SYNC_UL_Procedure_r4_H_
#define	_SYNC_UL_Procedure_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SYNC_UL_Procedure_r4__max_SYNC_UL_Transmissions {
	SYNC_UL_Procedure_r4__max_SYNC_UL_Transmissions_tr1	= 0,
	SYNC_UL_Procedure_r4__max_SYNC_UL_Transmissions_tr2	= 1,
	SYNC_UL_Procedure_r4__max_SYNC_UL_Transmissions_tr4	= 2,
	SYNC_UL_Procedure_r4__max_SYNC_UL_Transmissions_tr8	= 3
} e_SYNC_UL_Procedure_r4__max_SYNC_UL_Transmissions;

/* SYNC-UL-Procedure-r4 */
typedef struct SYNC_UL_Procedure_r4 {
	long	 max_SYNC_UL_Transmissions;
	long	 powerRampStep;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SYNC_UL_Procedure_r4_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_max_SYNC_UL_Transmissions_2;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_SYNC_UL_Procedure_r4;

#ifdef __cplusplus
}
#endif

#endif	/* _SYNC_UL_Procedure_r4_H_ */
#include <asn_internal.h>
