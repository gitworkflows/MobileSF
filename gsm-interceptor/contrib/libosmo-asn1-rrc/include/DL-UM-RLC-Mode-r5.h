/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DL_UM_RLC_Mode_r5_H_
#define	_DL_UM_RLC_Mode_r5_H_


#include <asn_application.h>

/* Including external dependencies */
#include "DL-UM-RLC-LI-size.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DL-UM-RLC-Mode-r5 */
typedef struct DL_UM_RLC_Mode_r5 {
	DL_UM_RLC_LI_size_t	 dl_UM_RLC_LI_size;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_UM_RLC_Mode_r5_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_UM_RLC_Mode_r5;

#ifdef __cplusplus
}
#endif

#endif	/* _DL_UM_RLC_Mode_r5_H_ */
#include <asn_internal.h>
