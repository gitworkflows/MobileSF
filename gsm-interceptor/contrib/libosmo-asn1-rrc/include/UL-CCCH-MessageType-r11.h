/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Class-definitions"
 * 	found in "../asn/Class-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UL_CCCH_MessageType_r11_H_
#define	_UL_CCCH_MessageType_r11_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CellUpdateFDD-r11.h"
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_CCCH_MessageType_r11_PR {
	UL_CCCH_MessageType_r11_PR_NOTHING,	/* No components present */
	UL_CCCH_MessageType_r11_PR_cellUpdate,
	UL_CCCH_MessageType_r11_PR_spare3,
	UL_CCCH_MessageType_r11_PR_spare2,
	UL_CCCH_MessageType_r11_PR_spare1
} UL_CCCH_MessageType_r11_PR;

/* UL-CCCH-MessageType-r11 */
typedef struct UL_CCCH_MessageType_r11 {
	UL_CCCH_MessageType_r11_PR present;
	union UL_CCCH_MessageType_r11_u {
		CellUpdateFDD_r11_t	 cellUpdate;
		NULL_t	 spare3;
		NULL_t	 spare2;
		NULL_t	 spare1;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_CCCH_MessageType_r11_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_CCCH_MessageType_r11;

#ifdef __cplusplus
}
#endif

#endif	/* _UL_CCCH_MessageType_r11_H_ */
#include <asn_internal.h>
