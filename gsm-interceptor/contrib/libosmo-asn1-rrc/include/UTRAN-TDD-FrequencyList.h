/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UTRAN_TDD_FrequencyList_H_
#define	_UTRAN_TDD_FrequencyList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct UTRAN_TDD_Frequency;

/* UTRAN-TDD-FrequencyList */
typedef struct UTRAN_TDD_FrequencyList {
	A_SEQUENCE_OF(struct UTRAN_TDD_Frequency) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UTRAN_TDD_FrequencyList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UTRAN_TDD_FrequencyList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "UTRAN-TDD-Frequency.h"

#endif	/* _UTRAN_TDD_FrequencyList_H_ */
#include <asn_internal.h>
