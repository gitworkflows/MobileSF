/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_GANSS_SAT_Info_Almanac_GLOkpList_H_
#define	_GANSS_SAT_Info_Almanac_GLOkpList_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GANSS_SAT_Info_Almanac_GLOkp;

/* GANSS-SAT-Info-Almanac-GLOkpList */
typedef struct GANSS_SAT_Info_Almanac_GLOkpList {
	A_SEQUENCE_OF(struct GANSS_SAT_Info_Almanac_GLOkp) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GANSS_SAT_Info_Almanac_GLOkpList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GANSS_SAT_Info_Almanac_GLOkpList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "GANSS-SAT-Info-Almanac-GLOkp.h"

#endif	/* _GANSS_SAT_Info_Almanac_GLOkpList_H_ */
#include <asn_internal.h>
