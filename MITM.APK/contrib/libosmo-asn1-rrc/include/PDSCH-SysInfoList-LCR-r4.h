/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PDSCH_SysInfoList_LCR_r4_H_
#define	_PDSCH_SysInfoList_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PDSCH_SysInfo_LCR_r4;

/* PDSCH-SysInfoList-LCR-r4 */
typedef struct PDSCH_SysInfoList_LCR_r4 {
	A_SEQUENCE_OF(struct PDSCH_SysInfo_LCR_r4) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDSCH_SysInfoList_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PDSCH_SysInfoList_LCR_r4;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PDSCH-SysInfo-LCR-r4.h"

#endif	/* _PDSCH_SysInfoList_LCR_r4_H_ */
#include <asn_internal.h>
