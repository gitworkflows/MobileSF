/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PDSCH_SysInfoList_VHCR_r7_H_
#define	_PDSCH_SysInfoList_VHCR_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PDSCH_SysInfo_VHCR_r7;

/* PDSCH-SysInfoList-VHCR-r7 */
typedef struct PDSCH_SysInfoList_VHCR_r7 {
	A_SEQUENCE_OF(struct PDSCH_SysInfo_VHCR_r7) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDSCH_SysInfoList_VHCR_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PDSCH_SysInfoList_VHCR_r7;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PDSCH-SysInfo-VHCR-r7.h"

#endif	/* _PDSCH_SysInfoList_VHCR_r7_H_ */
#include <asn_internal.h>
