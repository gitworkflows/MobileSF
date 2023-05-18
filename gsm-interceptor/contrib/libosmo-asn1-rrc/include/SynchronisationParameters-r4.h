/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SynchronisationParameters_r4_H_
#define	_SynchronisationParameters_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include "FPACH-Info-r4.h"
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SynchronisationParameters_r4__sync_UL_CodesBitmap {
	SynchronisationParameters_r4__sync_UL_CodesBitmap_code7	= 0,
	SynchronisationParameters_r4__sync_UL_CodesBitmap_code6	= 1,
	SynchronisationParameters_r4__sync_UL_CodesBitmap_code5	= 2,
	SynchronisationParameters_r4__sync_UL_CodesBitmap_code4	= 3,
	SynchronisationParameters_r4__sync_UL_CodesBitmap_code3	= 4,
	SynchronisationParameters_r4__sync_UL_CodesBitmap_code2	= 5,
	SynchronisationParameters_r4__sync_UL_CodesBitmap_code1	= 6,
	SynchronisationParameters_r4__sync_UL_CodesBitmap_code0	= 7
} e_SynchronisationParameters_r4__sync_UL_CodesBitmap;

/* Forward declarations */
struct SYNC_UL_Procedure_r4;

/* SynchronisationParameters-r4 */
typedef struct SynchronisationParameters_r4 {
	BIT_STRING_t	 sync_UL_CodesBitmap;
	FPACH_Info_r4_t	 fpach_Info;
	long	 prxUpPCHdes;
	struct SYNC_UL_Procedure_r4	*sync_UL_Procedure	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SynchronisationParameters_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SynchronisationParameters_r4;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "SYNC-UL-Procedure-r4.h"

#endif	/* _SynchronisationParameters_r4_H_ */
#include <asn_internal.h>
