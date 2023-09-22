/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_DL_CommonTransChInfo_r4_H_
#define	_DL_CommonTransChInfo_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DL_CommonTransChInfo_r4__modeSpecificInfo_PR {
	DL_CommonTransChInfo_r4__modeSpecificInfo_PR_NOTHING,	/* No components present */
	DL_CommonTransChInfo_r4__modeSpecificInfo_PR_fdd,
	DL_CommonTransChInfo_r4__modeSpecificInfo_PR_tdd
} DL_CommonTransChInfo_r4__modeSpecificInfo_PR;
typedef enum DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters_PR {
	DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters_PR_NOTHING,	/* No components present */
	DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters_PR_dl_DCH_TFCS,
	DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters_PR_sameAsUL
} DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters_PR;

/* Forward declarations */
struct TFCS;
struct IndividualDL_CCTrCH_InfoList;

/* DL-CommonTransChInfo-r4 */
typedef struct DL_CommonTransChInfo_r4 {
	struct TFCS	*sccpch_TFCS	/* OPTIONAL */;
	struct DL_CommonTransChInfo_r4__modeSpecificInfo {
		DL_CommonTransChInfo_r4__modeSpecificInfo_PR present;
		union DL_CommonTransChInfo_r4__modeSpecificInfo_u {
			struct DL_CommonTransChInfo_r4__modeSpecificInfo__fdd {
				struct DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters {
					DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters_PR present;
					union DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters_u {
						struct DL_CommonTransChInfo_r4__modeSpecificInfo__fdd__dl_Parameters__dl_DCH_TFCS {
							struct TFCS	*tfcs	/* OPTIONAL */;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} dl_DCH_TFCS;
						NULL_t	 sameAsUL;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *dl_Parameters;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct DL_CommonTransChInfo_r4__modeSpecificInfo__tdd {
				struct IndividualDL_CCTrCH_InfoList	*individualDL_CCTrCH_InfoList	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DL_CommonTransChInfo_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DL_CommonTransChInfo_r4;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "TFCS.h"
#include "IndividualDL-CCTrCH-InfoList.h"

#endif	/* _DL_CommonTransChInfo_r4_H_ */
#include <asn_internal.h>
