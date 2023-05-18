/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_TGP_Sequence_H_
#define	_TGP_Sequence_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TGPSI.h"
#include <NULL.h>
#include "TGCFN.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TGP_Sequence__tgps_Status_PR {
	TGP_Sequence__tgps_Status_PR_NOTHING,	/* No components present */
	TGP_Sequence__tgps_Status_PR_activate,
	TGP_Sequence__tgps_Status_PR_deactivate
} TGP_Sequence__tgps_Status_PR;

/* Forward declarations */
struct TGPS_ConfigurationParams;

/* TGP-Sequence */
typedef struct TGP_Sequence {
	TGPSI_t	 tgpsi;
	struct TGP_Sequence__tgps_Status {
		TGP_Sequence__tgps_Status_PR present;
		union TGP_Sequence__tgps_Status_u {
			struct TGP_Sequence__tgps_Status__activate {
				TGCFN_t	 tgcfn;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} activate;
			NULL_t	 deactivate;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} tgps_Status;
	struct TGPS_ConfigurationParams	*tgps_ConfigurationParams	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TGP_Sequence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TGP_Sequence;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "TGPS-ConfigurationParams.h"

#endif	/* _TGP_Sequence_H_ */
#include <asn_internal.h>
