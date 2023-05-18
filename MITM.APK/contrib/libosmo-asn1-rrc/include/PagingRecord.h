/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PagingRecord_H_
#define	_PagingRecord_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PagingCause.h"
#include "CN-DomainIdentity.h"
#include "CN-PagedUE-Identity.h"
#include <constr_SEQUENCE.h>
#include "U-RNTI.h"
#include "PagingRecordTypeID.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PagingRecord_PR {
	PagingRecord_PR_NOTHING,	/* No components present */
	PagingRecord_PR_cn_Identity,
	PagingRecord_PR_utran_Identity
} PagingRecord_PR;

/* PagingRecord */
typedef struct PagingRecord {
	PagingRecord_PR present;
	union PagingRecord_u {
		struct PagingRecord__cn_Identity {
			PagingCause_t	 pagingCause;
			CN_DomainIdentity_t	 cn_DomainIdentity;
			CN_PagedUE_Identity_t	 cn_pagedUE_Identity;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} cn_Identity;
		struct PagingRecord__utran_Identity {
			U_RNTI_t	 u_RNTI;
			struct PagingRecord__utran_Identity__cn_OriginatedPage_connectedMode_UE {
				PagingCause_t	 pagingCause;
				CN_DomainIdentity_t	 cn_DomainIdentity;
				PagingRecordTypeID_t	 pagingRecordTypeID;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *cn_OriginatedPage_connectedMode_UE;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} utran_Identity;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PagingRecord_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PagingRecord;

#ifdef __cplusplus
}
#endif

#endif	/* _PagingRecord_H_ */
#include <asn_internal.h>
