/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_RRCConnectionRelease_CCCH_H_
#define	_RRCConnectionRelease_CCCH_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRCConnectionRelease-CCCH-r3-IEs.h"
#include <BIT_STRING.h>
#include "RRCConnectionRelease-CCCH-v690ext-IEs.h"
#include "RRCConnectionRelease-CCCH-v860ext-IEs.h"
#include "RRCConnectionRelease-va40ext-IEs.h"
#include <constr_SEQUENCE.h>
#include "U-RNTI.h"
#include "RRC-TransactionIdentifier.h"
#include "RRCConnectionRelease-CCCH-r4-IEs.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include "RRCConnectionRelease-CCCH-r5-IEs.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RRCConnectionRelease_CCCH_PR {
	RRCConnectionRelease_CCCH_PR_NOTHING,	/* No components present */
	RRCConnectionRelease_CCCH_PR_r3,
	RRCConnectionRelease_CCCH_PR_later_than_r3
} RRCConnectionRelease_CCCH_PR;
typedef enum RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions_PR {
	RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions_PR_NOTHING,	/* No components present */
	RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions_PR_r4,
	RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions_PR_criticalExtensions
} RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions_PR;
typedef enum RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR {
	RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_NOTHING,	/* No components present */
	RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_r5,
	RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR_criticalExtensions
} RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR;

/* Forward declarations */
struct GroupReleaseInformation;

/* RRCConnectionRelease-CCCH */
typedef struct RRCConnectionRelease_CCCH {
	RRCConnectionRelease_CCCH_PR present;
	union RRCConnectionRelease_CCCH_u {
		struct RRCConnectionRelease_CCCH__r3 {
			RRCConnectionRelease_CCCH_r3_IEs_t	 rrcConnectionRelease_CCCH_r3;
			struct RRCConnectionRelease_CCCH__r3__laterNonCriticalExtensions {
				BIT_STRING_t	*rrcConnectionRelease_CCCH_r3_add_ext	/* OPTIONAL */;
				struct RRCConnectionRelease_CCCH__r3__laterNonCriticalExtensions__v690NonCriticalExtensions {
					RRCConnectionRelease_CCCH_v690ext_IEs_t	 rrcConnectionRelease_v690ext;
					struct RRCConnectionRelease_CCCH__r3__laterNonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions {
						RRCConnectionRelease_CCCH_v860ext_IEs_t	 rrcConnectionRelease_v860ext;
						struct RRCConnectionRelease_CCCH__r3__laterNonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions__va40NonCriticalExtensions {
							RRCConnectionRelease_va40ext_IEs_t	 rrcConnectionRelease_va40ext;
							struct RRCConnectionRelease_CCCH__r3__laterNonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions__va40NonCriticalExtensions__nonCriticalExtensions {
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *nonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *va40NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} *v860NonCriticalExtensions;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *v690NonCriticalExtensions;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} *laterNonCriticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} r3;
		struct RRCConnectionRelease_CCCH__later_than_r3 {
			U_RNTI_t	 u_RNTI;
			RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
			struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions {
				RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions_PR present;
				union RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions_u {
					struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__r4 {
						RRCConnectionRelease_CCCH_r4_IEs_t	 rrcConnectionRelease_CCCH_r4;
						struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions {
							BIT_STRING_t	*rrcConnectionRelease_CCCH_r4_add_ext	/* OPTIONAL */;
							struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v690NonCriticalExtensions {
								RRCConnectionRelease_CCCH_v690ext_IEs_t	 rrcConnectionRelease_v690ext;
								struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions {
									RRCConnectionRelease_CCCH_v860ext_IEs_t	 rrcConnectionRelease_v860ext;
									struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions__va40NonCriticalExtensions {
										RRCConnectionRelease_va40ext_IEs_t	 rrcConnectionRelease_va40ext;
										struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__r4__v4d0NonCriticalExtensions__v690NonCriticalExtensions__v860NonCriticalExtensions__va40NonCriticalExtensions__nonCriticalExtensions {
											
											/* Context for parsing across buffer boundaries */
											asn_struct_ctx_t _asn_ctx;
										} *nonCriticalExtensions;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} *va40NonCriticalExtensions;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} *v860NonCriticalExtensions;
								
								/* Context for parsing across buffer boundaries */
								asn_struct_ctx_t _asn_ctx;
							} *v690NonCriticalExtensions;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *v4d0NonCriticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} r4;
					struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions {
						struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__groupIdentity {
							A_SEQUENCE_OF(struct GroupReleaseInformation) list;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} *groupIdentity;
						struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions {
							RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_PR present;
							union RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions_u {
								struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r5 {
									RRCConnectionRelease_CCCH_r5_IEs_t	 rrcConnectionRelease_CCCH_r5;
									BIT_STRING_t	*rrcConnectionRelease_CCCH_r5_add_ext	/* OPTIONAL */;
									struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r5__v690NonCriticalExtensions {
										RRCConnectionRelease_CCCH_v690ext_IEs_t	 rrcConnectionRelease_v690ext;
										struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r5__v690NonCriticalExtensions__v860NonCriticalExtensions {
											RRCConnectionRelease_CCCH_v860ext_IEs_t	 rrcConnectionRelease_v860ext;
											struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r5__v690NonCriticalExtensions__v860NonCriticalExtensions__va40NonCriticalExtensions {
												RRCConnectionRelease_va40ext_IEs_t	 rrcConnectionRelease_va40ext;
												struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__r5__v690NonCriticalExtensions__v860NonCriticalExtensions__va40NonCriticalExtensions__nonCriticalExtensions {
													
													/* Context for parsing across buffer boundaries */
													asn_struct_ctx_t _asn_ctx;
												} *nonCriticalExtensions;
												
												/* Context for parsing across buffer boundaries */
												asn_struct_ctx_t _asn_ctx;
											} *va40NonCriticalExtensions;
											
											/* Context for parsing across buffer boundaries */
											asn_struct_ctx_t _asn_ctx;
										} *v860NonCriticalExtensions;
										
										/* Context for parsing across buffer boundaries */
										asn_struct_ctx_t _asn_ctx;
									} *v690NonCriticalExtensions;
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} r5;
								struct RRCConnectionRelease_CCCH__later_than_r3__criticalExtensions__criticalExtensions__criticalExtensions__criticalExtensions {
									
									/* Context for parsing across buffer boundaries */
									asn_struct_ctx_t _asn_ctx;
								} criticalExtensions;
							} choice;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} criticalExtensions;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} criticalExtensions;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} criticalExtensions;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} later_than_r3;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RRCConnectionRelease_CCCH_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RRCConnectionRelease_CCCH;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "GroupReleaseInformation.h"

#endif	/* _RRCConnectionRelease_CCCH_H_ */
#include <asn_internal.h>
