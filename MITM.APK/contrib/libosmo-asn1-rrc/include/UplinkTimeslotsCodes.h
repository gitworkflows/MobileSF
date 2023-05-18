/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_UplinkTimeslotsCodes_H_
#define	_UplinkTimeslotsCodes_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include "IndividualTimeslotInfo.h"
#include "UL-TS-ChannelisationCodeList.h"
#include <NULL.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UplinkTimeslotsCodes__moreTimeslots_PR {
	UplinkTimeslotsCodes__moreTimeslots_PR_NOTHING,	/* No components present */
	UplinkTimeslotsCodes__moreTimeslots_PR_noMore,
	UplinkTimeslotsCodes__moreTimeslots_PR_additionalTimeslots
} UplinkTimeslotsCodes__moreTimeslots_PR;
typedef enum UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR {
	UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR_NOTHING,	/* No components present */
	UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR_consecutive,
	UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR_timeslotList
} UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR;

/* Forward declarations */
struct UplinkAdditionalTimeslots;

/* UplinkTimeslotsCodes */
typedef struct UplinkTimeslotsCodes {
	BOOLEAN_t	 dynamicSFusage;
	IndividualTimeslotInfo_t	 firstIndividualTimeslotInfo;
	UL_TS_ChannelisationCodeList_t	 ul_TS_ChannelisationCodeList;
	struct UplinkTimeslotsCodes__moreTimeslots {
		UplinkTimeslotsCodes__moreTimeslots_PR present;
		union UplinkTimeslotsCodes__moreTimeslots_u {
			NULL_t	 noMore;
			struct UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots {
				UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots_PR present;
				union UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots_u {
					struct UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots__consecutive {
						long	 numAdditionalTimeslots;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} consecutive;
					struct UplinkTimeslotsCodes__moreTimeslots__additionalTimeslots__timeslotList {
						A_SEQUENCE_OF(struct UplinkAdditionalTimeslots) list;
						
						/* Context for parsing across buffer boundaries */
						asn_struct_ctx_t _asn_ctx;
					} timeslotList;
				} choice;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} additionalTimeslots;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} moreTimeslots;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UplinkTimeslotsCodes_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UplinkTimeslotsCodes;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "UplinkAdditionalTimeslots.h"

#endif	/* _UplinkTimeslotsCodes_H_ */
#include <asn_internal.h>
