/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SecondaryCCPCHInfo_MBMS_r7_H_
#define	_SecondaryCCPCHInfo_MBMS_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SecondaryScramblingCode.h"
#include <BOOLEAN.h>
#include "SF256-AndCodeNumber.h"
#include "TimingOffset.h"
#include <NULL.h>
#include <NativeInteger.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#include "CommonTimeslotInfoMBMS.h"
#include "DownlinkTimeslotsCodes-r7.h"
#include <NativeEnumerated.h>
#include "DownlinkTimeslotsCodes-VHCR.h"
#include "DownlinkTimeslotsCodes-LCR-r4.h"
#include "TimeSlotLCR-ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_PR {
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_PR_NOTHING,	/* No components present */
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_PR_fdd,
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_PR_tdd384,
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_PR_tdd768,
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_PR_tdd128
} SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_PR;
typedef enum SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation_PR {
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation_PR_NOTHING,	/* No components present */
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation_PR_modQPSK,
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation_PR_mod16QAM
} SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation_PR;
typedef enum SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384__modulation {
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384__modulation_modQPSK	= 0,
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384__modulation_mod16QAM	= 1
} e_SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384__modulation;
typedef enum SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768__modulation {
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768__modulation_modQPSK	= 0,
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768__modulation_mod16QAM	= 1
} e_SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768__modulation;
typedef enum SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128__modulation {
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128__modulation_modQPSK	= 0,
	SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128__modulation_mod16QAM	= 1
} e_SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128__modulation;

/* SecondaryCCPCHInfo-MBMS-r7 */
typedef struct SecondaryCCPCHInfo_MBMS_r7 {
	struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo {
		SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_PR present;
		union SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo_u {
			struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd {
				SecondaryScramblingCode_t	*secondaryScramblingCode	/* OPTIONAL */;
				BOOLEAN_t	 sttd_Indicator;
				SF256_AndCodeNumber_t	 sf_AndCodeNumber;
				TimingOffset_t	 timingOffset	/* DEFAULT 0 */;
				struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation {
					SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation_PR present;
					union SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__fdd__modulation_u {
						NULL_t	 modQPSK;
						long	 mod16QAM;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} *modulation;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd384 {
				CommonTimeslotInfoMBMS_t	 commonTimeslotInfoMBMS;
				DownlinkTimeslotsCodes_r7_t	 downlinkTimeslotsCodes;
				long	 modulation;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd384;
			struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd768 {
				CommonTimeslotInfoMBMS_t	 commonTimeslotInfoMBMS;
				DownlinkTimeslotsCodes_VHCR_t	 downlinkTimeslotsCodes;
				long	 modulation;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd768;
			struct SecondaryCCPCHInfo_MBMS_r7__modeSpecificInfo__tdd128 {
				CommonTimeslotInfoMBMS_t	 commonTimeslotInfoMBMS;
				DownlinkTimeslotsCodes_LCR_r4_t	 downlinkTimeslotsCodes;
				TimeSlotLCR_ext_t	*mbsfnSpecialTimeSlot	/* OPTIONAL */;
				long	 modulation;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd128;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SecondaryCCPCHInfo_MBMS_r7_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_modulation_14;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_modulation_20;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_modulation_27;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_SecondaryCCPCHInfo_MBMS_r7;

#ifdef __cplusplus
}
#endif

#endif	/* _SecondaryCCPCHInfo_MBMS_r7_H_ */
#include <asn_internal.h>
