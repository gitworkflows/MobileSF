/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_PRACH_PreambleForEnhancedUplink_H_
#define	_PRACH_PreambleForEnhancedUplink_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AvailableSignatures.h"
#include <BOOLEAN.h>
#include "PreambleScramblingCodeWordNumber.h"
#include "AvailableSubChannelNumbers.h"
#include "PrimaryCPICH-TX-Power.h"
#include "ConstantValue.h"
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PRACH_Partitioning_r7;
struct PersistenceScalingFactorList;
struct AC_To_ASC_MappingTable;
struct PRACH_PowerOffset;
struct RACH_TransmissionParameters;
struct AICH_Info;

/* PRACH-PreambleForEnhancedUplink */
typedef struct PRACH_PreambleForEnhancedUplink {
	AvailableSignatures_t	*availableSignatures	/* OPTIONAL */;
	BOOLEAN_t	 e_ai_Indication;
	PreambleScramblingCodeWordNumber_t	*preambleScramblingCodeWordNumber	/* OPTIONAL */;
	AvailableSubChannelNumbers_t	*availableSubChannelNumbers	/* OPTIONAL */;
	struct PRACH_Partitioning_r7	*prach_Partitioning	/* OPTIONAL */;
	struct PersistenceScalingFactorList	*persistenceScalingFactorList	/* OPTIONAL */;
	struct AC_To_ASC_MappingTable	*ac_To_ASC_MappingTable	/* OPTIONAL */;
	PrimaryCPICH_TX_Power_t	*primaryCPICH_TX_Power	/* OPTIONAL */;
	ConstantValue_t	*constantValue	/* OPTIONAL */;
	struct PRACH_PowerOffset	*prach_PowerOffset	/* OPTIONAL */;
	struct RACH_TransmissionParameters	*rach_TransmissionParameters	/* OPTIONAL */;
	struct AICH_Info	*aich_Info	/* OPTIONAL */;
	long	 powerOffsetPp_e;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PRACH_PreambleForEnhancedUplink_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PRACH_PreambleForEnhancedUplink;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PRACH-Partitioning-r7.h"
#include "PersistenceScalingFactorList.h"
#include "AC-To-ASC-MappingTable.h"
#include "PRACH-PowerOffset.h"
#include "RACH-TransmissionParameters.h"
#include "AICH-Info.h"

#endif	/* _PRACH_PreambleForEnhancedUplink_H_ */
#include <asn_internal.h>
