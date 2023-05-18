/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#ifndef	_SecurityModeCommand_r3_IEs_H_
#define	_SecurityModeCommand_r3_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-TransactionIdentifier.h"
#include "SecurityCapability.h"
#include "CN-DomainIdentity.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CipheringModeInfo;
struct IntegrityProtectionModeInfo;
struct InterRAT_UE_SecurityCapList;

/* SecurityModeCommand-r3-IEs */
typedef struct SecurityModeCommand_r3_IEs {
	RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
	SecurityCapability_t	 securityCapability;
	struct CipheringModeInfo	*cipheringModeInfo	/* OPTIONAL */;
	struct IntegrityProtectionModeInfo	*integrityProtectionModeInfo	/* OPTIONAL */;
	CN_DomainIdentity_t	 cn_DomainIdentity;
	struct InterRAT_UE_SecurityCapList	*ue_SystemSpecificSecurityCap	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SecurityModeCommand_r3_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SecurityModeCommand_r3_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CipheringModeInfo.h"
#include "IntegrityProtectionModeInfo.h"
#include "InterRAT-UE-SecurityCapList.h"

#endif	/* _SecurityModeCommand_r3_IEs_H_ */
#include <asn_internal.h>
