/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "PRACH-PreambleForEnhancedUplink.h"

static int
memb_powerOffsetPp_e_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= -5 && value <= 10)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		_ASN_CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_per_constraints_t asn_PER_memb_powerOffsetPp_e_constr_14 = {
	{ APC_CONSTRAINED,	 4,  4, -5,  10 }	/* (-5..10) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_PRACH_PreambleForEnhancedUplink_1[] = {
	{ ATF_POINTER, 1, offsetof(struct PRACH_PreambleForEnhancedUplink, availableSignatures),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AvailableSignatures,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"availableSignatures"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_PreambleForEnhancedUplink, e_ai_Indication),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-ai-Indication"
		},
	{ ATF_POINTER, 10, offsetof(struct PRACH_PreambleForEnhancedUplink, preambleScramblingCodeWordNumber),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PreambleScramblingCodeWordNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"preambleScramblingCodeWordNumber"
		},
	{ ATF_POINTER, 9, offsetof(struct PRACH_PreambleForEnhancedUplink, availableSubChannelNumbers),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AvailableSubChannelNumbers,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"availableSubChannelNumbers"
		},
	{ ATF_POINTER, 8, offsetof(struct PRACH_PreambleForEnhancedUplink, prach_Partitioning),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_PRACH_Partitioning_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"prach-Partitioning"
		},
	{ ATF_POINTER, 7, offsetof(struct PRACH_PreambleForEnhancedUplink, persistenceScalingFactorList),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PersistenceScalingFactorList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"persistenceScalingFactorList"
		},
	{ ATF_POINTER, 6, offsetof(struct PRACH_PreambleForEnhancedUplink, ac_To_ASC_MappingTable),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AC_To_ASC_MappingTable,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ac-To-ASC-MappingTable"
		},
	{ ATF_POINTER, 5, offsetof(struct PRACH_PreambleForEnhancedUplink, primaryCPICH_TX_Power),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_TX_Power,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"primaryCPICH-TX-Power"
		},
	{ ATF_POINTER, 4, offsetof(struct PRACH_PreambleForEnhancedUplink, constantValue),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ConstantValue,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"constantValue"
		},
	{ ATF_POINTER, 3, offsetof(struct PRACH_PreambleForEnhancedUplink, prach_PowerOffset),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PRACH_PowerOffset,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"prach-PowerOffset"
		},
	{ ATF_POINTER, 2, offsetof(struct PRACH_PreambleForEnhancedUplink, rach_TransmissionParameters),
		(ASN_TAG_CLASS_CONTEXT | (10 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RACH_TransmissionParameters,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rach-TransmissionParameters"
		},
	{ ATF_POINTER, 1, offsetof(struct PRACH_PreambleForEnhancedUplink, aich_Info),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AICH_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"aich-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_PreambleForEnhancedUplink, powerOffsetPp_e),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		memb_powerOffsetPp_e_constraint_1,
		&asn_PER_memb_powerOffsetPp_e_constr_14,
		0,
		"powerOffsetPp-e"
		},
};
static int asn_MAP_PRACH_PreambleForEnhancedUplink_oms_1[] = { 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
static ber_tlv_tag_t asn_DEF_PRACH_PreambleForEnhancedUplink_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_PRACH_PreambleForEnhancedUplink_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* availableSignatures at 10248 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* e-ai-Indication at 10249 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* preambleScramblingCodeWordNumber at 10250 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* availableSubChannelNumbers at 10251 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* prach-Partitioning at 10252 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* persistenceScalingFactorList at 10253 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* ac-To-ASC-MappingTable at 10254 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* primaryCPICH-TX-Power at 10255 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* constantValue at 10256 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 }, /* prach-PowerOffset at 10257 */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 10, 0, 0 }, /* rach-TransmissionParameters at 10258 */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 11, 0, 0 }, /* aich-Info at 10259 */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 12, 0, 0 } /* powerOffsetPp-e at 10260 */
};
static asn_SEQUENCE_specifics_t asn_SPC_PRACH_PreambleForEnhancedUplink_specs_1 = {
	sizeof(struct PRACH_PreambleForEnhancedUplink),
	offsetof(struct PRACH_PreambleForEnhancedUplink, _asn_ctx),
	asn_MAP_PRACH_PreambleForEnhancedUplink_tag2el_1,
	13,	/* Count of tags in the map */
	asn_MAP_PRACH_PreambleForEnhancedUplink_oms_1,	/* Optional members */
	11, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_PRACH_PreambleForEnhancedUplink = {
	"PRACH-PreambleForEnhancedUplink",
	"PRACH-PreambleForEnhancedUplink",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_PRACH_PreambleForEnhancedUplink_tags_1,
	sizeof(asn_DEF_PRACH_PreambleForEnhancedUplink_tags_1)
		/sizeof(asn_DEF_PRACH_PreambleForEnhancedUplink_tags_1[0]), /* 1 */
	asn_DEF_PRACH_PreambleForEnhancedUplink_tags_1,	/* Same as above */
	sizeof(asn_DEF_PRACH_PreambleForEnhancedUplink_tags_1)
		/sizeof(asn_DEF_PRACH_PreambleForEnhancedUplink_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_PRACH_PreambleForEnhancedUplink_1,
	13,	/* Elements count */
	&asn_SPC_PRACH_PreambleForEnhancedUplink_specs_1	/* Additional specs */
};

