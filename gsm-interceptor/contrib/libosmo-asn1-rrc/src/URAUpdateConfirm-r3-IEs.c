/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "URAUpdateConfirm-r3-IEs.h"

static asn_TYPE_member_t asn_MBR_URAUpdateConfirm_r3_IEs_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct URAUpdateConfirm_r3_IEs, rrc_TransactionIdentifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_TransactionIdentifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rrc-TransactionIdentifier"
		},
	{ ATF_POINTER, 4, offsetof(struct URAUpdateConfirm_r3_IEs, integrityProtectionModeInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntegrityProtectionModeInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"integrityProtectionModeInfo"
		},
	{ ATF_POINTER, 3, offsetof(struct URAUpdateConfirm_r3_IEs, cipheringModeInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CipheringModeInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cipheringModeInfo"
		},
	{ ATF_POINTER, 2, offsetof(struct URAUpdateConfirm_r3_IEs, new_U_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_U_RNTI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"new-U-RNTI"
		},
	{ ATF_POINTER, 1, offsetof(struct URAUpdateConfirm_r3_IEs, new_C_RNTI),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_C_RNTI,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"new-C-RNTI"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct URAUpdateConfirm_r3_IEs, rrc_StateIndicator),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_StateIndicator,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rrc-StateIndicator"
		},
	{ ATF_POINTER, 4, offsetof(struct URAUpdateConfirm_r3_IEs, utran_DRX_CycleLengthCoeff),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTRAN_DRX_CycleLengthCoefficient,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"utran-DRX-CycleLengthCoeff"
		},
	{ ATF_POINTER, 3, offsetof(struct URAUpdateConfirm_r3_IEs, cn_InformationInfo),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CN_InformationInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cn-InformationInfo"
		},
	{ ATF_POINTER, 2, offsetof(struct URAUpdateConfirm_r3_IEs, ura_Identity),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_URA_Identity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ura-Identity"
		},
	{ ATF_POINTER, 1, offsetof(struct URAUpdateConfirm_r3_IEs, dl_CounterSynchronisationInfo),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CounterSynchronisationInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-CounterSynchronisationInfo"
		},
};
static int asn_MAP_URAUpdateConfirm_r3_IEs_oms_1[] = { 1, 2, 3, 4, 6, 7, 8, 9 };
static ber_tlv_tag_t asn_DEF_URAUpdateConfirm_r3_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_URAUpdateConfirm_r3_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrc-TransactionIdentifier at 10850 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* integrityProtectionModeInfo at 10851 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* cipheringModeInfo at 10852 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* new-U-RNTI at 10853 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* new-C-RNTI at 10854 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* rrc-StateIndicator at 10855 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* utran-DRX-CycleLengthCoeff at 10856 */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* cn-InformationInfo at 10858 */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* ura-Identity at 10860 */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 } /* dl-CounterSynchronisationInfo at 10862 */
};
static asn_SEQUENCE_specifics_t asn_SPC_URAUpdateConfirm_r3_IEs_specs_1 = {
	sizeof(struct URAUpdateConfirm_r3_IEs),
	offsetof(struct URAUpdateConfirm_r3_IEs, _asn_ctx),
	asn_MAP_URAUpdateConfirm_r3_IEs_tag2el_1,
	10,	/* Count of tags in the map */
	asn_MAP_URAUpdateConfirm_r3_IEs_oms_1,	/* Optional members */
	8, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_URAUpdateConfirm_r3_IEs = {
	"URAUpdateConfirm-r3-IEs",
	"URAUpdateConfirm-r3-IEs",
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
	asn_DEF_URAUpdateConfirm_r3_IEs_tags_1,
	sizeof(asn_DEF_URAUpdateConfirm_r3_IEs_tags_1)
		/sizeof(asn_DEF_URAUpdateConfirm_r3_IEs_tags_1[0]), /* 1 */
	asn_DEF_URAUpdateConfirm_r3_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_URAUpdateConfirm_r3_IEs_tags_1)
		/sizeof(asn_DEF_URAUpdateConfirm_r3_IEs_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_URAUpdateConfirm_r3_IEs_1,
	10,	/* Elements count */
	&asn_SPC_URAUpdateConfirm_r3_IEs_specs_1	/* Additional specs */
};

