/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "CellChangeOrderFromUTRAN-r3-IEs.h"

static asn_TYPE_member_t asn_MBR_CellChangeOrderFromUTRAN_r3_IEs_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CellChangeOrderFromUTRAN_r3_IEs, rrc_TransactionIdentifier),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RRC_TransactionIdentifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rrc-TransactionIdentifier"
		},
	{ ATF_POINTER, 3, offsetof(struct CellChangeOrderFromUTRAN_r3_IEs, dummy),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IntegrityProtectionModeInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dummy"
		},
	{ ATF_POINTER, 2, offsetof(struct CellChangeOrderFromUTRAN_r3_IEs, activationTime),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ActivationTime,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"activationTime"
		},
	{ ATF_POINTER, 1, offsetof(struct CellChangeOrderFromUTRAN_r3_IEs, rab_InformationList),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RAB_InformationList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rab-InformationList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellChangeOrderFromUTRAN_r3_IEs, interRAT_TargetCellDescription),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRAT_TargetCellDescription,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"interRAT-TargetCellDescription"
		},
};
static int asn_MAP_CellChangeOrderFromUTRAN_r3_IEs_oms_1[] = { 1, 2, 3 };
static ber_tlv_tag_t asn_DEF_CellChangeOrderFromUTRAN_r3_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_CellChangeOrderFromUTRAN_r3_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rrc-TransactionIdentifier at 1109 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dummy at 1112 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* activationTime at 1113 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* rab-InformationList at 1117 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* interRAT-TargetCellDescription at 1119 */
};
static asn_SEQUENCE_specifics_t asn_SPC_CellChangeOrderFromUTRAN_r3_IEs_specs_1 = {
	sizeof(struct CellChangeOrderFromUTRAN_r3_IEs),
	offsetof(struct CellChangeOrderFromUTRAN_r3_IEs, _asn_ctx),
	asn_MAP_CellChangeOrderFromUTRAN_r3_IEs_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_CellChangeOrderFromUTRAN_r3_IEs_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_CellChangeOrderFromUTRAN_r3_IEs = {
	"CellChangeOrderFromUTRAN-r3-IEs",
	"CellChangeOrderFromUTRAN-r3-IEs",
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
	asn_DEF_CellChangeOrderFromUTRAN_r3_IEs_tags_1,
	sizeof(asn_DEF_CellChangeOrderFromUTRAN_r3_IEs_tags_1)
		/sizeof(asn_DEF_CellChangeOrderFromUTRAN_r3_IEs_tags_1[0]), /* 1 */
	asn_DEF_CellChangeOrderFromUTRAN_r3_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_CellChangeOrderFromUTRAN_r3_IEs_tags_1)
		/sizeof(asn_DEF_CellChangeOrderFromUTRAN_r3_IEs_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_CellChangeOrderFromUTRAN_r3_IEs_1,
	5,	/* Elements count */
	&asn_SPC_CellChangeOrderFromUTRAN_r3_IEs_specs_1	/* Additional specs */
};

