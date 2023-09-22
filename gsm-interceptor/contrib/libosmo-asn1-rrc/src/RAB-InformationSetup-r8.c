/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "RAB-InformationSetup-r8.h"

static asn_TYPE_member_t asn_MBR_RAB_InformationSetup_r8_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RAB_InformationSetup_r8, rab_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RAB_Info_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rab-Info"
		},
	{ ATF_POINTER, 2, offsetof(struct RAB_InformationSetup_r8, cs_HSPA_Information),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CS_HSPA_Information,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cs-HSPA-Information"
		},
	{ ATF_POINTER, 1, offsetof(struct RAB_InformationSetup_r8, rab_InfoReplace),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RAB_InfoReplace,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rab-InfoReplace"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RAB_InformationSetup_r8, rb_InformationSetupList),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RB_InformationSetupList_r8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"rb-InformationSetupList"
		},
};
static int asn_MAP_RAB_InformationSetup_r8_oms_1[] = { 1, 2 };
static ber_tlv_tag_t asn_DEF_RAB_InformationSetup_r8_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_RAB_InformationSetup_r8_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rab-Info at 3990 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cs-HSPA-Information at 3991 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* rab-InfoReplace at 3992 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* rb-InformationSetupList at 3994 */
};
static asn_SEQUENCE_specifics_t asn_SPC_RAB_InformationSetup_r8_specs_1 = {
	sizeof(struct RAB_InformationSetup_r8),
	offsetof(struct RAB_InformationSetup_r8, _asn_ctx),
	asn_MAP_RAB_InformationSetup_r8_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_RAB_InformationSetup_r8_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RAB_InformationSetup_r8 = {
	"RAB-InformationSetup-r8",
	"RAB-InformationSetup-r8",
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
	asn_DEF_RAB_InformationSetup_r8_tags_1,
	sizeof(asn_DEF_RAB_InformationSetup_r8_tags_1)
		/sizeof(asn_DEF_RAB_InformationSetup_r8_tags_1[0]), /* 1 */
	asn_DEF_RAB_InformationSetup_r8_tags_1,	/* Same as above */
	sizeof(asn_DEF_RAB_InformationSetup_r8_tags_1)
		/sizeof(asn_DEF_RAB_InformationSetup_r8_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RAB_InformationSetup_r8_1,
	4,	/* Elements count */
	&asn_SPC_RAB_InformationSetup_r8_specs_1	/* Additional specs */
};

