/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DL-AddReconfTransChInformation-r11.h"

static asn_per_constraints_t asn_PER_type_tfs_SignallingMode_constr_3 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_tfs_SignallingMode_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_AddReconfTransChInformation_r11__tfs_SignallingMode, choice.explicit_config),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TransportFormatSet,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"explicit-config"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_AddReconfTransChInformation_r11__tfs_SignallingMode, choice.sameAsULTrCH),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_TransportChannelIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"sameAsULTrCH"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_AddReconfTransChInformation_r11__tfs_SignallingMode, choice.hsdsch),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HSDSCH_Info_r11,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"hsdsch"
		},
};
static asn_TYPE_tag2member_t asn_MAP_tfs_SignallingMode_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* explicit-config at 5107 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* sameAsULTrCH at 5108 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* hsdsch at 5110 */
};
static asn_CHOICE_specifics_t asn_SPC_tfs_SignallingMode_specs_3 = {
	sizeof(struct DL_AddReconfTransChInformation_r11__tfs_SignallingMode),
	offsetof(struct DL_AddReconfTransChInformation_r11__tfs_SignallingMode, _asn_ctx),
	offsetof(struct DL_AddReconfTransChInformation_r11__tfs_SignallingMode, present),
	sizeof(((struct DL_AddReconfTransChInformation_r11__tfs_SignallingMode *)0)->present),
	asn_MAP_tfs_SignallingMode_tag2el_3,
	3,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tfs_SignallingMode_3 = {
	"tfs-SignallingMode",
	"tfs-SignallingMode",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_tfs_SignallingMode_constr_3,
	asn_MBR_tfs_SignallingMode_3,
	3,	/* Elements count */
	&asn_SPC_tfs_SignallingMode_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_DL_AddReconfTransChInformation_r11_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_AddReconfTransChInformation_r11, dl_TransportChannelType),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_DL_TrCH_TypeId1_r5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-TransportChannelType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_AddReconfTransChInformation_r11, tfs_SignallingMode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_tfs_SignallingMode_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tfs-SignallingMode"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_AddReconfTransChInformation_r11, dch_QualityTarget),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_QualityTarget,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dch-QualityTarget"
		},
};
static int asn_MAP_DL_AddReconfTransChInformation_r11_oms_1[] = { 2 };
static ber_tlv_tag_t asn_DEF_DL_AddReconfTransChInformation_r11_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_DL_AddReconfTransChInformation_r11_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-TransportChannelType at 5105 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tfs-SignallingMode at 5107 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* dch-QualityTarget at 5111 */
};
static asn_SEQUENCE_specifics_t asn_SPC_DL_AddReconfTransChInformation_r11_specs_1 = {
	sizeof(struct DL_AddReconfTransChInformation_r11),
	offsetof(struct DL_AddReconfTransChInformation_r11, _asn_ctx),
	asn_MAP_DL_AddReconfTransChInformation_r11_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_DL_AddReconfTransChInformation_r11_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_DL_AddReconfTransChInformation_r11 = {
	"DL-AddReconfTransChInformation-r11",
	"DL-AddReconfTransChInformation-r11",
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
	asn_DEF_DL_AddReconfTransChInformation_r11_tags_1,
	sizeof(asn_DEF_DL_AddReconfTransChInformation_r11_tags_1)
		/sizeof(asn_DEF_DL_AddReconfTransChInformation_r11_tags_1[0]), /* 1 */
	asn_DEF_DL_AddReconfTransChInformation_r11_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_AddReconfTransChInformation_r11_tags_1)
		/sizeof(asn_DEF_DL_AddReconfTransChInformation_r11_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_DL_AddReconfTransChInformation_r11_1,
	3,	/* Elements count */
	&asn_SPC_DL_AddReconfTransChInformation_r11_specs_1	/* Additional specs */
};

