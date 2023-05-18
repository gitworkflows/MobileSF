/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "F-TPICH-InfoOtherCell.h"

static asn_per_constraints_t asn_PER_type_f_tpich_Info_constr_3 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_f_tpich_Info_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct F_TPICH_InfoOtherCell__f_tpich_Info, choice.f_tpich_Information),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_F_TPICH_Information,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"f-tpich-Information"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct F_TPICH_InfoOtherCell__f_tpich_Info, choice.releaseIndicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"releaseIndicator"
		},
};
static asn_TYPE_tag2member_t asn_MAP_f_tpich_Info_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* f-tpich-Information at 8721 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* releaseIndicator at 8722 */
};
static asn_CHOICE_specifics_t asn_SPC_f_tpich_Info_specs_3 = {
	sizeof(struct F_TPICH_InfoOtherCell__f_tpich_Info),
	offsetof(struct F_TPICH_InfoOtherCell__f_tpich_Info, _asn_ctx),
	offsetof(struct F_TPICH_InfoOtherCell__f_tpich_Info, present),
	sizeof(((struct F_TPICH_InfoOtherCell__f_tpich_Info *)0)->present),
	asn_MAP_f_tpich_Info_tag2el_3,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_f_tpich_Info_3 = {
	"f-tpich-Info",
	"f-tpich-Info",
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
	&asn_PER_type_f_tpich_Info_constr_3,
	asn_MBR_f_tpich_Info_3,
	2,	/* Elements count */
	&asn_SPC_f_tpich_Info_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_F_TPICH_InfoOtherCell_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct F_TPICH_InfoOtherCell, primaryCPICH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PrimaryCPICH_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"primaryCPICH-Info"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct F_TPICH_InfoOtherCell, f_tpich_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_f_tpich_Info_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"f-tpich-Info"
		},
};
static ber_tlv_tag_t asn_DEF_F_TPICH_InfoOtherCell_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_F_TPICH_InfoOtherCell_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* primaryCPICH-Info at 8719 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* f-tpich-Info at 8721 */
};
static asn_SEQUENCE_specifics_t asn_SPC_F_TPICH_InfoOtherCell_specs_1 = {
	sizeof(struct F_TPICH_InfoOtherCell),
	offsetof(struct F_TPICH_InfoOtherCell, _asn_ctx),
	asn_MAP_F_TPICH_InfoOtherCell_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_F_TPICH_InfoOtherCell = {
	"F-TPICH-InfoOtherCell",
	"F-TPICH-InfoOtherCell",
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
	asn_DEF_F_TPICH_InfoOtherCell_tags_1,
	sizeof(asn_DEF_F_TPICH_InfoOtherCell_tags_1)
		/sizeof(asn_DEF_F_TPICH_InfoOtherCell_tags_1[0]), /* 1 */
	asn_DEF_F_TPICH_InfoOtherCell_tags_1,	/* Same as above */
	sizeof(asn_DEF_F_TPICH_InfoOtherCell_tags_1)
		/sizeof(asn_DEF_F_TPICH_InfoOtherCell_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_F_TPICH_InfoOtherCell_1,
	2,	/* Elements count */
	&asn_SPC_F_TPICH_InfoOtherCell_specs_1	/* Additional specs */
};

