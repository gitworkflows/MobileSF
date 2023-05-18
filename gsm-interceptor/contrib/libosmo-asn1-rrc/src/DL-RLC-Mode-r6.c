/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DL-RLC-Mode-r6.h"

static asn_per_constraints_t asn_PER_type_DL_RLC_Mode_r6_constr_1 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_DL_RLC_Mode_r6_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_RLC_Mode_r6, choice.dl_AM_RLC_Mode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_AM_RLC_Mode_r5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-AM-RLC-Mode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_RLC_Mode_r6, choice.dl_UM_RLC_Mode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_UM_RLC_Mode_r6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-UM-RLC-Mode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_RLC_Mode_r6, choice.dl_TM_RLC_Mode),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_TM_RLC_Mode,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dl-TM-RLC-Mode"
		},
};
static asn_TYPE_tag2member_t asn_MAP_DL_RLC_Mode_r6_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-AM-RLC-Mode at 3605 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dl-UM-RLC-Mode at 3606 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* dl-TM-RLC-Mode at 3608 */
};
static asn_CHOICE_specifics_t asn_SPC_DL_RLC_Mode_r6_specs_1 = {
	sizeof(struct DL_RLC_Mode_r6),
	offsetof(struct DL_RLC_Mode_r6, _asn_ctx),
	offsetof(struct DL_RLC_Mode_r6, present),
	sizeof(((struct DL_RLC_Mode_r6 *)0)->present),
	asn_MAP_DL_RLC_Mode_r6_tag2el_1,
	3,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_DL_RLC_Mode_r6 = {
	"DL-RLC-Mode-r6",
	"DL-RLC-Mode-r6",
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
	&asn_PER_type_DL_RLC_Mode_r6_constr_1,
	asn_MBR_DL_RLC_Mode_r6_1,
	3,	/* Elements count */
	&asn_SPC_DL_RLC_Mode_r6_specs_1	/* Additional specs */
};

