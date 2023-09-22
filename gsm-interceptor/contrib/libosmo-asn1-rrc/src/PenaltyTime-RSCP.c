/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "PenaltyTime-RSCP.h"

static asn_per_constraints_t asn_PER_type_PenaltyTime_RSCP_constr_1 = {
	{ APC_CONSTRAINED,	 3,  3,  0,  6 }	/* (0..6) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_PenaltyTime_RSCP_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PenaltyTime_RSCP, choice.notUsed),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"notUsed"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PenaltyTime_RSCP, choice.pt10),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TemporaryOffset1,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pt10"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PenaltyTime_RSCP, choice.pt20),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TemporaryOffset1,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pt20"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PenaltyTime_RSCP, choice.pt30),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TemporaryOffset1,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pt30"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PenaltyTime_RSCP, choice.pt40),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TemporaryOffset1,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pt40"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PenaltyTime_RSCP, choice.pt50),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TemporaryOffset1,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pt50"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PenaltyTime_RSCP, choice.pt60),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TemporaryOffset1,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"pt60"
		},
};
static asn_TYPE_tag2member_t asn_MAP_PenaltyTime_RSCP_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* notUsed at 17715 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* pt10 at 17716 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* pt20 at 17717 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* pt30 at 17718 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* pt40 at 17719 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* pt50 at 17720 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* pt60 at 17722 */
};
static asn_CHOICE_specifics_t asn_SPC_PenaltyTime_RSCP_specs_1 = {
	sizeof(struct PenaltyTime_RSCP),
	offsetof(struct PenaltyTime_RSCP, _asn_ctx),
	offsetof(struct PenaltyTime_RSCP, present),
	sizeof(((struct PenaltyTime_RSCP *)0)->present),
	asn_MAP_PenaltyTime_RSCP_tag2el_1,
	7,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_PenaltyTime_RSCP = {
	"PenaltyTime-RSCP",
	"PenaltyTime-RSCP",
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
	&asn_PER_type_PenaltyTime_RSCP_constr_1,
	asn_MBR_PenaltyTime_RSCP_1,
	7,	/* Elements count */
	&asn_SPC_PenaltyTime_RSCP_specs_1	/* Additional specs */
};

