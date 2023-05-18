/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UE-InternalEventParam.h"

static asn_per_constraints_t asn_PER_type_UE_InternalEventParam_constr_1 = {
	{ APC_CONSTRAINED,	 3,  3,  0,  6 }	/* (0..6) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_UE_InternalEventParam_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UE_InternalEventParam, choice.event6a),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_6AB_Event,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"event6a"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_InternalEventParam, choice.event6b),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_6AB_Event,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"event6b"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_InternalEventParam, choice.event6c),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeToTrigger,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"event6c"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_InternalEventParam, choice.event6d),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeToTrigger,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"event6d"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_InternalEventParam, choice.event6e),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeToTrigger,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"event6e"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_InternalEventParam, choice.event6f),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_6FG_Event,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"event6f"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_InternalEventParam, choice.event6g),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_6FG_Event,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"event6g"
		},
};
static asn_TYPE_tag2member_t asn_MAP_UE_InternalEventParam_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* event6a at 18491 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* event6b at 18492 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* event6c at 18493 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* event6d at 18494 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* event6e at 18495 */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* event6f at 18496 */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* event6g at 18498 */
};
static asn_CHOICE_specifics_t asn_SPC_UE_InternalEventParam_specs_1 = {
	sizeof(struct UE_InternalEventParam),
	offsetof(struct UE_InternalEventParam, _asn_ctx),
	offsetof(struct UE_InternalEventParam, present),
	sizeof(((struct UE_InternalEventParam *)0)->present),
	asn_MAP_UE_InternalEventParam_tag2el_1,
	7,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_UE_InternalEventParam = {
	"UE-InternalEventParam",
	"UE-InternalEventParam",
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
	&asn_PER_type_UE_InternalEventParam_constr_1,
	asn_MBR_UE_InternalEventParam_1,
	7,	/* Elements count */
	&asn_SPC_UE_InternalEventParam_specs_1	/* Additional specs */
};

