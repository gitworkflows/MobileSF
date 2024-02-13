/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "SFN-SFN-ObsTimeDifference.h"

static asn_per_constraints_t asn_PER_type_SFN_SFN_ObsTimeDifference_constr_1 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_SFN_SFN_ObsTimeDifference_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SFN_SFN_ObsTimeDifference, choice.type1),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SFN_SFN_ObsTimeDifference1,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"type1"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SFN_SFN_ObsTimeDifference, choice.type2),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SFN_SFN_ObsTimeDifference2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"type2"
		},
};
static asn_TYPE_tag2member_t asn_MAP_SFN_SFN_ObsTimeDifference_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* type1 at 18129 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* type2 at 18131 */
};
static asn_CHOICE_specifics_t asn_SPC_SFN_SFN_ObsTimeDifference_specs_1 = {
	sizeof(struct SFN_SFN_ObsTimeDifference),
	offsetof(struct SFN_SFN_ObsTimeDifference, _asn_ctx),
	offsetof(struct SFN_SFN_ObsTimeDifference, present),
	sizeof(((struct SFN_SFN_ObsTimeDifference *)0)->present),
	asn_MAP_SFN_SFN_ObsTimeDifference_tag2el_1,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_SFN_SFN_ObsTimeDifference = {
	"SFN-SFN-ObsTimeDifference",
	"SFN-SFN-ObsTimeDifference",
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
	&asn_PER_type_SFN_SFN_ObsTimeDifference_constr_1,
	asn_MBR_SFN_SFN_ObsTimeDifference_1,
	2,	/* Elements count */
	&asn_SPC_SFN_SFN_ObsTimeDifference_specs_1	/* Additional specs */
};

