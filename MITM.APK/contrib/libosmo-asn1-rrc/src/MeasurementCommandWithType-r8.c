/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "MeasurementCommandWithType-r8.h"

static asn_per_constraints_t asn_PER_type_MeasurementCommandWithType_r8_constr_1 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_MeasurementCommandWithType_r8_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MeasurementCommandWithType_r8, choice.setup),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_MeasurementType_r8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"setup"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MeasurementCommandWithType_r8, choice.modify),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modify"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MeasurementCommandWithType_r8, choice.release),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"release"
		},
};
static asn_TYPE_tag2member_t asn_MAP_MeasurementCommandWithType_r8_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* setup at 1681 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* modify at 1682 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* release at 1683 */
};
static asn_CHOICE_specifics_t asn_SPC_MeasurementCommandWithType_r8_specs_1 = {
	sizeof(struct MeasurementCommandWithType_r8),
	offsetof(struct MeasurementCommandWithType_r8, _asn_ctx),
	offsetof(struct MeasurementCommandWithType_r8, present),
	sizeof(((struct MeasurementCommandWithType_r8 *)0)->present),
	asn_MAP_MeasurementCommandWithType_r8_tag2el_1,
	3,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_MeasurementCommandWithType_r8 = {
	"MeasurementCommandWithType-r8",
	"MeasurementCommandWithType-r8",
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
	&asn_PER_type_MeasurementCommandWithType_r8_constr_1,
	asn_MBR_MeasurementCommandWithType_r8_1,
	3,	/* Elements count */
	&asn_SPC_MeasurementCommandWithType_r8_specs_1	/* Additional specs */
};

