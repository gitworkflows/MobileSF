/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "SimultaneousSCCPCH-DPCH-Reception.h"

static asn_per_constraints_t asn_PER_type_SimultaneousSCCPCH_DPCH_Reception_constr_1 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_supported_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SimultaneousSCCPCH_DPCH_Reception__supported, maxNoSCCPCH_RL),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MaxNoSCCPCH_RL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"maxNoSCCPCH-RL"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SimultaneousSCCPCH_DPCH_Reception__supported, simultaneousSCCPCH_DPCH_DPDCH_Reception),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"simultaneousSCCPCH-DPCH-DPDCH-Reception"
		},
};
static ber_tlv_tag_t asn_DEF_supported_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_supported_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* maxNoSCCPCH-RL at 2252 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* simultaneousSCCPCH-DPCH-DPDCH-Reception at 2257 */
};
static asn_SEQUENCE_specifics_t asn_SPC_supported_specs_3 = {
	sizeof(struct SimultaneousSCCPCH_DPCH_Reception__supported),
	offsetof(struct SimultaneousSCCPCH_DPCH_Reception__supported, _asn_ctx),
	asn_MAP_supported_tag2el_3,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_supported_3 = {
	"supported",
	"supported",
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
	asn_DEF_supported_tags_3,
	sizeof(asn_DEF_supported_tags_3)
		/sizeof(asn_DEF_supported_tags_3[0]) - 1, /* 1 */
	asn_DEF_supported_tags_3,	/* Same as above */
	sizeof(asn_DEF_supported_tags_3)
		/sizeof(asn_DEF_supported_tags_3[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_supported_3,
	2,	/* Elements count */
	&asn_SPC_supported_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_SimultaneousSCCPCH_DPCH_Reception_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct SimultaneousSCCPCH_DPCH_Reception, choice.notSupported),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"notSupported"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct SimultaneousSCCPCH_DPCH_Reception, choice.supported),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_supported_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"supported"
		},
};
static asn_TYPE_tag2member_t asn_MAP_SimultaneousSCCPCH_DPCH_Reception_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* notSupported at 2250 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* supported at 2252 */
};
static asn_CHOICE_specifics_t asn_SPC_SimultaneousSCCPCH_DPCH_Reception_specs_1 = {
	sizeof(struct SimultaneousSCCPCH_DPCH_Reception),
	offsetof(struct SimultaneousSCCPCH_DPCH_Reception, _asn_ctx),
	offsetof(struct SimultaneousSCCPCH_DPCH_Reception, present),
	sizeof(((struct SimultaneousSCCPCH_DPCH_Reception *)0)->present),
	asn_MAP_SimultaneousSCCPCH_DPCH_Reception_tag2el_1,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_SimultaneousSCCPCH_DPCH_Reception = {
	"SimultaneousSCCPCH-DPCH-Reception",
	"SimultaneousSCCPCH-DPCH-Reception",
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
	&asn_PER_type_SimultaneousSCCPCH_DPCH_Reception_constr_1,
	asn_MBR_SimultaneousSCCPCH_DPCH_Reception_1,
	2,	/* Elements count */
	&asn_SPC_SimultaneousSCCPCH_DPCH_Reception_specs_1	/* Additional specs */
};

