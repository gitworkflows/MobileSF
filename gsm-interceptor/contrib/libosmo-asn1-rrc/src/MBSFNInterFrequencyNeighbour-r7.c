/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "MBSFNInterFrequencyNeighbour-r7.h"

static asn_per_constraints_t asn_PER_type_mbsfnServicesNotification_constr_3 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_mbsfnServicesNotification_3[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBSFNInterFrequencyNeighbour_r7__mbsfnServicesNotification, choice.mbsfnServicesNotified),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NULL,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mbsfnServicesNotified"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBSFNInterFrequencyNeighbour_r7__mbsfnServicesNotification, choice.mbsfnServicesNotNotified),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MBSFNservicesNotNotified_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mbsfnServicesNotNotified"
		},
};
static asn_TYPE_tag2member_t asn_MAP_mbsfnServicesNotification_tag2el_3[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mbsfnServicesNotified at 22504 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* mbsfnServicesNotNotified at 22506 */
};
static asn_CHOICE_specifics_t asn_SPC_mbsfnServicesNotification_specs_3 = {
	sizeof(struct MBSFNInterFrequencyNeighbour_r7__mbsfnServicesNotification),
	offsetof(struct MBSFNInterFrequencyNeighbour_r7__mbsfnServicesNotification, _asn_ctx),
	offsetof(struct MBSFNInterFrequencyNeighbour_r7__mbsfnServicesNotification, present),
	sizeof(((struct MBSFNInterFrequencyNeighbour_r7__mbsfnServicesNotification *)0)->present),
	asn_MAP_mbsfnServicesNotification_tag2el_3,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_mbsfnServicesNotification_3 = {
	"mbsfnServicesNotification",
	"mbsfnServicesNotification",
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
	&asn_PER_type_mbsfnServicesNotification_constr_3,
	asn_MBR_mbsfnServicesNotification_3,
	2,	/* Elements count */
	&asn_SPC_mbsfnServicesNotification_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_MBSFNInterFrequencyNeighbour_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MBSFNInterFrequencyNeighbour_r7, mbsfnFrequency),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FrequencyInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mbsfnFrequency"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MBSFNInterFrequencyNeighbour_r7, mbsfnServicesNotification),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_mbsfnServicesNotification_3,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mbsfnServicesNotification"
		},
};
static ber_tlv_tag_t asn_DEF_MBSFNInterFrequencyNeighbour_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_MBSFNInterFrequencyNeighbour_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mbsfnFrequency at 22502 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* mbsfnServicesNotification at 22504 */
};
static asn_SEQUENCE_specifics_t asn_SPC_MBSFNInterFrequencyNeighbour_r7_specs_1 = {
	sizeof(struct MBSFNInterFrequencyNeighbour_r7),
	offsetof(struct MBSFNInterFrequencyNeighbour_r7, _asn_ctx),
	asn_MAP_MBSFNInterFrequencyNeighbour_r7_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_MBSFNInterFrequencyNeighbour_r7 = {
	"MBSFNInterFrequencyNeighbour-r7",
	"MBSFNInterFrequencyNeighbour-r7",
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
	asn_DEF_MBSFNInterFrequencyNeighbour_r7_tags_1,
	sizeof(asn_DEF_MBSFNInterFrequencyNeighbour_r7_tags_1)
		/sizeof(asn_DEF_MBSFNInterFrequencyNeighbour_r7_tags_1[0]), /* 1 */
	asn_DEF_MBSFNInterFrequencyNeighbour_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_MBSFNInterFrequencyNeighbour_r7_tags_1)
		/sizeof(asn_DEF_MBSFNInterFrequencyNeighbour_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_MBSFNInterFrequencyNeighbour_r7_1,
	2,	/* Elements count */
	&asn_SPC_MBSFNInterFrequencyNeighbour_r7_specs_1	/* Additional specs */
};

