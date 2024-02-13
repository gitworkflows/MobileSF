/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "PRACH-PowerOffset.h"

static asn_TYPE_member_t asn_MBR_PRACH_PowerOffset_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_PowerOffset, powerRampStep),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PowerRampStep,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"powerRampStep"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_PowerOffset, preambleRetransMax),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PreambleRetransMax,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"preambleRetransMax"
		},
};
static ber_tlv_tag_t asn_DEF_PRACH_PowerOffset_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_PRACH_PowerOffset_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* powerRampStep at 10243 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* preambleRetransMax at 10245 */
};
static asn_SEQUENCE_specifics_t asn_SPC_PRACH_PowerOffset_specs_1 = {
	sizeof(struct PRACH_PowerOffset),
	offsetof(struct PRACH_PowerOffset, _asn_ctx),
	asn_MAP_PRACH_PowerOffset_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_PRACH_PowerOffset = {
	"PRACH-PowerOffset",
	"PRACH-PowerOffset",
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
	asn_DEF_PRACH_PowerOffset_tags_1,
	sizeof(asn_DEF_PRACH_PowerOffset_tags_1)
		/sizeof(asn_DEF_PRACH_PowerOffset_tags_1[0]), /* 1 */
	asn_DEF_PRACH_PowerOffset_tags_1,	/* Same as above */
	sizeof(asn_DEF_PRACH_PowerOffset_tags_1)
		/sizeof(asn_DEF_PRACH_PowerOffset_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_PRACH_PowerOffset_1,
	2,	/* Elements count */
	&asn_SPC_PRACH_PowerOffset_specs_1	/* Additional specs */
};

