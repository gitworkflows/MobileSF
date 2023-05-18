/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "PRACH-Definition-LCR-r4.h"

static asn_TYPE_member_t asn_MBR_PRACH_Definition_LCR_r4_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_Definition_LCR_r4, timeslot),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber_PRACH_LCR_r4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeslot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_Definition_LCR_r4, prach_ChanCodes_LCR),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PRACH_ChanCodes_LCR_r4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"prach-ChanCodes-LCR"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_Definition_LCR_r4, midambleShiftAndBurstType),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftAndBurstType_LCR_r4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleShiftAndBurstType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_Definition_LCR_r4, fpach_Info),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FPACH_Info_r4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fpach-Info"
		},
};
static ber_tlv_tag_t asn_DEF_PRACH_Definition_LCR_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_PRACH_Definition_LCR_r4_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeslot at 10195 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* prach-ChanCodes-LCR at 10196 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* midambleShiftAndBurstType at 10197 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* fpach-Info at 10199 */
};
static asn_SEQUENCE_specifics_t asn_SPC_PRACH_Definition_LCR_r4_specs_1 = {
	sizeof(struct PRACH_Definition_LCR_r4),
	offsetof(struct PRACH_Definition_LCR_r4, _asn_ctx),
	asn_MAP_PRACH_Definition_LCR_r4_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_PRACH_Definition_LCR_r4 = {
	"PRACH-Definition-LCR-r4",
	"PRACH-Definition-LCR-r4",
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
	asn_DEF_PRACH_Definition_LCR_r4_tags_1,
	sizeof(asn_DEF_PRACH_Definition_LCR_r4_tags_1)
		/sizeof(asn_DEF_PRACH_Definition_LCR_r4_tags_1[0]), /* 1 */
	asn_DEF_PRACH_Definition_LCR_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_PRACH_Definition_LCR_r4_tags_1)
		/sizeof(asn_DEF_PRACH_Definition_LCR_r4_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_PRACH_Definition_LCR_r4_1,
	4,	/* Elements count */
	&asn_SPC_PRACH_Definition_LCR_r4_specs_1	/* Additional specs */
};

