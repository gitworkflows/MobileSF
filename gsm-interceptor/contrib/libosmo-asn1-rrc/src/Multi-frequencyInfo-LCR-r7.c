/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "Multi-frequencyInfo-LCR-r7.h"

static asn_TYPE_member_t asn_MBR_Multi_frequencyInfo_LCR_r7_1[] = {
	{ ATF_POINTER, 3, offsetof(struct Multi_frequencyInfo_LCR_r7, secondFrequencyInfo),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FrequencyInfoTDD,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"secondFrequencyInfo"
		},
	{ ATF_POINTER, 2, offsetof(struct Multi_frequencyInfo_LCR_r7, fPachFrequencyInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FrequencyInfoTDD,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fPachFrequencyInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct Multi_frequencyInfo_LCR_r7, upPCHpositionInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UpPCHposition_LCR,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"upPCHpositionInfo"
		},
};
static int asn_MAP_Multi_frequencyInfo_LCR_r7_oms_1[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_Multi_frequencyInfo_LCR_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_Multi_frequencyInfo_LCR_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* secondFrequencyInfo at 9726 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* fPachFrequencyInfo at 9727 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* upPCHpositionInfo at 9729 */
};
static asn_SEQUENCE_specifics_t asn_SPC_Multi_frequencyInfo_LCR_r7_specs_1 = {
	sizeof(struct Multi_frequencyInfo_LCR_r7),
	offsetof(struct Multi_frequencyInfo_LCR_r7, _asn_ctx),
	asn_MAP_Multi_frequencyInfo_LCR_r7_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_Multi_frequencyInfo_LCR_r7_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Multi_frequencyInfo_LCR_r7 = {
	"Multi-frequencyInfo-LCR-r7",
	"Multi-frequencyInfo-LCR-r7",
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
	asn_DEF_Multi_frequencyInfo_LCR_r7_tags_1,
	sizeof(asn_DEF_Multi_frequencyInfo_LCR_r7_tags_1)
		/sizeof(asn_DEF_Multi_frequencyInfo_LCR_r7_tags_1[0]), /* 1 */
	asn_DEF_Multi_frequencyInfo_LCR_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_Multi_frequencyInfo_LCR_r7_tags_1)
		/sizeof(asn_DEF_Multi_frequencyInfo_LCR_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Multi_frequencyInfo_LCR_r7_1,
	3,	/* Elements count */
	&asn_SPC_Multi_frequencyInfo_LCR_r7_specs_1	/* Additional specs */
};

