/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "PRACH-RACH-Info-VHCR-r7.h"

static asn_TYPE_member_t asn_MBR_PRACH_RACH_Info_VHCR_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_RACH_Info_VHCR_r7, timeslot),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeslot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_RACH_Info_VHCR_r7, channelisationCodeList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_TDD768_PRACH_CCodeList,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"channelisationCodeList"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct PRACH_RACH_Info_VHCR_r7, prach_Midamble),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PRACH_Midamble,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"prach-Midamble"
		},
};
static ber_tlv_tag_t asn_DEF_PRACH_RACH_Info_VHCR_r7_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_PRACH_RACH_Info_VHCR_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeslot at 10299 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* channelisationCodeList at 10300 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* prach-Midamble at 10302 */
};
static asn_SEQUENCE_specifics_t asn_SPC_PRACH_RACH_Info_VHCR_r7_specs_1 = {
	sizeof(struct PRACH_RACH_Info_VHCR_r7),
	offsetof(struct PRACH_RACH_Info_VHCR_r7, _asn_ctx),
	asn_MAP_PRACH_RACH_Info_VHCR_r7_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_PRACH_RACH_Info_VHCR_r7 = {
	"PRACH-RACH-Info-VHCR-r7",
	"PRACH-RACH-Info-VHCR-r7",
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
	asn_DEF_PRACH_RACH_Info_VHCR_r7_tags_1,
	sizeof(asn_DEF_PRACH_RACH_Info_VHCR_r7_tags_1)
		/sizeof(asn_DEF_PRACH_RACH_Info_VHCR_r7_tags_1[0]), /* 1 */
	asn_DEF_PRACH_RACH_Info_VHCR_r7_tags_1,	/* Same as above */
	sizeof(asn_DEF_PRACH_RACH_Info_VHCR_r7_tags_1)
		/sizeof(asn_DEF_PRACH_RACH_Info_VHCR_r7_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_PRACH_RACH_Info_VHCR_r7_1,
	3,	/* Elements count */
	&asn_SPC_PRACH_RACH_Info_VHCR_r7_specs_1	/* Additional specs */
};

