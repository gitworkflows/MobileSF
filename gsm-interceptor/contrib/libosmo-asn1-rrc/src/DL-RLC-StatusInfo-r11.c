/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DL-RLC-StatusInfo-r11.h"

static asn_TYPE_member_t asn_MBR_DL_RLC_StatusInfo_r11_1[] = {
	{ ATF_POINTER, 1, offsetof(struct DL_RLC_StatusInfo_r11, timerStatusProhibit),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimerStatusProhibit,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timerStatusProhibit"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_RLC_StatusInfo_r11, missingPDU_Indicator),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"missingPDU-Indicator"
		},
	{ ATF_POINTER, 2, offsetof(struct DL_RLC_StatusInfo_r11, timerStatusPeriodic),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimerStatusPeriodic,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timerStatusPeriodic"
		},
	{ ATF_POINTER, 1, offsetof(struct DL_RLC_StatusInfo_r11, timerReordering),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimerReordering,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timerReordering"
		},
};
static int asn_MAP_DL_RLC_StatusInfo_r11_oms_1[] = { 0, 2, 3 };
static ber_tlv_tag_t asn_DEF_DL_RLC_StatusInfo_r11_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_DL_RLC_StatusInfo_r11_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timerStatusProhibit at 3632 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* missingPDU-Indicator at 3633 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timerStatusPeriodic at 3634 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* timerReordering at 3635 */
};
static asn_SEQUENCE_specifics_t asn_SPC_DL_RLC_StatusInfo_r11_specs_1 = {
	sizeof(struct DL_RLC_StatusInfo_r11),
	offsetof(struct DL_RLC_StatusInfo_r11, _asn_ctx),
	asn_MAP_DL_RLC_StatusInfo_r11_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_DL_RLC_StatusInfo_r11_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_DL_RLC_StatusInfo_r11 = {
	"DL-RLC-StatusInfo-r11",
	"DL-RLC-StatusInfo-r11",
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
	asn_DEF_DL_RLC_StatusInfo_r11_tags_1,
	sizeof(asn_DEF_DL_RLC_StatusInfo_r11_tags_1)
		/sizeof(asn_DEF_DL_RLC_StatusInfo_r11_tags_1[0]), /* 1 */
	asn_DEF_DL_RLC_StatusInfo_r11_tags_1,	/* Same as above */
	sizeof(asn_DEF_DL_RLC_StatusInfo_r11_tags_1)
		/sizeof(asn_DEF_DL_RLC_StatusInfo_r11_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_DL_RLC_StatusInfo_r11_1,
	4,	/* Elements count */
	&asn_SPC_DL_RLC_StatusInfo_r11_specs_1	/* Additional specs */
};

