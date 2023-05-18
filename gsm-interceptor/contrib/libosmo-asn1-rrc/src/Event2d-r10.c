/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "Event2d-r10.h"

static asn_TYPE_member_t asn_MBR_Event2d_r10_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Event2d_r10, usedFreqThreshold),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Threshold_r6,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"usedFreqThreshold"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event2d_r10, usedFreqW),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_W,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"usedFreqW"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event2d_r10, hysteresis),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HysteresisInterFreq,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"hysteresis"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Event2d_r10, timeToTrigger),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeToTrigger,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeToTrigger"
		},
	{ ATF_POINTER, 1, offsetof(struct Event2d_r10, reportingCellStatus),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ReportingCellStatus_r10,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"reportingCellStatus"
		},
};
static int asn_MAP_Event2d_r10_oms_1[] = { 4 };
static ber_tlv_tag_t asn_DEF_Event2d_r10_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_Event2d_r10_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* usedFreqThreshold at 14257 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* usedFreqW at 14258 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* hysteresis at 14259 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* timeToTrigger at 14260 */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* reportingCellStatus at 14261 */
};
static asn_SEQUENCE_specifics_t asn_SPC_Event2d_r10_specs_1 = {
	sizeof(struct Event2d_r10),
	offsetof(struct Event2d_r10, _asn_ctx),
	asn_MAP_Event2d_r10_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_Event2d_r10_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Event2d_r10 = {
	"Event2d-r10",
	"Event2d-r10",
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
	asn_DEF_Event2d_r10_tags_1,
	sizeof(asn_DEF_Event2d_r10_tags_1)
		/sizeof(asn_DEF_Event2d_r10_tags_1[0]), /* 1 */
	asn_DEF_Event2d_r10_tags_1,	/* Same as above */
	sizeof(asn_DEF_Event2d_r10_tags_1)
		/sizeof(asn_DEF_Event2d_r10_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Event2d_r10_1,
	5,	/* Elements count */
	&asn_SPC_Event2d_r10_specs_1	/* Additional specs */
};

