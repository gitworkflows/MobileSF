/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "CellAndChannelIdentity.h"

static asn_TYPE_member_t asn_MBR_CellAndChannelIdentity_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CellAndChannelIdentity, burstType),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BurstType,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"burstType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellAndChannelIdentity, midambleShift),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MidambleShiftLong,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"midambleShift"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellAndChannelIdentity, timeslot),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimeslotNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeslot"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CellAndChannelIdentity, cellParametersID),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellParametersID,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"cellParametersID"
		},
};
static ber_tlv_tag_t asn_DEF_CellAndChannelIdentity_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_CellAndChannelIdentity_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* burstType at 6319 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* midambleShift at 6320 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timeslot at 6321 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* cellParametersID at 6323 */
};
static asn_SEQUENCE_specifics_t asn_SPC_CellAndChannelIdentity_specs_1 = {
	sizeof(struct CellAndChannelIdentity),
	offsetof(struct CellAndChannelIdentity, _asn_ctx),
	asn_MAP_CellAndChannelIdentity_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_CellAndChannelIdentity = {
	"CellAndChannelIdentity",
	"CellAndChannelIdentity",
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
	asn_DEF_CellAndChannelIdentity_tags_1,
	sizeof(asn_DEF_CellAndChannelIdentity_tags_1)
		/sizeof(asn_DEF_CellAndChannelIdentity_tags_1[0]), /* 1 */
	asn_DEF_CellAndChannelIdentity_tags_1,	/* Same as above */
	sizeof(asn_DEF_CellAndChannelIdentity_tags_1)
		/sizeof(asn_DEF_CellAndChannelIdentity_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_CellAndChannelIdentity_1,
	4,	/* Elements count */
	&asn_SPC_CellAndChannelIdentity_specs_1	/* Additional specs */
};

