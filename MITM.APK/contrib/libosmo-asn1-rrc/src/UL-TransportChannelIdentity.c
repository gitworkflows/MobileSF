/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UL-TransportChannelIdentity.h"

static asn_TYPE_member_t asn_MBR_UL_TransportChannelIdentity_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransportChannelIdentity, ul_TransportChannelType),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_TrCH_Type,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ul-TransportChannelType"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_TransportChannelIdentity, ul_TransportChannelIdentity),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportChannelIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ul-TransportChannelIdentity"
		},
};
static ber_tlv_tag_t asn_DEF_UL_TransportChannelIdentity_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_UL_TransportChannelIdentity_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ul-TransportChannelType at 5894 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ul-TransportChannelIdentity at 5896 */
};
static asn_SEQUENCE_specifics_t asn_SPC_UL_TransportChannelIdentity_specs_1 = {
	sizeof(struct UL_TransportChannelIdentity),
	offsetof(struct UL_TransportChannelIdentity, _asn_ctx),
	asn_MAP_UL_TransportChannelIdentity_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UL_TransportChannelIdentity = {
	"UL-TransportChannelIdentity",
	"UL-TransportChannelIdentity",
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
	asn_DEF_UL_TransportChannelIdentity_tags_1,
	sizeof(asn_DEF_UL_TransportChannelIdentity_tags_1)
		/sizeof(asn_DEF_UL_TransportChannelIdentity_tags_1[0]), /* 1 */
	asn_DEF_UL_TransportChannelIdentity_tags_1,	/* Same as above */
	sizeof(asn_DEF_UL_TransportChannelIdentity_tags_1)
		/sizeof(asn_DEF_UL_TransportChannelIdentity_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UL_TransportChannelIdentity_1,
	2,	/* Elements count */
	&asn_SPC_UL_TransportChannelIdentity_specs_1	/* Additional specs */
};

