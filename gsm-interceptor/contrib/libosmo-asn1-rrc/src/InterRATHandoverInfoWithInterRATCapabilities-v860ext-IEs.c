/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "Internode-definitions"
 * 	found in "../asn/Internode-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "InterRATHandoverInfoWithInterRATCapabilities-v860ext-IEs.h"

static asn_TYPE_member_t asn_MBR_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_1[] = {
	{ ATF_POINTER, 1, offsetof(struct InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs, ue_RATSpecificCapability),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterRAT_UE_RadioAccessCapability_v860ext,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ue-RATSpecificCapability"
		},
};
static int asn_MAP_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_oms_1[] = { 0 };
static ber_tlv_tag_t asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* ue-RATSpecificCapability at 290 */
};
static asn_SEQUENCE_specifics_t asn_SPC_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_specs_1 = {
	sizeof(struct InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs),
	offsetof(struct InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs, _asn_ctx),
	asn_MAP_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tag2el_1,
	1,	/* Count of tags in the map */
	asn_MAP_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs = {
	"InterRATHandoverInfoWithInterRATCapabilities-v860ext-IEs",
	"InterRATHandoverInfoWithInterRATCapabilities-v860ext-IEs",
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
	asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tags_1,
	sizeof(asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tags_1)
		/sizeof(asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tags_1)
		/sizeof(asn_DEF_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_1,
	1,	/* Elements count */
	&asn_SPC_InterRATHandoverInfoWithInterRATCapabilities_v860ext_IEs_specs_1	/* Additional specs */
};

