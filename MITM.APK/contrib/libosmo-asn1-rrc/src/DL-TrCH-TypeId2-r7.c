/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DL-TrCH-TypeId2-r7.h"

static asn_per_constraints_t asn_PER_type_hsdsch_constr_4 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_DL_TrCH_TypeId2_r7_constr_1 = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_hsdsch_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TrCH_TypeId2_r7__hsdsch, choice.mac_hs),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MAC_d_FlowIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mac-hs"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TrCH_TypeId2_r7__hsdsch, choice.mac_ehs),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MAC_ehs_QueueId,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mac-ehs"
		},
};
static asn_TYPE_tag2member_t asn_MAP_hsdsch_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mac-hs at 5210 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* mac-ehs at 5212 */
};
static asn_CHOICE_specifics_t asn_SPC_hsdsch_specs_4 = {
	sizeof(struct DL_TrCH_TypeId2_r7__hsdsch),
	offsetof(struct DL_TrCH_TypeId2_r7__hsdsch, _asn_ctx),
	offsetof(struct DL_TrCH_TypeId2_r7__hsdsch, present),
	sizeof(((struct DL_TrCH_TypeId2_r7__hsdsch *)0)->present),
	asn_MAP_hsdsch_tag2el_4,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_hsdsch_4 = {
	"hsdsch",
	"hsdsch",
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
	&asn_PER_type_hsdsch_constr_4,
	asn_MBR_hsdsch_4,
	2,	/* Elements count */
	&asn_SPC_hsdsch_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_DL_TrCH_TypeId2_r7_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TrCH_TypeId2_r7, choice.dch),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportChannelIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dch"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TrCH_TypeId2_r7, choice.dsch),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TransportChannelIdentity,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"dsch"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DL_TrCH_TypeId2_r7, choice.hsdsch),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_hsdsch_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"hsdsch"
		},
};
static asn_TYPE_tag2member_t asn_MAP_DL_TrCH_TypeId2_r7_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dch at 5205 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dsch at 5208 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* hsdsch at 5210 */
};
static asn_CHOICE_specifics_t asn_SPC_DL_TrCH_TypeId2_r7_specs_1 = {
	sizeof(struct DL_TrCH_TypeId2_r7),
	offsetof(struct DL_TrCH_TypeId2_r7, _asn_ctx),
	offsetof(struct DL_TrCH_TypeId2_r7, present),
	sizeof(((struct DL_TrCH_TypeId2_r7 *)0)->present),
	asn_MAP_DL_TrCH_TypeId2_r7_tag2el_1,
	3,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_DL_TrCH_TypeId2_r7 = {
	"DL-TrCH-TypeId2-r7",
	"DL-TrCH-TypeId2-r7",
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
	&asn_PER_type_DL_TrCH_TypeId2_r7_constr_1,
	asn_MBR_DL_TrCH_TypeId2_r7_1,
	3,	/* Elements count */
	&asn_SPC_DL_TrCH_TypeId2_r7_specs_1	/* Additional specs */
};

