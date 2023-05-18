/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "DTX-E-DCH-TTI-10ms.h"

static asn_TYPE_member_t asn_MBR_DTX_E_DCH_TTI_10ms_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DTX_E_DCH_TTI_10ms, ue_dtx_Cycle1_10ms),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_DTX_Cycle1_10ms,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ue-dtx-Cycle1-10ms"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DTX_E_DCH_TTI_10ms, ue_dtx_Cycle2_10ms),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UE_DTX_Cycle2_10ms,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ue-dtx-Cycle2-10ms"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct DTX_E_DCH_TTI_10ms, mac_dtx_Cycle_10ms),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MAC_DTX_Cycle_10ms,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mac-dtx-Cycle-10ms"
		},
};
static ber_tlv_tag_t asn_DEF_DTX_E_DCH_TTI_10ms_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_DTX_E_DCH_TTI_10ms_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* ue-dtx-Cycle1-10ms at 7987 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* ue-dtx-Cycle2-10ms at 7988 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* mac-dtx-Cycle-10ms at 7990 */
};
static asn_SEQUENCE_specifics_t asn_SPC_DTX_E_DCH_TTI_10ms_specs_1 = {
	sizeof(struct DTX_E_DCH_TTI_10ms),
	offsetof(struct DTX_E_DCH_TTI_10ms, _asn_ctx),
	asn_MAP_DTX_E_DCH_TTI_10ms_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_DTX_E_DCH_TTI_10ms = {
	"DTX-E-DCH-TTI-10ms",
	"DTX-E-DCH-TTI-10ms",
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
	asn_DEF_DTX_E_DCH_TTI_10ms_tags_1,
	sizeof(asn_DEF_DTX_E_DCH_TTI_10ms_tags_1)
		/sizeof(asn_DEF_DTX_E_DCH_TTI_10ms_tags_1[0]), /* 1 */
	asn_DEF_DTX_E_DCH_TTI_10ms_tags_1,	/* Same as above */
	sizeof(asn_DEF_DTX_E_DCH_TTI_10ms_tags_1)
		/sizeof(asn_DEF_DTX_E_DCH_TTI_10ms_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_DTX_E_DCH_TTI_10ms_1,
	3,	/* Elements count */
	&asn_SPC_DTX_E_DCH_TTI_10ms_specs_1	/* Additional specs */
};

