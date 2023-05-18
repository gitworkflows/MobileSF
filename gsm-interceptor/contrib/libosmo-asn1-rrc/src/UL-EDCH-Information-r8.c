/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "UL-EDCH-Information-r8.h"

static int
mac_es_e_resetIndicator_2_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	/* Replace with underlying type checker */
	td->check_constraints = asn_DEF_NativeEnumerated.check_constraints;
	return td->check_constraints(td, sptr, ctfailcb, app_key);
}

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static void
mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
	td->free_struct    = asn_DEF_NativeEnumerated.free_struct;
	td->print_struct   = asn_DEF_NativeEnumerated.print_struct;
	td->ber_decoder    = asn_DEF_NativeEnumerated.ber_decoder;
	td->der_encoder    = asn_DEF_NativeEnumerated.der_encoder;
	td->xer_decoder    = asn_DEF_NativeEnumerated.xer_decoder;
	td->xer_encoder    = asn_DEF_NativeEnumerated.xer_encoder;
	td->uper_decoder   = asn_DEF_NativeEnumerated.uper_decoder;
	td->uper_encoder   = asn_DEF_NativeEnumerated.uper_encoder;
	if(!td->per_constraints)
		td->per_constraints = asn_DEF_NativeEnumerated.per_constraints;
	td->elements       = asn_DEF_NativeEnumerated.elements;
	td->elements_count = asn_DEF_NativeEnumerated.elements_count;
     /* td->specifics      = asn_DEF_NativeEnumerated.specifics;	// Defined explicitly */
}

static void
mac_es_e_resetIndicator_2_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
mac_es_e_resetIndicator_2_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
mac_es_e_resetIndicator_2_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
mac_es_e_resetIndicator_2_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
mac_es_e_resetIndicator_2_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
mac_es_e_resetIndicator_2_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
mac_es_e_resetIndicator_2_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
mac_es_e_resetIndicator_2_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	mac_es_e_resetIndicator_2_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_type_mac_es_e_resetIndicator_constr_2 = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_modeSpecificInfo_constr_4 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_mac_es_e_resetIndicator_value2enum_2[] = {
	{ 0,	4,	"true" }
};
static unsigned int asn_MAP_mac_es_e_resetIndicator_enum2value_2[] = {
	0	/* true(0) */
};
static asn_INTEGER_specifics_t asn_SPC_mac_es_e_resetIndicator_specs_2 = {
	asn_MAP_mac_es_e_resetIndicator_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_mac_es_e_resetIndicator_enum2value_2,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_mac_es_e_resetIndicator_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_mac_es_e_resetIndicator_2 = {
	"mac-es-e-resetIndicator",
	"mac-es-e-resetIndicator",
	mac_es_e_resetIndicator_2_free,
	mac_es_e_resetIndicator_2_print,
	mac_es_e_resetIndicator_2_constraint,
	mac_es_e_resetIndicator_2_decode_ber,
	mac_es_e_resetIndicator_2_encode_der,
	mac_es_e_resetIndicator_2_decode_xer,
	mac_es_e_resetIndicator_2_encode_xer,
	mac_es_e_resetIndicator_2_decode_uper,
	mac_es_e_resetIndicator_2_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_mac_es_e_resetIndicator_tags_2,
	sizeof(asn_DEF_mac_es_e_resetIndicator_tags_2)
		/sizeof(asn_DEF_mac_es_e_resetIndicator_tags_2[0]) - 1, /* 1 */
	asn_DEF_mac_es_e_resetIndicator_tags_2,	/* Same as above */
	sizeof(asn_DEF_mac_es_e_resetIndicator_tags_2)
		/sizeof(asn_DEF_mac_es_e_resetIndicator_tags_2[0]), /* 2 */
	&asn_PER_type_mac_es_e_resetIndicator_constr_2,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_mac_es_e_resetIndicator_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_fdd_5[] = {
	{ ATF_POINTER, 4, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__fdd, e_DPCCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPCCH_Info_r7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-DPCCH-Info"
		},
	{ ATF_POINTER, 3, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__fdd, e_DPDCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPDCH_Info_r8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-DPDCH-Info"
		},
	{ ATF_POINTER, 2, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__fdd, schedulingTransmConfiguration),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_DPDCH_SchedulingTransmConfiguration,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"schedulingTransmConfiguration"
		},
	{ ATF_POINTER, 1, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__fdd, ul_16QAM_Settings),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UL_16QAM_Settings,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"ul-16QAM-Settings"
		},
};
static int asn_MAP_fdd_oms_5[] = { 0, 1, 2, 3 };
static ber_tlv_tag_t asn_DEF_fdd_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_fdd_tag2el_5[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-DPCCH-Info at 12551 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* e-DPDCH-Info at 12552 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* schedulingTransmConfiguration at 12553 */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* ul-16QAM-Settings at 12554 */
};
static asn_SEQUENCE_specifics_t asn_SPC_fdd_specs_5 = {
	sizeof(struct UL_EDCH_Information_r8__modeSpecificInfo__fdd),
	offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__fdd, _asn_ctx),
	asn_MAP_fdd_tag2el_5,
	4,	/* Count of tags in the map */
	asn_MAP_fdd_oms_5,	/* Optional members */
	4, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fdd_5 = {
	"fdd",
	"fdd",
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
	asn_DEF_fdd_tags_5,
	sizeof(asn_DEF_fdd_tags_5)
		/sizeof(asn_DEF_fdd_tags_5[0]) - 1, /* 1 */
	asn_DEF_fdd_tags_5,	/* Same as above */
	sizeof(asn_DEF_fdd_tags_5)
		/sizeof(asn_DEF_fdd_tags_5[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_fdd_5,
	4,	/* Elements count */
	&asn_SPC_fdd_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tdd_10[] = {
	{ ATF_POINTER, 3, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__tdd, e_RUCCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_RUCCH_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-RUCCH-Info"
		},
	{ ATF_POINTER, 2, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__tdd, e_PUCH_Info),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_E_PUCH_Info,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-PUCH-Info"
		},
	{ ATF_POINTER, 1, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__tdd, non_ScheduledTransGrantInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Non_ScheduledTransGrantInfoTDD,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"non-ScheduledTransGrantInfo"
		},
};
static int asn_MAP_tdd_oms_10[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_tdd_tags_10[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_tdd_tag2el_10[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-RUCCH-Info at 12557 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* e-PUCH-Info at 12558 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* non-ScheduledTransGrantInfo at 12559 */
};
static asn_SEQUENCE_specifics_t asn_SPC_tdd_specs_10 = {
	sizeof(struct UL_EDCH_Information_r8__modeSpecificInfo__tdd),
	offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo__tdd, _asn_ctx),
	asn_MAP_tdd_tag2el_10,
	3,	/* Count of tags in the map */
	asn_MAP_tdd_oms_10,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tdd_10 = {
	"tdd",
	"tdd",
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
	asn_DEF_tdd_tags_10,
	sizeof(asn_DEF_tdd_tags_10)
		/sizeof(asn_DEF_tdd_tags_10[0]) - 1, /* 1 */
	asn_DEF_tdd_tags_10,	/* Same as above */
	sizeof(asn_DEF_tdd_tags_10)
		/sizeof(asn_DEF_tdd_tags_10[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_tdd_10,
	3,	/* Elements count */
	&asn_SPC_tdd_specs_10	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_modeSpecificInfo_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo, choice.fdd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fdd_5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"fdd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo, choice.tdd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		0,
		&asn_DEF_tdd_10,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"tdd"
		},
};
static asn_TYPE_tag2member_t asn_MAP_modeSpecificInfo_tag2el_4[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* fdd at 12551 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* tdd at 12557 */
};
static asn_CHOICE_specifics_t asn_SPC_modeSpecificInfo_specs_4 = {
	sizeof(struct UL_EDCH_Information_r8__modeSpecificInfo),
	offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo, _asn_ctx),
	offsetof(struct UL_EDCH_Information_r8__modeSpecificInfo, present),
	sizeof(((struct UL_EDCH_Information_r8__modeSpecificInfo *)0)->present),
	asn_MAP_modeSpecificInfo_tag2el_4,
	2,	/* Count of tags in the map */
	0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_modeSpecificInfo_4 = {
	"modeSpecificInfo",
	"modeSpecificInfo",
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
	&asn_PER_type_modeSpecificInfo_constr_4,
	asn_MBR_modeSpecificInfo_4,
	2,	/* Elements count */
	&asn_SPC_modeSpecificInfo_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_UL_EDCH_Information_r8_1[] = {
	{ ATF_POINTER, 1, offsetof(struct UL_EDCH_Information_r8, mac_es_e_resetIndicator),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_mac_es_e_resetIndicator_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"mac-es-e-resetIndicator"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UL_EDCH_Information_r8, modeSpecificInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_modeSpecificInfo_4,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"modeSpecificInfo"
		},
};
static int asn_MAP_UL_EDCH_Information_r8_oms_1[] = { 0 };
static ber_tlv_tag_t asn_DEF_UL_EDCH_Information_r8_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_UL_EDCH_Information_r8_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mac-es-e-resetIndicator at 12548 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* modeSpecificInfo at 12555 */
};
static asn_SEQUENCE_specifics_t asn_SPC_UL_EDCH_Information_r8_specs_1 = {
	sizeof(struct UL_EDCH_Information_r8),
	offsetof(struct UL_EDCH_Information_r8, _asn_ctx),
	asn_MAP_UL_EDCH_Information_r8_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_UL_EDCH_Information_r8_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_UL_EDCH_Information_r8 = {
	"UL-EDCH-Information-r8",
	"UL-EDCH-Information-r8",
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
	asn_DEF_UL_EDCH_Information_r8_tags_1,
	sizeof(asn_DEF_UL_EDCH_Information_r8_tags_1)
		/sizeof(asn_DEF_UL_EDCH_Information_r8_tags_1[0]), /* 1 */
	asn_DEF_UL_EDCH_Information_r8_tags_1,	/* Same as above */
	sizeof(asn_DEF_UL_EDCH_Information_r8_tags_1)
		/sizeof(asn_DEF_UL_EDCH_Information_r8_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_UL_EDCH_Information_r8_1,
	2,	/* Elements count */
	&asn_SPC_UL_EDCH_Information_r8_specs_1	/* Additional specs */
};

