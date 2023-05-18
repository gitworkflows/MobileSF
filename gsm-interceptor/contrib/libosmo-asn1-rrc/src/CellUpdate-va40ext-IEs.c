/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "../asn/PDU-definitions.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "CellUpdate-va40ext-IEs.h"

static int
securityRevertStatusIndicator_2_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
securityRevertStatusIndicator_2_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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
securityRevertStatusIndicator_2_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	securityRevertStatusIndicator_2_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
securityRevertStatusIndicator_2_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	securityRevertStatusIndicator_2_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
securityRevertStatusIndicator_2_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	securityRevertStatusIndicator_2_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
securityRevertStatusIndicator_2_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	securityRevertStatusIndicator_2_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
securityRevertStatusIndicator_2_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	securityRevertStatusIndicator_2_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
securityRevertStatusIndicator_2_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	securityRevertStatusIndicator_2_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
securityRevertStatusIndicator_2_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	securityRevertStatusIndicator_2_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
securityRevertStatusIndicator_2_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	securityRevertStatusIndicator_2_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static int
loggedMeasAvailable_5_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
loggedMeasAvailable_5_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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
loggedMeasAvailable_5_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	loggedMeasAvailable_5_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
loggedMeasAvailable_5_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	loggedMeasAvailable_5_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
loggedMeasAvailable_5_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	loggedMeasAvailable_5_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
loggedMeasAvailable_5_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	loggedMeasAvailable_5_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
loggedMeasAvailable_5_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	loggedMeasAvailable_5_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
loggedMeasAvailable_5_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	loggedMeasAvailable_5_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
loggedMeasAvailable_5_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	loggedMeasAvailable_5_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
loggedMeasAvailable_5_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	loggedMeasAvailable_5_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static int
loggedANRResultsAvailable_7_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
loggedANRResultsAvailable_7_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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
loggedANRResultsAvailable_7_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	loggedANRResultsAvailable_7_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

static int
loggedANRResultsAvailable_7_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	loggedANRResultsAvailable_7_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

static asn_dec_rval_t
loggedANRResultsAvailable_7_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	loggedANRResultsAvailable_7_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

static asn_enc_rval_t
loggedANRResultsAvailable_7_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	loggedANRResultsAvailable_7_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

static asn_dec_rval_t
loggedANRResultsAvailable_7_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	loggedANRResultsAvailable_7_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

static asn_enc_rval_t
loggedANRResultsAvailable_7_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	loggedANRResultsAvailable_7_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

static asn_dec_rval_t
loggedANRResultsAvailable_7_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	loggedANRResultsAvailable_7_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

static asn_enc_rval_t
loggedANRResultsAvailable_7_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	loggedANRResultsAvailable_7_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_type_securityRevertStatusIndicator_constr_2 = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_loggedMeasAvailable_constr_5 = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_per_constraints_t asn_PER_type_loggedANRResultsAvailable_constr_7 = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_securityRevertStatusIndicator_value2enum_2[] = {
	{ 0,	12,	"revertedBack" },
	{ 1,	15,	"normalOperation" }
};
static unsigned int asn_MAP_securityRevertStatusIndicator_enum2value_2[] = {
	1,	/* normalOperation(1) */
	0	/* revertedBack(0) */
};
static asn_INTEGER_specifics_t asn_SPC_securityRevertStatusIndicator_specs_2 = {
	asn_MAP_securityRevertStatusIndicator_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_securityRevertStatusIndicator_enum2value_2,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_securityRevertStatusIndicator_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_securityRevertStatusIndicator_2 = {
	"securityRevertStatusIndicator",
	"securityRevertStatusIndicator",
	securityRevertStatusIndicator_2_free,
	securityRevertStatusIndicator_2_print,
	securityRevertStatusIndicator_2_constraint,
	securityRevertStatusIndicator_2_decode_ber,
	securityRevertStatusIndicator_2_encode_der,
	securityRevertStatusIndicator_2_decode_xer,
	securityRevertStatusIndicator_2_encode_xer,
	securityRevertStatusIndicator_2_decode_uper,
	securityRevertStatusIndicator_2_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_securityRevertStatusIndicator_tags_2,
	sizeof(asn_DEF_securityRevertStatusIndicator_tags_2)
		/sizeof(asn_DEF_securityRevertStatusIndicator_tags_2[0]) - 1, /* 1 */
	asn_DEF_securityRevertStatusIndicator_tags_2,	/* Same as above */
	sizeof(asn_DEF_securityRevertStatusIndicator_tags_2)
		/sizeof(asn_DEF_securityRevertStatusIndicator_tags_2[0]), /* 2 */
	&asn_PER_type_securityRevertStatusIndicator_constr_2,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_securityRevertStatusIndicator_specs_2	/* Additional specs */
};

static asn_INTEGER_enum_map_t asn_MAP_loggedMeasAvailable_value2enum_5[] = {
	{ 0,	4,	"true" }
};
static unsigned int asn_MAP_loggedMeasAvailable_enum2value_5[] = {
	0	/* true(0) */
};
static asn_INTEGER_specifics_t asn_SPC_loggedMeasAvailable_specs_5 = {
	asn_MAP_loggedMeasAvailable_value2enum_5,	/* "tag" => N; sorted by tag */
	asn_MAP_loggedMeasAvailable_enum2value_5,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_loggedMeasAvailable_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_loggedMeasAvailable_5 = {
	"loggedMeasAvailable",
	"loggedMeasAvailable",
	loggedMeasAvailable_5_free,
	loggedMeasAvailable_5_print,
	loggedMeasAvailable_5_constraint,
	loggedMeasAvailable_5_decode_ber,
	loggedMeasAvailable_5_encode_der,
	loggedMeasAvailable_5_decode_xer,
	loggedMeasAvailable_5_encode_xer,
	loggedMeasAvailable_5_decode_uper,
	loggedMeasAvailable_5_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_loggedMeasAvailable_tags_5,
	sizeof(asn_DEF_loggedMeasAvailable_tags_5)
		/sizeof(asn_DEF_loggedMeasAvailable_tags_5[0]) - 1, /* 1 */
	asn_DEF_loggedMeasAvailable_tags_5,	/* Same as above */
	sizeof(asn_DEF_loggedMeasAvailable_tags_5)
		/sizeof(asn_DEF_loggedMeasAvailable_tags_5[0]), /* 2 */
	&asn_PER_type_loggedMeasAvailable_constr_5,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_loggedMeasAvailable_specs_5	/* Additional specs */
};

static asn_INTEGER_enum_map_t asn_MAP_loggedANRResultsAvailable_value2enum_7[] = {
	{ 0,	4,	"true" }
};
static unsigned int asn_MAP_loggedANRResultsAvailable_enum2value_7[] = {
	0	/* true(0) */
};
static asn_INTEGER_specifics_t asn_SPC_loggedANRResultsAvailable_specs_7 = {
	asn_MAP_loggedANRResultsAvailable_value2enum_7,	/* "tag" => N; sorted by tag */
	asn_MAP_loggedANRResultsAvailable_enum2value_7,	/* N => "tag"; sorted by N */
	1,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_loggedANRResultsAvailable_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_loggedANRResultsAvailable_7 = {
	"loggedANRResultsAvailable",
	"loggedANRResultsAvailable",
	loggedANRResultsAvailable_7_free,
	loggedANRResultsAvailable_7_print,
	loggedANRResultsAvailable_7_constraint,
	loggedANRResultsAvailable_7_decode_ber,
	loggedANRResultsAvailable_7_encode_der,
	loggedANRResultsAvailable_7_decode_xer,
	loggedANRResultsAvailable_7_encode_xer,
	loggedANRResultsAvailable_7_decode_uper,
	loggedANRResultsAvailable_7_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_loggedANRResultsAvailable_tags_7,
	sizeof(asn_DEF_loggedANRResultsAvailable_tags_7)
		/sizeof(asn_DEF_loggedANRResultsAvailable_tags_7[0]) - 1, /* 1 */
	asn_DEF_loggedANRResultsAvailable_tags_7,	/* Same as above */
	sizeof(asn_DEF_loggedANRResultsAvailable_tags_7)
		/sizeof(asn_DEF_loggedANRResultsAvailable_tags_7[0]), /* 2 */
	&asn_PER_type_loggedANRResultsAvailable_constr_7,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_loggedANRResultsAvailable_specs_7	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_CellUpdate_va40ext_IEs_1[] = {
	{ ATF_POINTER, 3, offsetof(struct CellUpdate_va40ext_IEs, securityRevertStatusIndicator),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_securityRevertStatusIndicator_2,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"securityRevertStatusIndicator"
		},
	{ ATF_POINTER, 2, offsetof(struct CellUpdate_va40ext_IEs, loggedMeasAvailable),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_loggedMeasAvailable_5,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"loggedMeasAvailable"
		},
	{ ATF_POINTER, 1, offsetof(struct CellUpdate_va40ext_IEs, loggedANRResultsAvailable),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_loggedANRResultsAvailable_7,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"loggedANRResultsAvailable"
		},
};
static int asn_MAP_CellUpdate_va40ext_IEs_oms_1[] = { 0, 1, 2 };
static ber_tlv_tag_t asn_DEF_CellUpdate_va40ext_IEs_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_CellUpdate_va40ext_IEs_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* securityRevertStatusIndicator at 1272 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* loggedMeasAvailable at 1274 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* loggedANRResultsAvailable at 1275 */
};
static asn_SEQUENCE_specifics_t asn_SPC_CellUpdate_va40ext_IEs_specs_1 = {
	sizeof(struct CellUpdate_va40ext_IEs),
	offsetof(struct CellUpdate_va40ext_IEs, _asn_ctx),
	asn_MAP_CellUpdate_va40ext_IEs_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_CellUpdate_va40ext_IEs_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_CellUpdate_va40ext_IEs = {
	"CellUpdate-va40ext-IEs",
	"CellUpdate-va40ext-IEs",
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
	asn_DEF_CellUpdate_va40ext_IEs_tags_1,
	sizeof(asn_DEF_CellUpdate_va40ext_IEs_tags_1)
		/sizeof(asn_DEF_CellUpdate_va40ext_IEs_tags_1[0]), /* 1 */
	asn_DEF_CellUpdate_va40ext_IEs_tags_1,	/* Same as above */
	sizeof(asn_DEF_CellUpdate_va40ext_IEs_tags_1)
		/sizeof(asn_DEF_CellUpdate_va40ext_IEs_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_CellUpdate_va40ext_IEs_1,
	3,	/* Elements count */
	&asn_SPC_CellUpdate_va40ext_IEs_specs_1	/* Additional specs */
};

