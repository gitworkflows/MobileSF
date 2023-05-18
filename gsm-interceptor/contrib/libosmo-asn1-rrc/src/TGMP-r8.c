/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "TGMP-r8.h"

int
TGMP_r8_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
TGMP_r8_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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

void
TGMP_r8_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	TGMP_r8_1_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

int
TGMP_r8_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	TGMP_r8_1_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

asn_dec_rval_t
TGMP_r8_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	TGMP_r8_1_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

asn_enc_rval_t
TGMP_r8_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	TGMP_r8_1_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

asn_dec_rval_t
TGMP_r8_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	TGMP_r8_1_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

asn_enc_rval_t
TGMP_r8_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	TGMP_r8_1_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

asn_dec_rval_t
TGMP_r8_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	TGMP_r8_1_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

asn_enc_rval_t
TGMP_r8_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	TGMP_r8_1_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_type_TGMP_r8_constr_1 = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_TGMP_r8_value2enum_1[] = {
	{ 0,	15,	"tdd-Measurement" },
	{ 1,	15,	"fdd-Measurement" },
	{ 2,	26,	"gsm-CarrierRSSIMeasurement" },
	{ 3,	29,	"gsm-initialBSICIdentification" },
	{ 4,	21,	"gsmBSICReconfirmation" },
	{ 5,	13,	"multi-carrier" },
	{ 6,	6,	"e-UTRA" },
	{ 7,	5,	"spare" }
};
static unsigned int asn_MAP_TGMP_r8_enum2value_1[] = {
	6,	/* e-UTRA(6) */
	1,	/* fdd-Measurement(1) */
	2,	/* gsm-CarrierRSSIMeasurement(2) */
	3,	/* gsm-initialBSICIdentification(3) */
	4,	/* gsmBSICReconfirmation(4) */
	5,	/* multi-carrier(5) */
	7,	/* spare(7) */
	0	/* tdd-Measurement(0) */
};
static asn_INTEGER_specifics_t asn_SPC_TGMP_r8_specs_1 = {
	asn_MAP_TGMP_r8_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_TGMP_r8_enum2value_1,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_TGMP_r8_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_TGMP_r8 = {
	"TGMP-r8",
	"TGMP-r8",
	TGMP_r8_free,
	TGMP_r8_print,
	TGMP_r8_constraint,
	TGMP_r8_decode_ber,
	TGMP_r8_encode_der,
	TGMP_r8_decode_xer,
	TGMP_r8_encode_xer,
	TGMP_r8_decode_uper,
	TGMP_r8_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_TGMP_r8_tags_1,
	sizeof(asn_DEF_TGMP_r8_tags_1)
		/sizeof(asn_DEF_TGMP_r8_tags_1[0]), /* 1 */
	asn_DEF_TGMP_r8_tags_1,	/* Same as above */
	sizeof(asn_DEF_TGMP_r8_tags_1)
		/sizeof(asn_DEF_TGMP_r8_tags_1[0]), /* 1 */
	&asn_PER_type_TGMP_r8_constr_1,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_TGMP_r8_specs_1	/* Additional specs */
};

