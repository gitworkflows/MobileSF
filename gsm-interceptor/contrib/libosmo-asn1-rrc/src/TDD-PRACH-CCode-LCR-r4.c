/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "../asn/InformationElements.asn"
 * 	`asn1c -fcompound-names -fnative-types`
 */

#include "TDD-PRACH-CCode-LCR-r4.h"

int
TDD_PRACH_CCode_LCR_r4_constraint(asn_TYPE_descriptor_t *td, const void *sptr,
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
TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(asn_TYPE_descriptor_t *td) {
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
TDD_PRACH_CCode_LCR_r4_free(asn_TYPE_descriptor_t *td,
		void *struct_ptr, int contents_only) {
	TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(td);
	td->free_struct(td, struct_ptr, contents_only);
}

int
TDD_PRACH_CCode_LCR_r4_print(asn_TYPE_descriptor_t *td, const void *struct_ptr,
		int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
	TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(td);
	return td->print_struct(td, struct_ptr, ilevel, cb, app_key);
}

asn_dec_rval_t
TDD_PRACH_CCode_LCR_r4_decode_ber(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const void *bufptr, size_t size, int tag_mode) {
	TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(td);
	return td->ber_decoder(opt_codec_ctx, td, structure, bufptr, size, tag_mode);
}

asn_enc_rval_t
TDD_PRACH_CCode_LCR_r4_encode_der(asn_TYPE_descriptor_t *td,
		void *structure, int tag_mode, ber_tlv_tag_t tag,
		asn_app_consume_bytes_f *cb, void *app_key) {
	TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(td);
	return td->der_encoder(td, structure, tag_mode, tag, cb, app_key);
}

asn_dec_rval_t
TDD_PRACH_CCode_LCR_r4_decode_xer(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		void **structure, const char *opt_mname, const void *bufptr, size_t size) {
	TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(td);
	return td->xer_decoder(opt_codec_ctx, td, structure, opt_mname, bufptr, size);
}

asn_enc_rval_t
TDD_PRACH_CCode_LCR_r4_encode_xer(asn_TYPE_descriptor_t *td, void *structure,
		int ilevel, enum xer_encoder_flags_e flags,
		asn_app_consume_bytes_f *cb, void *app_key) {
	TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(td);
	return td->xer_encoder(td, structure, ilevel, flags, cb, app_key);
}

asn_dec_rval_t
TDD_PRACH_CCode_LCR_r4_decode_uper(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints, void **structure, asn_per_data_t *per_data) {
	TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(td);
	return td->uper_decoder(opt_codec_ctx, td, constraints, structure, per_data);
}

asn_enc_rval_t
TDD_PRACH_CCode_LCR_r4_encode_uper(asn_TYPE_descriptor_t *td,
		asn_per_constraints_t *constraints,
		void *structure, asn_per_outp_t *per_out) {
	TDD_PRACH_CCode_LCR_r4_1_inherit_TYPE_descriptor(td);
	return td->uper_encoder(td, constraints, structure, per_out);
}

static asn_per_constraints_t asn_PER_type_TDD_PRACH_CCode_LCR_r4_constr_1 = {
	{ APC_CONSTRAINED,	 5,  5,  0,  27 }	/* (0..27) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_INTEGER_enum_map_t asn_MAP_TDD_PRACH_CCode_LCR_r4_value2enum_1[] = {
	{ 0,	5,	"cc4-1" },
	{ 1,	5,	"cc4-2" },
	{ 2,	5,	"cc4-3" },
	{ 3,	5,	"cc4-4" },
	{ 4,	5,	"cc8-1" },
	{ 5,	5,	"cc8-2" },
	{ 6,	5,	"cc8-3" },
	{ 7,	5,	"cc8-4" },
	{ 8,	5,	"cc8-5" },
	{ 9,	5,	"cc8-6" },
	{ 10,	5,	"cc8-7" },
	{ 11,	5,	"cc8-8" },
	{ 12,	6,	"cc16-1" },
	{ 13,	6,	"cc16-2" },
	{ 14,	6,	"cc16-3" },
	{ 15,	6,	"cc16-4" },
	{ 16,	6,	"cc16-5" },
	{ 17,	6,	"cc16-6" },
	{ 18,	6,	"cc16-7" },
	{ 19,	6,	"cc16-8" },
	{ 20,	6,	"cc16-9" },
	{ 21,	7,	"cc16-10" },
	{ 22,	7,	"cc16-11" },
	{ 23,	7,	"cc16-12" },
	{ 24,	7,	"cc16-13" },
	{ 25,	7,	"cc16-14" },
	{ 26,	7,	"cc16-15" },
	{ 27,	7,	"cc16-16" }
};
static unsigned int asn_MAP_TDD_PRACH_CCode_LCR_r4_enum2value_1[] = {
	12,	/* cc16-1(12) */
	21,	/* cc16-10(21) */
	22,	/* cc16-11(22) */
	23,	/* cc16-12(23) */
	24,	/* cc16-13(24) */
	25,	/* cc16-14(25) */
	26,	/* cc16-15(26) */
	27,	/* cc16-16(27) */
	13,	/* cc16-2(13) */
	14,	/* cc16-3(14) */
	15,	/* cc16-4(15) */
	16,	/* cc16-5(16) */
	17,	/* cc16-6(17) */
	18,	/* cc16-7(18) */
	19,	/* cc16-8(19) */
	20,	/* cc16-9(20) */
	0,	/* cc4-1(0) */
	1,	/* cc4-2(1) */
	2,	/* cc4-3(2) */
	3,	/* cc4-4(3) */
	4,	/* cc8-1(4) */
	5,	/* cc8-2(5) */
	6,	/* cc8-3(6) */
	7,	/* cc8-4(7) */
	8,	/* cc8-5(8) */
	9,	/* cc8-6(9) */
	10,	/* cc8-7(10) */
	11	/* cc8-8(11) */
};
static asn_INTEGER_specifics_t asn_SPC_TDD_PRACH_CCode_LCR_r4_specs_1 = {
	asn_MAP_TDD_PRACH_CCode_LCR_r4_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_TDD_PRACH_CCode_LCR_r4_enum2value_1,	/* N => "tag"; sorted by N */
	28,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static ber_tlv_tag_t asn_DEF_TDD_PRACH_CCode_LCR_r4_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_TDD_PRACH_CCode_LCR_r4 = {
	"TDD-PRACH-CCode-LCR-r4",
	"TDD-PRACH-CCode-LCR-r4",
	TDD_PRACH_CCode_LCR_r4_free,
	TDD_PRACH_CCode_LCR_r4_print,
	TDD_PRACH_CCode_LCR_r4_constraint,
	TDD_PRACH_CCode_LCR_r4_decode_ber,
	TDD_PRACH_CCode_LCR_r4_encode_der,
	TDD_PRACH_CCode_LCR_r4_decode_xer,
	TDD_PRACH_CCode_LCR_r4_encode_xer,
	TDD_PRACH_CCode_LCR_r4_decode_uper,
	TDD_PRACH_CCode_LCR_r4_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_TDD_PRACH_CCode_LCR_r4_tags_1,
	sizeof(asn_DEF_TDD_PRACH_CCode_LCR_r4_tags_1)
		/sizeof(asn_DEF_TDD_PRACH_CCode_LCR_r4_tags_1[0]), /* 1 */
	asn_DEF_TDD_PRACH_CCode_LCR_r4_tags_1,	/* Same as above */
	sizeof(asn_DEF_TDD_PRACH_CCode_LCR_r4_tags_1)
		/sizeof(asn_DEF_TDD_PRACH_CCode_LCR_r4_tags_1[0]), /* 1 */
	&asn_PER_type_TDD_PRACH_CCode_LCR_r4_constr_1,
	0, 0,	/* Defined elsewhere */
	&asn_SPC_TDD_PRACH_CCode_LCR_r4_specs_1	/* Additional specs */
};

