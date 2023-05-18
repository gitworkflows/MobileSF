#! /bin/bash -e

usage()
{
		echo >&2 "Usage: $0 -t {android|android64|host} [-f] [-h] [-a]"
		echo >&2 "   -t <target>   Target to build for"
		echo >&2 "   -a            build for targets android AND android64"
		echo >&2 "   -f            Fast mode - only build parser"
		echo >&2 "   -g            init git submodules"
		echo >&2 "   -u            update ./prebuilt directory"
		echo >&2 "   -h            This help screen"
		exit 1
}

fast=""

while getopts hfguat: o
do
		case "$o" in
				t)      target="${OPTARG}";;
				a)      all_chipsets=1;;
				f)      fast=1;;
				u)      update=1;;
				h)      usage;;
				g)      do_git=1;;
				[?])    usage;;
		esac
done
shift $(($OPTIND-1))

if [ -z "${all_chipsets}" ];
then
		case ${target} in
						android|android64|host) ;;
						*)             usage;
		esac;
fi


function buildForTarget() {
	target="$1"
	binary_variant=""

	case "$target" in
			android)    binary_variant="32Bit";;
			android64)  binary_variant="64Bit";;
			host)       binary_variant="";;
	esac

	# Link to latest successful build
	LATEST=build-${HOST}-${target}-latest

	if [ -z "${fast}" ];
	then
		BUILD_DIR=$(mktemp -d build-XXXXXXXXXX)
	else
		BUILD_DIR=${LATEST}
	fi

	cd ${BUILD_DIR}
	OUTPUT_DIR=`pwd`

	export MSD_DESTDIR="${OUTPUT_DIR}/out"

	echo "----------------------------------------------"
	echo "Building $binary_variant binaries on $HOST...(${OUTPUT_DIR})"

	case ${target} in
		android)
			# Intentionally use old sysroot for 32-bit since older phones (up to Android 5.1) lack the
			# symbol "__register_atfork" in the C library => The binaries fail to start on older phones
			# https://github.com/android/ndk/issues/964#issuecomment-485182237
			export SYSROOT="${NDK_DIR}/platforms/android-22/arch-arm/"
			export MSD_CONFIGURE_OPTS="--host arm-linux-androideabi --prefix=${MSD_DESTDIR}"
			export PATH=${PATH}:${NDK_DIR}/toolchains/arm-linux-androideabi-4.9/prebuilt/${HOST}/bin/
			# Make sure that "clang" points to NDK clang, not to /usr/bin/clang of the host system
			export PATH=${NDK_DIR}/toolchains/llvm/prebuilt/${HOST}/bin/:${PATH}
			export CROSS_COMPILE=arm-linux-androideabi
			export RANLIB=arm-linux-androideabi-ranlib
			export CC=armv7a-linux-androideabi22-clang
			export CFLAGS="--sysroot=${SYSROOT} -nostdlib -I${NDK_DIR}/sysroot/usr/include/  -I${NDK_DIR}/sysroot/usr/include/arm-linux-androideabi/ -DANDROID_ABI=armeabi-v7a"
			export CPPFLAGS="-I${NDK_DIR}/sysroot/usr/include/  -I${NDK_DIR}/sysroot/usr/include/arm-linux-androideabi/"
			export LDFLAGS="--sysroot=${SYSROOT} -Wl,-rpath-link=${NDK_DIR}/toolchains/llvm/prebuilt/${HOST}/sysroot/usr/lib/arm-linux-androideabi/,-L${NDK_DIR}/toolchains/llvm/prebuilt/${HOST}/sysroot/usr/lib/arm-linux-androideabi/"
			export LIBS="-lc -lm"
			export GSM_PARSER_MAKE_ARGS="TARGET=android PCAP=1 PREFIX=${MSD_DESTDIR} DESTDIR=${MSD_DESTDIR}/gsm-parser SYSROOT=${SYSROOT} CC=armv7a-linux-androideabi28-clang"
			export OPENSSL_TARGET="android-arm"
			;;
		android64)
			export SYSROOT="${NDK_DIR}/platforms/android-28/arch-arm64/"
			export MSD_CONFIGURE_OPTS="--host aarch64-linux-android --prefix=${MSD_DESTDIR}"
			export PATH=${PATH}:${NDK_DIR}/toolchains/arm-linux-androideabi-4.9/prebuilt/${HOST}/bin/
			# Make sure that "clang" points to NDK clang, not to /usr/bin/clang of the host system
			export PATH=${NDK_DIR}/toolchains/llvm/prebuilt/${HOST}/bin/:${PATH}
			export CROSS_COMPILE=aarch64-linux-android
			export RANLIB=aarch64-linux-android-ranlib
			export CC=aarch64-linux-android28-clang
			export CFLAGS="--sysroot=${SYSROOT} -nostdlib -I${NDK_DIR}/sysroot/usr/include/  -I${NDK_DIR}/sysroot/usr/include/aarch64-linux-android/ -DANDROID_ABI=arm64-v8a"
			export CPPFLAGS="-I${NDK_DIR}/sysroot/usr/include/  -I${NDK_DIR}/sysroot/usr/include/aarch64-linux-android/"
			export LDFLAGS="--sysroot=${SYSROOT} -Wl,-rpath-link=${NDK_DIR}/toolchains/llvm/prebuilt/${HOST}/sysroot/usr/lib/aarch64-linux-android/,-L${NDK_DIR}/toolchains/llvm/prebuilt/${HOST}/sysroot/usr/lib/aarch64-linux-android/"
			export LIBS="-lc -lm"
			export GSM_PARSER_MAKE_ARGS="TARGET=android PCAP=1 PREFIX=${MSD_DESTDIR} DESTDIR=${MSD_DESTDIR}/gsm-parser SYSROOT=${SYSROOT} install"
			export OPENSSL_TARGET="android-arm64"
			;;
		host)
			export MSD_CONFIGURE_OPTS="--prefix=${MSD_DESTDIR}"
			export GSM_PARSER_MAKE_ARGS="TARGET=host PCAP=1 PREFIX=${MSD_DESTDIR}"
			;;
		*)
			# Shouldn't happen
			echo "Invalid target \"${target}\""
			exit 1;
	esac

	mkdir -p ${MSD_DESTDIR}

	# Do not build dependencies in fast mode
	if [ -z "${fast}" ];
	then
		TARGETS="libosmocore libasn1c libosmo-asn1-rrc"
	fi

	# Build OpenSSL and diag helper only for Android
	if [ "x${target}" = "xandroid" -o "x${target}" = "xandroid64" ] && [ "x${fast}" = "x" ];
	then
		TARGETS="${TARGETS} openssl diag_helper"
	fi

	TARGETS="${TARGETS} gsm-parser"

	for i in ${TARGETS}; do
			echo -n "Building $i..."
			cd $OUTPUT_DIR
			if ${BASE_DIR}/scripts/compile_$i.sh > $OUTPUT_DIR/$i.compile_log 2>&1;then
				echo OK
			else
				echo "Failed!"
				echo "Please view log file $OUTPUT_DIR/$i.compile_log"
				exit 1
			fi
	done

	PARSER_DIR=${OUTPUT_DIR}/parser

	if [ "x${target}" = "xandroid" ] || [ "x${target}" = "xandroid64" ];
	then
		# Install parser
		install -d ${PARSER_DIR}
		install -m 755 ${OUTPUT_DIR}/out/lib/libasn1c.so           ${PARSER_DIR}/libasn1c.so
		install -m 755 ${OUTPUT_DIR}/out/lib/libosmo-asn1-rrc.so   ${PARSER_DIR}/libosmo-asn1-rrc.so
		install -m 755 ${OUTPUT_DIR}/out/lib/libosmocore.so        ${PARSER_DIR}/libosmocore.so
		install -m 755 ${OUTPUT_DIR}/out/lib/libosmogsm.so         ${PARSER_DIR}/libosmogsm.so
		install -m 755 ${OUTPUT_DIR}/out/gsm-parser/diag_import       ${PARSER_DIR}/libdiag_import.so
		install -m 755 ${OUTPUT_DIR}/out/gsm-parser/libcompat.so      ${PARSER_DIR}/libcompat.so

		install -m 644 ${OUTPUT_DIR}/out/gsm-parser/sm_2g.sql    ${PARSER_DIR}/sm_2g.sql
		install -m 644 ${OUTPUT_DIR}/out/gsm-parser/sm_3g.sql    ${PARSER_DIR}/sm_3g.sql
		install -m 644 ${OUTPUT_DIR}/out/gsm-parser/mcc.sql      ${PARSER_DIR}/mcc.sql
		install -m 644 ${OUTPUT_DIR}/out/gsm-parser/mnc.sql      ${PARSER_DIR}/mnc.sql
		install -m 644 ${OUTPUT_DIR}/out/gsm-parser/hlr_info.sql ${PARSER_DIR}/hlr_info.sql
		install -m 644 ${OUTPUT_DIR}/out/gsm-parser/sm.sql       ${PARSER_DIR}/sm.sql

		install -m 644 ${BASE_DIR}/gsm-parser/cell_info.sql ${PARSER_DIR}/cell_info.sql
		install -m 644 ${BASE_DIR}/gsm-parser/si.sql        ${PARSER_DIR}/si.sql
		install -m 644 ${BASE_DIR}/gsm-parser/sms.sql       ${PARSER_DIR}/sms.sql
		install -m 644 ${BASE_DIR}/gsm-parser/anonymize.sql ${PARSER_DIR}/anonymize.sql

		# Put the smime crt into the library directory since it needs to be a physical
		# file on the Android system so that it can be accessed from the openssl binary.
		# Other parts of the App like assets are not stored as read files on the Android
		# system and therefore can only be used from the Android java code but not from
		# native binaries.

		install -m 755 ${BASE_DIR}/openssl/apps/openssl               ${PARSER_DIR}/libopenssl.so
		install -m 755 ${BASE_DIR}/smime.crt                         ${PARSER_DIR}/libsmime_crt.so

		# Really dirty hack: The Android build system and package installer require
		# all files in the native library dir to have a filename like libXXX.so. If
		# the file extension ends with .so.5, it will not be copied to the APK file.
		# So the following line of perl patches all references so that the libraries
		# are found with a .so extension instead of .so.[digit]
		perl -i -pe 's/libasn1c\.so\.0/libasn1c.so\0\0/gs;s/libosmo-asn1-rrc\.so\.0/libosmo-asn1-rrc.so\0\0/gs;s/libosmocore\.so\.6/libosmocore.so\0\0/gs;s/libosmogsm\.so\.5/libosmogsm.so\0\0/gs' ${PARSER_DIR}/*.so

	fi

	ln -sf ${BUILD_DIR} ../${LATEST}

	# Update prebuilt dir
	if [ "x${update}" = "x1" ];
	then
			DST=${BASE_DIR}/prebuilt
			if [ "x${target}" = "xandroid" ];
			then
				 DST=${DST}/32/
			 mkdir -p ${DST}
				 cp ${BASE_DIR}/diag_helper/libs/armeabi-v7a/libdiag-helper.so ${DST}
			elif [ "x${target}" = "xandroid64" ];
			then
				 DST=${DST}/64/
			 mkdir -p ${DST}
				 cp ${BASE_DIR}/diag_helper/libs/arm64-v8a/libdiag-helper.so ${DST}
			else
				 cp ${BASE_DIR}/diag_helper/libs/armeabi/libdiag-helper.so ${BASE_DIR}/prebuilt/
			fi

		cp ${PARSER_DIR}/*.so ${DST}
		cp ${PARSER_DIR}/*.sql ${BASE_DIR}/prebuilt
	fi

}


# set platform
MACH=$(uname -m)
KERN=$(uname -s)

export ANDROID_NDK_HOME="$NDK_DIR"

case ${KERN} in
				Darwin) HOST="darwin-${MACH}";;
				Linux)  HOST="linux-${MACH}";;
				*)      echo "Unknown platform ${KERN}-${MACH}!"; exit 1;;
esac



export BASE_DIR="$( cd "$( dirname $0 )" && pwd )"
if [ -n "${do_git}" ];then
# update submodules if necessary
		if [ ! "$(ls -A libasn1c)" -a "x${fast}" = "x" ];
		then
		(cd .. && git submodule init contrib/libasn1c)
		fi

		if [ ! "$(ls -A libosmocore)" -a "x${fast}" = "x" ];
		then
	(cd .. && git submodule init contrib/libosmocore)
		fi

		if [ ! "$(ls -A gsm-parser)" -a "x${fast}" = "x" ];
		then
	(cd .. && git submodule init contrib/gsm-parser)
		fi

		if [ ! "$(ls -A openssl)" -a "x${fast}" = "x" ];
		then
		(cd .. && git submodule init contrib/openssl)
		fi
fi

if [ -n "${do_git}" ];then
		if [ "x${fast}" = "x" ];
		then
	(cd .. && \
			git submodule update contrib/libasn1c && \
			git submodule update contrib/libosmocore && \
			git submodule update contrib/gsm-parser && \
			git submodule update contrib/openssl)
		fi
fi

if [ ! -z "${all_chipsets}" ];
then
		echo "Building 32Bit AND 64Bit variants..."
		buildForTarget "android"
		buildForTarget "android64"
else
		case ${target} in
						android|android64|host) ;;
						*)             usage;
		esac;

		buildForTarget ${target}
fi

echo DONE
