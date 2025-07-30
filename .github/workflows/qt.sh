#!/bin/bash

###############################################################################
# This script allows for building Qt versions that wolfSSL supports.
# A patch for Qt 5.15.2 will be applied to allow for a wolfSSL config.
# An OpenSSL build option was added to demonstrate that both options work.
#
# Instructions:
#   It is reccomended to do each unique build in a seperate directory.
#   Run the script "./build-qt-wolfssl.sh"
#   Follow the prompts for Qt and SSL versions.
#
# For any questions or problems, please contact:
# Original Author:  Aaron Jense
# Updated by : HM
# Contact: hide@wolfssl.com
###############################################################################

###############################################################################
# Environment
###############################################################################
HOME=$(cd $(dirname $0);pwd)
WOLFINSTDIR=/wolfssl-install

QT_BUILDDIR=qt5_build
QT_TEST_DIR=$QT_BUILDDIR/qtbase/tests/auto/network/ssl
#PATCH_DIR=/home/miyazakh/workspace/jenkins
PATCH_DIR=$HOME
PATCH_V5158_DIR=${HOME}/v5158_patch
PATCH_V5159_DIR=${HOME}/v5159_patch
PATCH_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/wolfssl-qt-515.patch
UPATCH_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/wolfssl-qt-515-unit-test.patch

# Certs URL
CERT1_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/qssl_wolf/certs/ca-cert.pem
CERT2_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/qssl_wolf/certs/client-cert.pem
CERT3_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/qssl_wolf/certs/client-key.pem
CERT4_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/qssl_wolf/certs/server-cert.pem
CERT5_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/qssl_wolf/certs/server-key.pem
# Unit Test Program URL
UT1_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/qssl_wolf/qssl_wolf.pro
UT2_WGETPATH=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/qssl_wolf/tst_wolfssl.cpp

# Patch files for v5158
PATCH_v5158_WGETPATH1=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/5.15.8/qsslcertificate.patch
PATCH_v5158_WGETPATH2=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/5.15.8/qsslsymbols_cpp.patch
PATCH_v5158_WGETPATH3=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/5.15.8/qsslsymbols_h.patch
PATCH_v5158_WGETPATH4=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/5.15.8/v5158_patch.sh
PATCH_v5158_WGETPATH5=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/5.15.8/v5158_wolf_unitest.patch
# Patch files for v5159
PATCH_v5159_WGETPATH1=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/5.15.9/qsslcertificate_openssl_v5159.patch
PATCH_v5159_WGETPATH2=https://raw.githubusercontent.com/wolfSSL/osp/master/qt/5.15.9/v5159_patch.sh

export LD_LIBRARY_PATH="${HOME}/${WOLFINSTDIR}/lib:$LD_LIBRARY_PATH"
###############################################################################
# wolfSSL Setup
###############################################################################
WOLFSSL_QT_CONFIG="-platform linux-g++ -wolfssl-linked -developer-build -opensource -confirm-license -no-opengl -nomake examples"
WOLFSSL_CONFIG=(--enable-qt --enable-qt-test --enable-alpn --enable-rc2 --prefix=${HOME}/${WOLFINSTDIR} CFLAGS="-DWOLFSSL_ERROR_CODE_OPENSSL -DWOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS=0x1b -DOPENSSL_COMPATIBLE_DEFAULTS -DWC_DISABLE_RADIX_ZERO_PAD -DALLOW_INVALID_CERTSIGN -DWOLFSSL_NO_ASN_STRICT")
#WOLFSSL_INCLUDE="-I${HOME}/${WOLFINSTDIR}/include/wolfssl -I$HOME/$WOLFINSTDIR/include"
WOLFSSL_INCLUDE="-I${HOME}/${WOLFINSTDIR}/include/wolfssl -I${HOME}/${WOLFINSTDIR}/include"
export WOLFSSL_LIBS="-L${HOME}/${WOLFINSTDIR}/lib -lwolfssl"
###############################################################################
# OpenSSL Setup
###############################################################################
OPENSSL_QT_CONFIG="-openssl-linked -developer-build -opensource -confirm-license"
OPENSSL_CONFIG="--prefix=$HOME/openssl-install --openssldir=$HOME/openssl-install"
OPENSSL_INCLUDE="-I$WORKSPACE/openssl-install/include/openssl -I$WORKSPACE/openssl-install/include"
export OPENSSL_LIBS="-L$WORKSPACE/openssl-install/lib -lcrypto -lssl"
export OPENSSL_VERSION_NUMBER=0x1000100fL

###############################################################################
# Default Set up
###############################################################################
#QT_VERSION="5.15.2"
QT_VERSION="v5.15.9-lts-lgpl"
QT_PATCH="${PATCH_DIR}/wolfssl-qt-515.patch"
QT_UNITTEST_PATCH="${PATCH_DIR}/wolfssl-qt-515-unit-test.patch"
SSL_VERSION="wolfSSL"
QT_WOLF_UNIT_TEST="qssl_wolf"
QT_WOLF_UNIT_TEST_PRG="tst_wolfssl.cpp"
QT_WOLF_UNIT_TEST_PRG_PATCH="$HOME/unitprg.patch"
################################################################################
## Retreive Path files and Test files
################################################################################
GetPatch_v5159() {
    # Retreive path files from URL
    if [ -d "$PATCH_V5159_DIR" ]; then
        rm -rf "$PATCH_V5159_DIR"
    fi

    mkdir "${PATCH_V5159_DIR}"

    cd "${PATCH_V5159_DIR}"

    wget $PATCH_v5159_WGETPATH1  --no-check-certificate
    wget $PATCH_v5159_WGETPATH2  --no-check-certificate

    cd "${HOME}"
}

GetPatch_v5158() {
    # Retreive path files from URL
    if [ -d "$PATCH_V5158_DIR" ]; then
        rm -rf "$PATCH_V5158_DIR"
    fi

    mkdir "${PATCH_V5158_DIR}"

    cd "${PATCH_V5158_DIR}"

    wget $PATCH_v5158_WGETPATH1  --no-check-certificate
    wget $PATCH_v5158_WGETPATH2  --no-check-certificate
    wget $PATCH_v5158_WGETPATH3  --no-check-certificate
    wget $PATCH_v5158_WGETPATH4  --no-check-certificate
    wget $PATCH_v5158_WGETPATH5  --no-check-certificate

    cd "${HOME}"
}

GetPatch_Test () {

    # Retreive path files from URL
    if [ -f "$QT_PATCH" ]; then
        rm -f "$QT_PATCH"
    fi

    if [ -f "$QT_UNITTEST_PATCH" ]; then
        rm -f "${QT_UNITTEST_PATCH}"
    fi

    wget $PATCH_WGETPATH  --no-check-certificate
    wget $UPATCH_WGETPATH --no-check-certificate

    # Retreive unit test program from URL
    if [ -d "$QT_WOLF_UNIT_TEST" ]; then
        rm -rf "$QT_WOLF_UNIT_TEST"
    fi

    mkdir "$QT_WOLF_UNIT_TEST"

    cd "$QT_WOLF_UNIT_TEST"
    mkdir "certs"

    cd "certs"

    wget $CERT1_WGETPATH  --no-check-certificate
    wget $CERT2_WGETPATH  --no-check-certificate
    wget $CERT3_WGETPATH  --no-check-certificate
    wget $CERT4_WGETPATH  --no-check-certificate
    wget $CERT5_WGETPATH  --no-check-certificate

    cd "$HOME/$QT_WOLF_UNIT_TEST"
    wget $UT1_WGETPATH  --no-check-certificate
    wget $UT2_WGETPATH  --no-check-certificate

    # apply patch for unit test program to be ran as jenkins job
    patch ./$QT_WOLF_UNIT_TEST_PRG $QT_WOLF_UNIT_TEST_PRG_PATCH
}
################################################################################
## User Setup
################################################################################
User_Setup () {
 echo "Choose Qt Version to build."

 options=("5.12.4" "5.13" "5.15" "Quit")

 select opt in "${options[@]}"
 do
     case $opt in
         "5.12.4")
             echo "Building Qt 5.12.4"
             QT_VERSION="5.12.4"
             QT_PATCH="wolfssl-qt-512.patch"
             QT_UNITTEST_PATCH=""
             break
             ;;
         "5.13")
             echo "Building Qt 5.13"
             QT_VERSION="5.13"
             QT_PATCH="wolfssl-qt-513.patch"
             QT_UNITTEST_PATCH=""
             break
             ;;
         "5.15")
             echo "Building Qt 5.15"
             #QT_VERSION="5.15.2"
             QT_VERSION="v5.15.9-lts-lgpl"
             QT_PATCH="wolfssl-qt-515.patch"
             #QT_UNITTEST_PATCH="wolfssl-qt-515-unit-test.patch"
             QT_UNITTEST_PATCH="v5158_wolf_unitest.patch"
             break
             ;;
         "Quit")
             exit 0
             ;;
         *) echo "Unknown Option: $REPLY";;
     esac
 done

 echo "Choose SSL Version to build."
 options=("wolfSSL" "OpenSSL" "Quit")
 select opt in "${options[@]}"
 do
     case $opt in
         "wolfSSL")
             SSL_VERSION="wolfSSL"
             break
             ;;
         "OpenSSL")
             SSL_VERSION="OpenSSL"
             break
             ;;
         "Quit")
             exit 0
             ;;
         *) echo "Unknown Option: $REPLY";;
     esac
 done

 echo "Building Qt $QT_VERSION with $SSL_VERSION"

}

################################################################################
## Build SSL Library (wolfSSL or OpenSSL)
################################################################################
build_SSLLib () {

 if [ $SSL_VERSION = "wolfSSL" ]; then
     # Configure and install wolfSSL
     if [ -d "wolfssl" ]; then
         echo rm wolfssl
         rm -rf wolfssl
     fi

     if [ ! -d "wolfssl" ]; then
         git clone --depth 1 https://github.com/wolfssl/wolfssl
     else
         cd "$HOME"/wolfssl
         git clean -dfx
         git pull
     fi

     cd "$HOME"/wolfssl
     git remote -v

     ./autogen.sh
     ./configure "${WOLFSSL_CONFIG[@]}"
     make check
     if [ $? -ne 0 ]; then
         echo "wolfSSL Unit Test Failure"
         exit -1
     else
         make install
     fi

     QT_CONFIG=${WOLFSSL_QT_CONFIG}
     QT_INCLUDE=${WOLFSSL_INCLUDE}
     echo "qt config $QT_CONFIG"
     echo "qt include $QT_INCLUDE"
 elif [ $SSL_VERSION = "OpenSSL" ]; then
     # Configure and install wolfSSL
     if [ ! -d "openssl" ]; then
         git clone git://git.openssl.org/openssl.git
     fi

     cd "$HOME"/openssl
     ./config "$OPENSSL_CONFIG"
     make -j

     QT_CONFIG=${OPENSSL_QT_CONFIG}
     QT_INCLUDE=${OPENSSL_INCLUDE}
 else
     echo "Error Building $SSL_VERSION"
 fi
}

###############################################################################
# Configure and build Qt
###############################################################################
build_Qt () {
 cd "$HOME"
 if [ ! -d "qt5" ]; then
     git clone https://github.com/qt/qt5.git
 else
     cd "$HOME"/qt5/qtbase
     git checkout .
 fi

 cd "$HOME"/qt5
 git checkout $QT_VERSION
 perl ./init-repository --module-subset=qtbase
 if [ $? -ne 0 ]; then
     echo "FAILED: fetching qtbase"
     exit -1
 fi

 cd "$HOME"/qt5/qtbase

 printf "\nApplying Patch on Qt for wolfSSL configuration.\n"
 printf "This shouldn't break OpenSSL configurations.\n\n"
 if [ ! -f "$QT_PATCH" ]; then
    echo "Can't locate patch file ${QT_PATCH}, please check the file path and try again"
    exit 1
 fi

 echo "${QT_PATCH}"
 git apply -v "${QT_PATCH}"
 if [ $? -ne 0 ]; then
     echo "FAILED: Applying Patch"
     exit -1
 fi

 cp "${PATCH_V5158_DIR}"/*.patch "$HOME"/qt5/
 cp "${PATCH_V5158_DIR}"/v5158_patch.sh "$HOME"/qt5/
 cp "${PATCH_V5159_DIR}"/*.patch "$HOME"/qt5/
 cp "${PATCH_V5159_DIR}"/v5159_patch.sh "$HOME"/qt5/

 echo "mem fix patch"
 cd "$HOME"/qt5/
 # the shell applies unit test as well
 sh ./v5158_patch.sh

 echo "v5159 patch"
 sh ./v5159_patch.sh

 cd "$HOME"/qt5/qtbase

 if [ ! -f "$QT_UNITTEST_PATCH" ]; then
    echo "Can't locate patch file ${QT_UNITTEST_PATCH}, please check the file path and try again"
    exit 1
 fi
 if [ $QT_UNITTEST_PATCH != "" ]; then
     echo "Apply unit test patch"
     patch ./tests/auto/network/ssl/ssl.pro ../v5158_wolf_unitest.patch

     cp -r "$PATCH_DIR"/qssl_wolf "$HOME"/qt5/qtbase/tests/auto/network/ssl
     cp "$HOME"/qt5/qtbase/tests/auto/network/ssl/qsslsocket/certs/* "$HOME"/qt5/qtbase/tests/auto/network/ssl/qssl_wolf/certs/
 fi

 if [ -d "${HOME}/${QT_BUILDDIR}" ]; then
    rm -rf "${HOME}/${QT_BUILDDIR}"
 fi
 mkdir "${HOME}/${QT_BUILDDIR}"

 cd "${HOME}/${QT_BUILDDIR}"
 echo "../qt5/configure ${QT_CONFIG} ${QT_INCLUDE}"
 ../qt5/configure $QT_CONFIG $QT_INCLUDE

 make -j
 if [ $? -ne 0 ]; then
     echo "FAILED : Qt build"
     exit -1
 fi

}

###############################################################################
# Run Qt unit test
###############################################################################
run_test () {
 no_pid=-1
 openssl_pid=$no_pid

 echo cp "$PATCH_DIR"/run_unit_test.sh "${HOME}/${QT_TEST_DIR}"
 cp "$PATCH_DIR"/run_unit_test.sh "${HOME}/${QT_TEST_DIR}"
 cd "${HOME}/${QT_TEST_DIR}"

 ./run_unit_test.sh

 if [ $? -ne 0 ]; then
     echo "FAILED : Qt unit test"
     exit -1
 fi
 echo "qt_unittest.log"
 cat "${HOME}/${QT_TEST_DIR}"/qt_unittest.log

 echo "unitlog.gold"
 cat "$PATCH_DIR"/unitlog.gold

 diff "${HOME}/${QT_TEST_DIR}"/qt_unittest.log "$PATCH_DIR"/unitlog.gold

 if [ $? -ne 0 ]; then
     echo "Qt test log has differences to gold file"
     exit -1
 fi
}

run_test_opnessl () {
 no_pid=-1
 openssl_pid=$no_pid

 cp "$HOME"/run_unit_test.sh "${HOME}/${QT_TEST_DIR}"
 cd "${HOME}/${QT_TEST_DIR}"

 if type openssl >/dev/null 2>&1; then

    openssl s_server -accept 11111 -key "$HOME"/wolfssl/certs/server-key.pem -cert "$HOME"/wolfssl/certs/server-cert.pem  -WWW &
    openssl_pid=$!
    echo openssl pid $openssl_pid

    ./run_unit_test.sh

    if [ $openssl_pid != $no_pid ]; then

        echo kill openssl pid $openssl_pid
        kill -9 $openssl_pid
        openssl_pid=$no_pid
    fi
 fi

 if [ $? -ne 0 ]; then
     echo "FAILED : Qt unit test"
     exit -1
 else
     echo "SUCCEED: Qt unit test!"
     exit 1
 fi
}

###############################################################################
# main
###############################################################################
#User_Setup

if [ "$#" -eq 1 ]; then
 QT_VERSION=$1
fi

echo "Qt version : ${QT_VERSION}"

cd "$HOME"

echo "Get patch file from" "${PATCH_WGETPATH}"
GetPatch_Test
GetPatch_v5158
GetPatch_v5159
cd "$HOME"

echo "Build SSL library"
build_SSLLib
cd "$HOME"

echo "Build Qt"
echo "g++ version"
g++ --version

build_Qt
cd "$HOME"

echo "LD_LIBRARY_PATH" "${LD_LIBRARY_PATH}"
echo "Run Qt Unit test"
run_test
cd "$HOME"

echo "END OF TEST"