#!/bin/bash

set -e

script_dir="$( cd "$( dirname "$0" )" && pwd )"
install_dir=""
arch=`uname -m`

if [[ $1 == static ]]; then
  openssl_opts="no-shared"
  libev_opts="--enable-shared=no --enable-static=yes"
  cmake_opts="-DLIBS_BUILD_TYPE=STATIC"
else
  openssl_opts=""
  libev_opts="--enable-shared=yes --enable-static=no"
  cmake_opts="-DLIBS_BUILD_TYPE=SHARED"
fi

generate_stub() {
  local sdir="$1"
  local fname="$2"
  mkdir -p "$sdir"
  touch "$sdir/$fname"
}

clean_submodule() {
  local sdir="$1"
  echo "[ Cleaning submodule at $sdir ]"
  pushd "$sdir"
  git reset --hard
  git submodule update --init --recursive
  git submodule foreach git reset --hard
  git clean -dfx --force
  git submodule foreach --recursive git clean -dfx --force
  popd
  echo "[ Done ]"
}

clean_dir() {
  local idir="$1"
  echo "[ Removing temporary directory at $idir ]"
  if [[ ! -z $idir && -d $idir ]]; then
    rm -rfv "$idir"
  fi
  echo "[ Done ]"
}

install_dir() {
  local inst_dir="$1"
  local dest_dir="$2"
  echo "[ Installing $inst_dir directory to $dest_dir ]"
  rm -rf "$dest_dir"
  cp -r "$inst_dir" "$dest_dir"
  echo "[ Done ]"
}

extract_tarball() {
  local sdir="$1"
  local tb_name="$2"
  pushd "$sdir"
  tb_file=`find . -type f -name "$tb_name" | head -1`
  [[ -z $tb_file ]] && echo "sourve tarball not found!" && exit 1
  echo "[ Extracting tarball $tb_file to $sdir ]"
  extractor=""
  [[ $tb_file =~ ^.*"tar.gz"$ ]] && extractor="gunzip -c"
  [[ -z $extractor ]] && echo "unsupported extractor!" && exit 1
  $extractor "$tb_file" | tar xf -
  popd
}

build_stuff() {
  local arch="$1"

  clean_submodule "$script_dir/External/openssl"
  clean_dir "$script_dir/External/dist/openssl_linux_$arch"
  pushd "$script_dir/External/openssl"
  if [[ $arch == "x86_64" ]]; then
    ./Configure --prefix="$script_dir/External/dist/openssl_linux_$arch" $openssl_opts linux-x86_64 -Os
  elif [[ $arch == "x86" ]]; then
    ./Configure --prefix="$script_dir/External/dist/openssl_linux_$arch" $openssl_opts linux-x86 -Os
  else
    echo "arch is not supported $arch"
  fi
  make -j$(nproc)
  make install_sw
  popd
  clean_submodule "$script_dir/External/openssl"

  clean_dir "$script_dir/External/dist/libev_linux_$arch"
  clean_dir "$script_dir/External/libev-4.25"
  extract_tarball "$script_dir/External" "libev-4.25.tar.*"
  pushd "$script_dir/External/libev-4.25"
  CFLAGS="$CFLAGS -Os" ./configure $libev_opts --with-pic \
  --prefix="$script_dir/External/dist/libev_linux_$arch"
  make
  make install
  popd
  clean_dir "$script_dir/External/libev-4.25"

  clean_submodule "$script_dir/External/nghttp3"
  clean_dir "$script_dir/External/dist/nghttp3_linux_$arch"
  pushd "$script_dir/External/nghttp3"
  patch -p1 -i ../nghttp3-build.patch
  CFLAGS="$CFLAGS -Os" CXXFLAGS="$CXXFLAGS -Os"\
  cmake -DCMAKE_BUILD_TYPE="Release"\
  -DENABLE_LIB_ONLY="TRUE"\
  $cmake_opts\
  -DCMAKE_INSTALL_PREFIX:PATH="$script_dir/External/dist/nghttp3_linux_$arch"\
  .
  make
  make install
  popd
  clean_submodule "$script_dir/External/nghttp3"

  clean_submodule "$script_dir/External/ngtcp2"
  clean_dir "$script_dir/External/dist/ngtcp2_linux_$arch"
  pushd "$script_dir/External/ngtcp2"
  patch -p1 -i ../ngtcp2-build.patch
  CFLAGS="$CFLAGS -Os" CXXFLAGS="$CXXFLAGS -Os"\
  cmake -DCMAKE_BUILD_TYPE="Release"\
  $cmake_opts\
  -DCMAKE_INSTALL_PREFIX:PATH="$script_dir/External/dist/ngtcp2_linux_$arch"\
  .
  make ngtcp2
  make install ngtcp2
  popd
  clean_submodule "$script_dir/External/ngtcp2"
}

build_stuff "$arch"

exit 0

[[ $arch != "x86_64" ]] && exit 0

export CFLAGS="-m32"
export CXXFLAGS="-m32"
export LDFLAGS="-m32"

build_stuff "x86"
