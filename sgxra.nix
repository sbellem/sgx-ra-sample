let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs { };
  sgxsdk = import ./sgxsdk.nix { inherit sources; };
in
#pkgs.mkShell {
pkgs.stdenv.mkDerivation {
#pkgs.stdenvNoCC.mkDerivation {
  inherit sgxsdk;
  name = "sgx-ra";
  src = ./.;
  #source $SGX_SDK/environment
  preConfigure = ''
    export SGX_SDK=$sgxsdk/sgxsdk
    export PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
    export PKG_CONFIG_PATH=$SGX_SDK/pkgconfig
    export LD_LIBRARY_PATH=$SGX_SDK/sdk_libs
    ./bootstrap
    '';
  configureFlags = ["--with-sgxsdk=$SGX_SDK"];
  buildInputs = with pkgs; [
    sgxsdk
    unixtools.xxd
    bashInteractive
    autoconf
    automake
    libtool
    #ocaml
    #ocamlPackages.ocamlbuild
    file
    #cmake
    #gnum4
    openssl
    #gnumake
    # FIXME For now, must get glibc from another nixpkgs revision.
    # See https://github.com/intel/linux-sgx/issues/612
    #glibc
    #/nix/store/681354n3k44r8z90m35hm8945vsp95h1-glibc-2.27
    #gcc8
    #texinfo
    #bison
    #flex
    #perl
    #python3
    which
    #git
  ];

  #dontInstall = true;
  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    cp Enclave/Enclave.so $out/bin/
    cp Enclave/Enclave.signed.so $out/bin/
    cp mrsigner $out/bin

    runHook postInstall
  '';
  postInstall = ''
    $sgxsdk/sgxsdk/bin/x64/sgx_sign dump -cssfile enclave_sigstruct_raw -dumpfile /dev/null -enclave $out/bin/Enclave.signed.so
    cp enclave_sigstruct_raw $out/bin/
    ./mrsigner enclave_sigstruct_raw > $out/bin/mrsigner.txt
    '';
  dontFixup = true;
}
