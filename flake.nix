{

  inputs = {
    # updated 2022-02-07
    nixpkgs = {
      type = "github";
      owner = "NixOS";
      repo = "nixpkgs";
      rev = "a102368ac4c3944978fecd9d7295a96d64586db5";
      narHash = "sha256-hgdcyLo2d8N2BmHuPMWhsXlorv1ZDkhBjq1gMYvFbdo=";
    };
  };

  outputs = { self, nixpkgs, ... }: {
    packages.x86_64-linux.default = nixpkgs.lib.makeOverridable self.derivations.default {
      inherit (nixpkgs.legacyPackages.x86_64-linux.stdenv) mkDerivation;
      inherit (nixpkgs.legacyPackages.x86_64-linux) ragel kconfig-frontends liburing;
    };

    derivations.default = {
      mkDerivation,
      ragel,
      kconfig-frontends,
      liburing,
      nats ? { host = "127.0.0.1"; port = "4222"; }
    }:
    mkDerivation {
      name = "lrsyslog";
      srcs = [
        ./Makefile
        ./src
        ./Kconfig
        ./configs
      ];
      unpackPhase = ''
        for file in $srcs; do
          cp -r $file $(stripHash $file)
        done
      '';
      depsBuildBuild = [
        ragel 
        kconfig-frontends 
      ];
      buildInputs = [
        liburing 
      ];
      configurePhase = ''
        make defconfig
      '';
      makeFlags = [ 
        "CONFIG_NATS_HOST=\"${nats.host}\""
        "CONFIG_NATS_PORT=\"${nats.port}\""
      ];
      installFlags = [ "DESTDIR=$(out)" "PREFIX=/" ];
    };

  };

}
