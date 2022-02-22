{

  inputs = {
    # updated 2022-02-07
    nixpkgs = {
      type = "github";
      owner = "NixOS";
      repo = "nixpkgs";
      rev = "a102368ac4c3944978fecd9d7295a96d64586db5";
    };
  };

  outputs = { self, nixpkgs, ...}: {
    defaultPackage.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.stdenv.mkDerivation {
      name = "lrsyslog";
      src = ./.;
      depsBuildBuild = [
        nixpkgs.legacyPackages.x86_64-linux.ragel 
        nixpkgs.legacyPackages.x86_64-linux.kconfig-frontends 
      ];
      buildInputs = [
        nixpkgs.legacyPackages.x86_64-linux.liburing 
      ];
    };
  };

}
