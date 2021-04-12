{
    outputs = inputs@{ self, nixpkgs, ...}: {
        defaultPackage.x86_64-linux = inputs.nixpkgs.legacyPackages.x86_64-linux.stdenv.mkDerivation {
            name = "lsyslog";
            nativeBuildInputs = [ inputs.nixpkgs.legacyPackages.x86_64-linux.ragel ];
        };
    };
}
