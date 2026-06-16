{
  description = "gopkcs11 - CGO-free PKCS#11 binding for Go using purego";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    flake-checks.url = "github:kradalby/flake-checks";
    flake-checks.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, flake-checks }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        fc = flake-checks.lib;
        common = {
          inherit pkgs;
          root = ./.;
          pname = "gopkcs11";
          version = "0.0.1";
          vendorHash = "sha256-qapWMnRP6ZzRIelgJ8vdi7lvbApjKKvbIDoZMn8s9u4=";
          goPkg = pkgs.go_1_26;
        };

        softhsm2-lib = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";

        # The package is //go:build linux throughout, so the Go checks only
        # exist on Linux (CI runs x86_64-linux). The softhsm integration tests
        # hard-fail without a module, so gotest provides softhsm + config.
        goOutputs = pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          packages.default = fc.goBuild common;
          formatter = fc.formatter common;
          checks = {
            build = fc.goBuild common;
            golangci-lint = fc.goLint common;
            formatting = fc.goFormat common;
            gotest = fc.goTest (common // {
              nativeCheckInputs = [ pkgs.softhsm ];
              testEnv = ''
                export SOFTHSM_LIB=${softhsm2-lib}
                export SOFTHSM_TOKENS_DIR=$TMPDIR/tokens
                mkdir -p $SOFTHSM_TOKENS_DIR
                export SOFTHSM2_CONF=$TMPDIR/softhsm2.conf
                {
                  echo "directories.tokendir = $SOFTHSM_TOKENS_DIR"
                  echo "objectstore.backend = file"
                  echo "log.level = INFO"
                  echo "slots.removable = false"
                } > $SOFTHSM2_CONF
              '';
            });
          };
        };
      in
      goOutputs // {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go
            pkgs.softhsm
            pkgs.golangci-lint
            pkgs.opensc
          ]
          # TPM2 PKCS#11 support (for //go:build tpm2 integration tests) is
          # Linux-only; keep the dev shell evaluable on Darwin.
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.tpm2-pkcs11
            pkgs.tpm2-pkcs11.bin
            pkgs.tpm2-tools
          ];

          shellHook = ''
            export CGO_ENABLED=0
            export GOOS=linux

            # SoftHSM2 configuration
            export SOFTHSM_TOKENS_DIR="$PWD/.softhsm/tokens"
            mkdir -p "$SOFTHSM_TOKENS_DIR"

            export SOFTHSM2_CONF="$PWD/.softhsm/softhsm2.conf"
            if [ ! -f "$SOFTHSM2_CONF" ]; then
              cat > "$SOFTHSM2_CONF" <<EOF
            directories.tokendir = $SOFTHSM_TOKENS_DIR
            objectstore.backend = file
            log.level = INFO
            slots.removable = false
            EOF
            fi

            export SOFTHSM_LIB="${softhsm2-lib}"

            echo "gopkcs11 dev shell"
            echo "  CGO_ENABLED = $CGO_ENABLED"
            echo "  SOFTHSM_LIB = $SOFTHSM_LIB"
          '';
        };
      }
    );
}
