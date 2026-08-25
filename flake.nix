{
  description = "gopkcs11 - CGO-free PKCS#11 binding for Go using purego";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    flake-checks.url = "github:kradalby/flake-checks";
    flake-checks.inputs.nixpkgs.follows = "nixpkgs";
    flake-checks.inputs.flake-utils.follows = "flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      flake-checks,
    }:
    # nixpkgs 26.11 dropped x86_64-darwin, and importing it for that system
    # throws at eval time, so enumerate the systems still supported instead of
    # using eachDefaultSystem.
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        # Build the Go toolchain and Go-based dev tools against the latest Go
        # (go_latest / buildGoLatestModule) rather than the default `go`, which
        # still resolves to an older release in nixpkgs. golangci-lint and gopls
        # already track go_latest upstream, so only gofumpt and gotools need the
        # override. goimports (gotools) ships wrapped with a `go` on PATH, and
        # that `go` must be at least the go.mod directive or GOTOOLCHAIN=auto
        # tries to fetch a toolchain inside the network-less treefmt sandbox.
        goOverlay = _: prev: {
          gofumpt = prev.gofumpt.override { buildGoModule = prev.buildGoLatestModule; };
          gotools = prev.gotools.override {
            buildGoModule = prev.buildGoLatestModule;
            go = prev.go_latest;
          };
        };

        pkgs = import nixpkgs {
          inherit system;
          overlays = [ goOverlay ];
        };
        fc = flake-checks.lib;
        common = {
          inherit pkgs;
          root = ./.;
          pname = "gopkcs11";
          version = "0.0.1";
          vendorHash = "sha256-6GrpGXYZAu5/BtixQpPe2LeEqLPbsAIDC6ZlNqh3ig0=";
          goPkg = pkgs.go_latest;
        };

        softhsm2-lib = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";

        # The package is //go:build linux throughout, so the Go checks only
        # exist on Linux (CI runs x86_64-linux). The softhsm integration tests
        # hard-fail without a module, so gotest provides softhsm + config.
        goOutputs = pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          packages.default = fc.goBuild common;
          formatter = fc.formatter common;
          checks = {
            build = fc.goBuild common;
            golangci-lint = fc.goLint common;
            formatting = fc.goFormat common;
            # zconst.go / zerror_strings.go are derived from the vendored
            # PKCS#11 v2.40 header. constgen is //go:build ignore, so it is
            # invisible to `go generate ./...` and must be named as a file
            # path; pkcs11t.h is not a .go file, so the src filter needs it
            # spelled out or the generator has nothing to read.
            generate = fc.goGenerate (
              common
              // {
                extraSrc = [ ./pkcs11t.h ];
                generateCommand = "go run ./cmd/constgen/main.go";
              }
            );
            gotest = fc.goTest (
              common
              // {
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
              }
            );
          };
        };
      in
      goOutputs
      // {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go_latest
            pkgs.gopls
            pkgs.gofumpt
            pkgs.golangci-lint
            pkgs.prek
            pkgs.softhsm
            pkgs.opensc
          ]
          # TPM2 PKCS#11 support (for //go:build tpm2 integration tests) is
          # Linux-only; keep the dev shell evaluable on Darwin.
          ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
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
