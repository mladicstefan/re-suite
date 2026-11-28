{
  description = "re-suite: every tool the workspace, its checks and its trial scripts run";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      # shortcut: Linux only, the one system the checks are run on; add a system here when one is.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      shell =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          # The version and components stay in rust-toolchain.toml, where rustup reads them too.
          # The two extra targets are only linted (ledger-os), never linked.
          rust = pkgs.rust-bin.fromRustupToolchain (
            (pkgs.lib.importTOML ./rust-toolchain.toml).toolchain
            // {
              targets = [
                "x86_64-pc-windows-gnu"
                "aarch64-apple-darwin"
              ];
            }
          );
          # nixpkgs still has 0.21.0, which fails every unmaintained crate in the tree; from 0.22.0
          # only the workspace's own dependencies are checked, and deny.toml does not say which it wants.
          # shortcut: built from source with hashes kept here; delete once nixpkgs has 0.22 or later.
          cargo-deny = pkgs.cargo-deny.overrideAttrs (
            final: prev: {
              version = "0.22.1";
              src = prev.src.override { hash = "sha256-elROwJFPjEJmVm6dSpQ2YvdbjyM2JaOYFK8hGf4JupM="; };
              cargoHash = "sha256-vAG2+4tiwKLO5lHRihIYYrPtW1OPEDUijVPs1WeM7ps=";
            }
          );
          # Wakaru, webcrack and retire.js at the versions in tools/js/package-lock.json.
          jsModules = pkgs.importNpmLock.buildNodeModules {
            npmRoot = ./tools/js;
            inherit (pkgs) nodejs;
          };
          jsTools = pkgs.runCommand "re-suite-js-tools" { } ''
            mkdir -p $out/bin
            for tool in webcrack retire; do
              ln -s ${jsModules}/node_modules/.bin/$tool $out/bin/$tool
            done
          '';
          # Wakaru's npm package runs a prebuilt program that asks for the host's loader, and a
          # confined tool sees only the store; this copy loads the store's glibc instead.
          wakaru = pkgs.stdenv.mkDerivation {
            name = "wakaru";
            dontUnpack = true;
            nativeBuildInputs = [ pkgs.autoPatchelfHook ];
            installPhase =
              let
                arch = { x86_64-linux = "x64"; aarch64-linux = "arm64"; }.${system};
              in
              "install -Dm755 ${jsModules}/node_modules/@wakaru/cli-linux-${arch}/wakaru $out/bin/wakaru";
          };
          # The Wappalyzer rule set (wappalyzergo, pinned by go.sum) on saved responses.
          fingerprint = pkgs.buildGoModule {
            pname = "ledger-fingerprint";
            version = "0";
            src = ./tools/fingerprint;
            vendorHash = "sha256-8qKM7GnfBtwkTaOSBFWeIC7tCG1NF153xvYCjb6WoyU=";
          };
        in
        pkgs.mkShell {
          packages = [
            rust
            pkgs.cargo-nextest
            cargo-deny
            pkgs.cargo-machete
            # The trial scripts read programs with it; ledger-mcp finds it by LEDGER_TOOL_RIZIN below.
            pkgs.rizin
            pkgs.kaitai-struct-compiler
            pkgs.gdb
            # Python comes from uv.lock; uv downloads the interpreter itself.
            pkgs.uv
            # Second readings for the trial scripts. objdump and readelf come with the shell's compiler.
            pkgs.llvm
            # `ledger-capture web` finds Chromium by LEDGER_TOOL_CHROMIUM below; Node runs the trial scripts.
            pkgs.nodejs
            pkgs.chromium
            # What the web playbooks run on captured traffic and scripts.
            jsTools
            wakaru
            fingerprint
            pkgs.ast-grep
            pkgs.mitmproxy
            pkgs.prettier
            pkgs.wabt
            pkgs.wasm-tools
          ];
          # ledger-mcp starts an outside program only by the absolute path in its
          # LEDGER_TOOL_<ID> variable, one per adapter in crates/ledger-mcp/src/runner.rs,
          # and never looks on PATH; nor does `ledger-capture web` for the browser.
          # Every tool runs inside bubblewrap, which sees the store and nothing of the host.
          LEDGER_TOOL_BWRAP = "${pkgs.bubblewrap}/bin/bwrap";
          LEDGER_TOOL_RIZIN = "${pkgs.rizin}/bin/rizin";
          LEDGER_TOOL_FINGERPRINT = "${fingerprint}/bin/ledger-fingerprint";
          LEDGER_TOOL_CHROMIUM = "${pkgs.chromium}/bin/chromium";
          LEDGER_TOOL_WAKARU = "${wakaru}/bin/wakaru";
          # No adapter yet; ledger-os's tests start each one confined and ask its version.
          LEDGER_TOOL_WEBCRACK = "${jsTools}/bin/webcrack";
          LEDGER_TOOL_RETIRE = "${jsTools}/bin/retire";
          LEDGER_TOOL_AST_GREP = "${pkgs.ast-grep}/bin/ast-grep";
          # The tests' stand-in for a tool: a shell from the store, the only place a confined tool sees.
          # Its loadable builtins (lib/bash: mkdir, ln) let a stand-in leave files and links.
          LEDGER_TEST_SH = "${pkgs.bash}/bin/sh";
        };
    in
    {
      devShells = nixpkgs.lib.genAttrs systems (system: {
        default = shell system;
      });
    };
}
