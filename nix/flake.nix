{
  description = "KernKlaw-Linux — Native C AI assistant daemon for Linux";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};

      # ── Core package ────────────────────────────────────────────────
      kernklaw-linux = pkgs.stdenv.mkDerivation rec {
        pname   = "kernklaw-linux";
        version = "0.1.0";
        src     = ../.;

        nativeBuildInputs = with pkgs; [
          cmake pkg-config clang bpftool
        ];

        buildInputs = with pkgs; [
          curl json_c libcap readline libsystemd liburing libbpf
        ];

        cmakeFlags = [
          "-DCMAKE_BUILD_TYPE=Release"
          "-DBUILD_EBPF=OFF"   # Set to ON if building on Linux with BTF
        ];

        postInstall = ''
          # setuid on skill executor
          chmod u+s $out/bin/claw-skill-exec

          # Install systemd units
          install -Dm644 ${src}/systemd/claw-daemon.service \
              $out/lib/systemd/system/claw-daemon.service
          install -Dm644 ${src}/systemd/claw-shell@.service \
              $out/lib/systemd/system/claw-shell@.service
        '';

        meta = with pkgs.lib; {
          description = "KernKlaw-Linux: AI assistant daemon (C99, eBPF, io_uring)";
          homepage    = "https://github.com/kernklaw/kernklaw-linux";
          license     = licenses.mit;
          platforms   = [ "x86_64-linux" "aarch64-linux" ];
          maintainers = [];
        };
      };

      # ── Dev shell ────────────────────────────────────────────────────
      devShell = pkgs.mkShell {
        inputsFrom  = [ kernklaw-linux ];
        packages    = with pkgs; [
          # Build tools
          gcc gdb clang lld cmake ninja pkg-config

          # Deps (runtime + dev)
          curl json_c libcap readline libsystemd liburing libbpf
          bpftool linux-headers

          # Debug / profiling
          strace ltrace valgrind perf
          linuxPackages.bpftrace

          # Container / packaging
          docker docker-compose
          dpkg rpm

          # Editor support
          clang-tools   # clangd, clang-format
          bear          # for compile_commands.json
        ];

        shellHook = ''
          echo "KernKlaw-Linux dev shell"
          echo "  make             — build all binaries"
          echo "  make ebpf        — compile eBPF programs"
          echo "  make install     — install to /usr/local"
          echo "  make test        — run quick tests"
          echo ""
          # Generate compile_commands.json for clangd
          [ -f compile_commands.json ] || \
              bear -- make -n > /dev/null 2>&1 || true
        '';
      };

    in {
      packages = {
        default       = kernklaw-linux;
        kernklaw-linux = kernklaw-linux;
      };

      devShells.default = devShell;

      # ── NixOS module ────────────────────────────────────────────────
      nixosModules.kernklaw-linux = { config, lib, pkgs, ... }:
        with lib;
        let cfg = config.services.kernklaw-linux;
        in {
          options.services.kernklaw-linux = {
            enable = mkEnableOption "KernKlaw-Linux AI daemon";

            model = mkOption {
              type    = types.str;
              default = "llama3.2";
              description = "Default Ollama model to use";
            };

            ollamaHost = mkOption {
              type    = types.str;
              default = "http://127.0.0.1:11434";
              description = "Ollama HTTP API endpoint";
            };

            skillDir = mkOption {
              type    = types.str;
              default = "/etc/claw/skills";
              description = "Directory to search for skills";
            };

            extraArgs = mkOption {
              type    = types.listOf types.str;
              default = [];
              description = "Extra arguments for claw-daemon";
            };

            enableEbpf = mkOption {
              type    = types.bool;
              default = false;
              description = "Enable eBPF hooks (requires root / CAP_BPF)";
            };
          };

          config = mkIf cfg.enable {
            # Ensure claw user exists
            users.users.claw = {
              isSystemUser = true;
              group        = "claw";
              description  = "KernKlaw daemon";
              home         = "/var/lib/claw";
              createHome   = true;
            };
            users.groups.claw = {};

            # Install the package
            environment.systemPackages = [ self.packages.${pkgs.system}.kernklaw-linux ];

            # Skill directory
            environment.etc."claw/skills/.keep".text = "";

            # Systemd service
            systemd.services.claw-daemon = {
              description = "KernKlaw-Linux AI Assistant Daemon";
              after       = [ "network-online.target" "ollama.service" ];
              wants       = [ "network-online.target" ];
              wantedBy    = [ "multi-user.target" ];

              serviceConfig = {
                Type            = "notify";
                NotifyAccess    = "main";
                User            = "claw";
                Group           = "claw";
                ExecStart       = ''
                  ${self.packages.${pkgs.system}.kernklaw-linux}/bin/claw-daemon \
                    -c /etc/claw \
                    -s ${cfg.skillDir} \
                    -m ${cfg.model} \
                    ${concatStringsSep " " cfg.extraArgs}
                '';
                Restart         = "on-failure";
                RestartSec      = "5s";
                RuntimeDirectory = "claw";
                LogsDirectory    = "claw";
                Environment      = [ "OLLAMA_HOST=${cfg.ollamaHost}" ];

                # Hardening
                NoNewPrivileges = true;
                ProtectSystem   = "strict";
                ProtectHome     = "read-only";
                ReadWritePaths  = [ "/run/claw" "/var/log/claw" "/etc/claw" ];
                PrivateTmp      = true;
                LockPersonality = true;
                RestrictRealtime = true;

                AmbientCapabilities = mkIf cfg.enableEbpf
                    [ "CAP_BPF" "CAP_SYS_ADMIN" "CAP_NET_ADMIN" ];
              };
            };
          };
        };

      # ── Overlay ─────────────────────────────────────────────────────
      overlays.default = final: prev: {
        kernklaw-linux = kernklaw-linux;
      };
    });
}
