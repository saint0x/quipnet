{ lib, pkgs, config, ... }:
let
  cfg = config.services.quip;
  quipdPackage = pkgs.rustPlatform.buildRustPackage {
    pname = "quipd";
    version = "0.1.0";
    src = builtins.path {
      path = ../..;
      name = "quip-source";
    };
    cargoLock.lockFile = ../../Cargo.lock;
    cargoBuildFlags = [ "-p" "quipd" ];
  };
in
{
  options.services.quip = {
    enable = lib.mkEnableOption "Quip daemon";
    package = lib.mkOption {
      type = lib.types.package;
      default = quipdPackage;
    };
    network = lib.mkOption {
      type = lib.types.str;
      default = "personalcloud-prod";
    };
    statePath = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/quip/.quip/net/state.json";
    };
    identityPath = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/quip/.quip/identity/node.json";
    };
    identityPassphraseEnvironmentVariable = lib.mkOption {
      type = lib.types.str;
      default = "QUIP_IDENTITY_PASSPHRASE";
    };
    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
    };
    authorityOrigin = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
    authoritySubject = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
    sync = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    revocationSync = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.quip = {
      isSystemUser = true;
      group = "quip";
      home = "/var/lib/quip";
      createHome = true;
    };

    users.groups.quip = {};

    systemd.services.quip = {
      description = "Quip daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = ''
          ${pkgs.bash}/bin/sh -ec '
            set -- --network ${lib.escapeShellArg cfg.network} --state-path ${lib.escapeShellArg cfg.statePath} --identity-path ${lib.escapeShellArg cfg.identityPath} --identity-passphrase-env ${lib.escapeShellArg cfg.identityPassphraseEnvironmentVariable}
            ${lib.optionalString cfg.sync "set -- \"$@\" --sync"}
            ${lib.optionalString cfg.revocationSync "set -- \"$@\" --revocation-sync"}
            ${lib.optionalString (cfg.authorityOrigin != null) "set -- \"$@\" --authority-origin ${lib.escapeShellArg cfg.authorityOrigin}"}
            ${lib.optionalString (cfg.authoritySubject != null) "set -- \"$@\" --authority-subject ${lib.escapeShellArg cfg.authoritySubject}"}
            exec ${lib.getExe cfg.package} "$@"
          '
        '';
        DynamicUser = false;
        User = "quip";
        Group = "quip";
        Restart = "on-failure";
        StateDirectory = "quip";
      };
      environmentFiles = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
    };
  };
}
