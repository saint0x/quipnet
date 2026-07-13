{ lib, pkgs, config, ... }:
let
  cfg = config.services.quicnet;
  quicnetdPackage = pkgs.rustPlatform.buildRustPackage {
    pname = "quicnetd";
    version = "0.1.0";
    src = builtins.path {
      path = ../..;
      name = "quicnet-source";
    };
    cargoLock.lockFile = ../../Cargo.lock;
    cargoBuildFlags = [ "-p" "quicnetd" ];
  };
in
{
  options.services.quicnet = {
    enable = lib.mkEnableOption "Quicnet daemon";
    package = lib.mkOption {
      type = lib.types.package;
      default = quicnetdPackage;
    };
    network = lib.mkOption {
      type = lib.types.str;
      default = "personalcloud-prod";
    };
    statePath = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/quicnet/state.json";
    };
    identityPath = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/quicnet/identity.json";
    };
    identityPassphraseEnvironmentVariable = lib.mkOption {
      type = lib.types.str;
      default = "QUICNET_IDENTITY_PASSPHRASE";
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
    users.users.quicnet = {
      isSystemUser = true;
      group = "quicnet";
      home = "/var/lib/quicnet";
      createHome = true;
    };

    users.groups.quicnet = {};

    systemd.services.quicnet = {
      description = "Quicnet daemon";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target"];
      wants = ["network-online.target"];
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
        User = "quicnet";
        Group = "quicnet";
        Restart = "on-failure";
        StateDirectory = "quicnet";
      };
      environmentFiles = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
    };
  };
}
