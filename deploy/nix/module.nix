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
        ExecStart = "${lib.getExe cfg.package} --network ${lib.escapeShellArg cfg.network} --state-path ${lib.escapeShellArg cfg.statePath}";
        DynamicUser = false;
        User = "quicnet";
        Group = "quicnet";
        Restart = "on-failure";
        StateDirectory = "quicnet";
      };
    };
  };
}
