# Configuration Guide

## Overview

WAN Manager is configured through its TR-181 data model. The data model is defined in XML files in the `config/` directory, and WAN Manager reads and writes the parameters at runtime. This guide covers the platform integration steps, the configuration files, the parameter reference, and common troubleshooting steps.

For build options and the directory layout, see the [README](README.md). For the component design, see [architecture/component-diagram.md](architecture/component-diagram.md).

---

## Platform Integration Guide

Integrating WAN Manager on a platform involves these steps:

1. **Build WAN Manager** with the autotools build (`configure.ac`). Enable the options your platform requires (for example `--enable-notify` or `--enable-wanunificationsupport`). See the [README](README.md#build-instructions).
2. **Provide the data model definition.** Use `config/RdkWanManager.xml` or `config/RdkWanManager_v2.xml`. The v2 file adds `Version`, `ResetDefaultConfig`, `RestorationDelay`, and `WanFailoverData`.
3. **Provide the platform WAN interfaces.** Define the `Wan` interface entries (name, type, priority, group) and the physical interface path (`Phy.Path`) in the data model.
4. **Provide the policy.** Set `Policy` to one of the values in the [policy reference](#policy-values).
5. **Provide the system readiness signal.** When WAN Manager runs with RBUS, it waits up to 180 seconds for the `wan_ready_to_go` signal before it starts the WAN web configuration and core. See [Troubleshooting](#troubleshooting).
6. **Provide the logger configuration.** WAN Manager initialises the logger from `/etc/debug.ini`.

> **Note:** The install location of the configuration XML files is not defined in this repository. Confirm the location with your platform integration before deployment.

---

## Configuration Architecture

```text
config/
├── RdkWanManager.xml          # Data model definition (Policy, Wan, PPP, DHCPv4, DHCPv6, MAP, ...)
└── RdkWanManager_v2.xml       # Data model definition with Version, ResetDefaultConfig,
                               # RestorationDelay, and WanFailoverData

source/TR-181/include/
└── wanmgr_dml.h               # Enum values for Policy, WAN state, and related fields

Runtime files
├── /etc/debug.ini             # Logger configuration (read at startup)
├── /var/tmp/wanmanager.pid    # Process ID file (written at startup)
├── /tmp/wanmanager_initialized  # Created after the component crash check
└── /tmp/udhcpc.<ifname>.pid   # DHCPv4 client PID file (created by udhcpc)
```

---

## Configuration Reference

### Top-Level WAN Manager Parameters

These parameters are defined under `X_RDK_WanManager` in `config/RdkWanManager.xml`.

| Parameter | Description |
| --------- | ----------- |
| `Enable` | Enables WAN Manager |
| `Policy` | WAN selection policy. See [policy values](#policy-values) |
| `ResetActiveInterface` | Defined in the data model. Purpose not verified in this repository |
| `AllowRemoteInterfaces` | Defined in the data model. Purpose not verified in this repository |
| `ResetDefaultConfig` | Defined in `RdkWanManager_v2.xml`. Purpose not verified in this repository |
| `RestorationDelay` | Defined in `RdkWanManager_v2.xml`. Purpose not verified in this repository |
| `WanFailoverData` | Defined in `RdkWanManager_v2.xml`. Purpose not verified in this repository |
| `DnsConnectivityCheck.Enable` | Enables DNS connectivity checking |

### Wan Interface Parameters

Each interface entry under `Wan` defines these parameters:

| Parameter | Description |
| --------- | ----------- |
| `Name` | Interface name |
| `Type` | Interface type |
| `Priority` | Interface priority |
| `Group` | Interface group |
| `Status` | Interface status |
| `ActiveLink` | Whether the interface is the active link |
| `Refresh` | Refresh control for the interface |
| `OperationalStatus` | Operational status |
| `Enable` | Enables the interface |
| `SelectionTimeout` | Selection timeout for the interface |
| `EnableMAPT` | Enables MAP-T on the interface |
| `EnableDSLite` | Enables DS-Lite on the interface |
| `EnableIPoEHealthCheck` | Enables IPoE health check on the interface |
| `EnableDHCP` | Enables DHCP on the interface |
| `RebootOnConfiguration` | Reboot control on configuration change |
| `Phy.Path` | Physical interface path |
| `Marking.SKBPort`, `Marking.SKBMark`, `Marking.EthernetPriorityMark`, `Marking.Alias` | Traffic marking settings |

### Policy Values

`Policy` maps to the `DML_WAN_POLICY` enum in `source/TR-181/include/wanmgr_dml.h`:

| Value | Enum | 
| ----- | ---- |
| 1 | `DML_WAN_POLICY_FIXED_MODE_ON_BOOTUP` |
| 2 | `DML_WAN_POLICY_FIXED_MODE` |
| 3 | `DML_WAN_POLICY_PRIMARY_PRIORITY_ON_BOOTUP` |
| 4 | `DML_WAN_POLICY_PRIMARY_PRIORITY` |
| 5 | `DML_WAN_POLICY_MULTIWAN_MODE` |
| 6 | `DML_WAN_POLICY_AUTOWAN_MODE` |
| 7 | `DML_WAN_POLICY_PARALLEL_SCAN` |

The policy implementation files are described in [controller.md](components/controller.md).

### MAP Parameters

These parameters are defined in `config/RdkWanManager.xml` under the MAP object. Their values are provided by DHCPv6 and stored in `dhcp6cMAPparameters`. See [dhcp-clients.md](components/dhcp-clients.md).

| Parameter | Description |
| --------- | ----------- |
| `MapTransportMode` | MAP transport mode (MAP-E or MAP-T) |
| `MapBRPrefix` | Border relay prefix |
| `MapRuleIPv4Prefix` | MAP rule IPv4 prefix |
| `MapRuleIPv6Prefix` | MAP rule IPv6 prefix |
| `MapEALen` | EA bits length |
| `MapPSIDOffset` | PSID offset |
| `MapPSIDLen` | PSID length |
| `MapPSID` | PSID value |
| `MapIsFMR` | Forwarding Mapping Rule flag |
| `MapIpv4Address` | MAP IPv4 address |
| `MapRatio` | Port ratio |

### DHCP Parameters

`DHCPv4` and `DHCPv6` objects in `config/RdkWanManager.xml` define the client entries. Each client has `Enable`, `Alias`, `Interface`, `Status`, and `DHCPStatus`. DHCPv4 clients also expose `IPAddress`, `SubnetMask`, `IPRouters`, `DNSServers`, and `LeaseTimeRemaining`. Sent and requested option tables (`SentOption`, `ReqOption`) define the option tag and value.

---

## TR-181 Data Model

WAN Manager implements its parameters in `source/TR-181/`:

| Directory | Contents |
| --------- | -------- |
| `source/TR-181/include/` | Headers, including `wanmgr_dml.h` (enums and structures) |
| `source/TR-181/middle_layer_src/` | Implementation of the middle layer, including MAP and DHCP client event handling |

Parameter get and set calls are handled by the middle layer. See [data-model-layer.md](components/data-model-layer.md).

---

## Troubleshooting

| Issue | Cause | Resolution |
| ----- | ----- | ---------- |
| WAN Manager does not start | `Cdm_Init` failed | Check the error printed at startup. The process exits with status 1 |
| Startup pauses for up to 3 minutes | WAN Manager waits for `wan_ready_to_go` when running with RBUS | After 180 seconds, WAN Manager continues startup |
| Process ID file already present | `/var/tmp/wanmanager.pid` is written at startup | Check whether a previous instance is still running |
| Component crash check reports a previous crash | `/tmp/wanmanager_initialized` already exists | The file is created after the check. Review the previous run before removing it |
| Logs are missing or at the wrong level | Logger configuration | Check `/etc/debug.ini` |
| WAN interface does not get IPv4 configuration | DHCPv4 client not running or no lease | Check `/tmp/udhcpc.<ifname>.pid` and the client logs |
| WAN interface does not get IPv6 configuration | DHCPv6 client not renewing | `dhcp6c` receives `SIGUSR2` to renew. Check its logs |
| Running in the foreground (`-c`) | Foreground mode is selected | Enter `q` to quit, or `c` to cancel the component |

---

## Best Practices

- Keep `/etc/debug.ini` in place so that log levels can be adjusted.
- Use foreground mode (`-c`) for debugging only. Without `-c`, WAN Manager daemonises at startup.
