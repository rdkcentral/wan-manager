# WAN Manager

## Overview

WAN Manager (`wan-manager`) is an RDK-B software component that selects the active WAN interface and configures its link and IP settings on the device.

It exposes the TR-181 data model subtree `Device.X_RDK_WanManager.*` to the platform. Interface managers (xDSL, Ethernet, DOCSIS, GPON, Cellular) bring up the physical layer and report status to WAN Manager. WAN Manager then configures the link and IP layers through other RDK components or Linux utilities.

WAN Manager runs as a background daemon process and is responsible for:

- Maintaining one WAN Interface State Machine per virtual WAN interface.
- Applying a WAN selection policy to choose the active interface within an interface group.
- Switching between interface groups through the failover logic.
- Obtaining IPv4 and IPv6 configuration through DHCP clients and applying it to the WAN interface.
- Configuring MAP-T and MAP-E transport when the DHCPv6 server provides MAP parameters.
- Exposing its configuration and status through the message bus and RBUS.

---

## Features

- TR-181 data model exposure (`Device.X_RDK_WanManager.*`).
- Seven WAN policy modes: `FIXED_MODE_ON_BOOTUP`, `FIXED_MODE`, `PRIMARY_PRIORITY_ON_BOOTUP`, `PRIMARY_PRIORITY`, `MULTIWAN_MODE`, `AUTOWAN_MODE`, and `PARALLEL_SCAN`.
- Per-interface state machine with the states `PHY_CONFIGURING` through `STANDBY`.
- IPv4 (DHCPv4 via `udhcpc`) and IPv6 (DHCPv6 via `dhcp6c`) configuration.
- MAP-T and MAP-E configuration support.
- Failover between interface groups.
- IPOE health check support (when built with `FEATURE_IPOE_HEALTH_CHECK`).
- Netlink-based monitoring of network link and route changes.
- Message bus (CCSP) and RBUS support.
- WebConfig configuration support.
- Systemd `sd_notify` support for supervised startup (when built with `ENABLE_SD_NOTIFY`).
- Breakpad crash reporting support (when built with `INCLUDE_BREAKPAD`).
- Telemetry reporting (`wanmgr_telemetry.c`, `wanmgr_t2_telemetry.c`).

---

## Build Instructions

### Prerequisites

- RDK-B build environment.
- Autotools (`autoconf`, `automake`, `libtool`).
- Libraries referenced in `source/WanManager/Makefile.am`: `ccsp_common`, `rdkloggers`, `hal_platform`, `api_dhcpv4c`, `nanomsg`, `webconfig_framework`, `msgpackc`, `privilege`, `rbus`, and `secure_wrapper`.
- `dhcp_client_utils` when DHCP manager support is disabled.

### Build Process

Build the component with the standard autotools flow:

```bash
autoreconf -i
./configure
make
```

Optional features are selected at configure time. All options are disabled by default.

| Configure option | Effect |
| ---------------- | ------ |
| `--enable-notify` | Defines `ENABLE_SD_NOTIFY` and links `systemd` |
| `--enable-gtestapp` | Defines `GTEST_ENABLE` for the unit test application |
| `--enable-wanunificationsupport` | Sets `WAN_UNIFICATION_ENABLED` |
| `--enable-dhcp_manager` | Sets `DHCPMANAGER_ENABLED` |

---

## Documentation

### Architecture

- [architecture/component-diagram.md](architecture/component-diagram.md)

### Components

- [components/controller.md](components/controller.md)
- [components/interface-state-machine.md](components/interface-state-machine.md)
- [components/data-model-layer.md](components/data-model-layer.md)
- [components/dhcp-clients.md](components/dhcp-clients.md)
- [components/ipc.md](components/ipc.md)
- [components/ssp.md](components/ssp.md)

### Configuration

- [configuration-guide.md](configuration-guide.md)

---

## Directory Structure

```text
wan-manager/
├── cfg/                                    # Autotools auxiliary files
│   └── Makefile.am
│
├── config/                                 # TR-181 data model definitions
│   ├── RdkWanManager.xml
│   └── RdkWanManager_v2.xml
│
├── docs/                                   # Component documentation
│   ├── architecture/
│   ├── components/
│   ├── configuration-guide.md
│   └── README.md
│
├── source/
│   ├── Makefile.am
│   │
│   ├── WanManager/                         # Core WAN Manager component
│   │   ├── DHCPv6cMsgHandler/
│   │   │   └── dhcpv6c_msg_apis.h
│   │   ├── wanmgr_controller.c / .h        # Policy controller
│   │   ├── wanmgr_core.c / .h              # Core init, start, and finalise
│   │   ├── wanmgr_data.c / .h              # Configuration and interface data
│   │   ├── wanmgr_dhcp_client_events.h     # DHCP client event queue
│   │   ├── wanmgr_dhcp_event_handler.c     # DHCP lease event handling
│   │   ├── wanmgr_dhcp_legacy_apis.c       # Legacy DHCP handling
│   │   ├── wanmgr_dhcpv4_apis.c / .h       # DHCPv4 client integration
│   │   ├── wanmgr_dhcpv6_apis.c / .h       # DHCPv6 client integration
│   │   ├── wanmgr_interface_apis.c / .h    # Interface start, stop, activate
│   │   ├── wanmgr_interface_sm.c / .h      # WAN Interface State Machine
│   │   ├── wanmgr_ipc.c / .h               # Inter-process communication
│   │   ├── wanmgr_mape.c / .h              # MAP-E configuration
│   │   ├── wanmgr_main.c                   # Process entry point
│   │   ├── wanmgr_net_utils.c / .h         # Network and MAP-T utilities
│   │   ├── wanmgr_network_monitor.c / .h   # Netlink link and route monitor
│   │   ├── wanmgr_policy_*_impl.c          # WAN selection policy implementations
│   │   ├── wanmgr_ssp_*.c / .h             # Service Start-up Process (SSP) layer
│   │   ├── wanmgr_sysevents.c / .h         # System event integration
│   │   ├── wanmgr_t2_telemetry.c / .h      # Telemetry 2.0 reporting
│   │   ├── wanmgr_telemetry.c / .h         # Telemetry reporting
│   │   ├── wanmgr_utils.c / .h             # Utility functions
│   │   ├── wanmgr_wan_failover.c / .h      # Failover between interface groups
│   │   ├── wanmgr_webconfig.c              # WebConfig handling
│   │   ├── wanmgr_webconfig_apis.c         # WebConfig APIs
│   │   └── Makefile.am
│   │
│   ├── TR-181/                             # TR-181 Data Model implementation
│   │   ├── Makefile.am
│   │   ├── include/
│   │   │   ├── wanmgr_apis.h
│   │   │   ├── wanmgr_dml.h
│   │   │   ├── wanmgr_webconfig.h
│   │   │   └── wanmgr_webconfig_apis.h
│   │   └── middle_layer_src/
│   │       ├── wanmgr_dml_apis.c / .h
│   │       ├── wanmgr_dml_dhcpv4.c / .h
│   │       ├── wanmgr_dml_dhcpv6.c / .h
│   │       ├── wanmgr_dml_iface_apis.c / .h
│   │       ├── wanmgr_dml_iface_v2_apis.c / .h
│   │       ├── wanmgr_dml_map.c / .h
│   │       ├── wanmgr_map_apis.c / .h
│   │       ├── wanmgr_plugin_main.c / .h
│   │       ├── wanmgr_plugin_main_apis.c / .h
│   │       ├── wanmgr_rbus_dhcp_client_events.c
│   │       ├── wanmgr_rbus_handler_apis.c / .h
│   │       ├── wanmgr_rdkbus_apis.c / .h
│   │       ├── wanmgr_rdkbus_utils.c / .h
│   │       └── Makefile.am
│   │
│   └── test/                               # Unit tests (gtest)
│       ├── RdkWanManagerTest.cpp / .h
│       ├── Test_wanmgr_rbus_handler_apis.cpp
│       └── gtest_main.cpp
│
├── configure.ac
├── CHANGELOG
├── CONTRIBUTING.md
├── COPYING
├── LICENSE
├── Makefile.am
├── NOTICE
└── README.md
```

---

## Quick Start

### Building the Component

```bash
autoreconf -i
./configure --enable-notify
make
```

### Configuration

WAN Manager reads its TR-181 data model definition from the XML files in `config/`:

- `RdkWanManager.xml`
- `RdkWanManager_v2.xml`

The two files define different parameter sets for the `X_RDK_WanManager` object. The `Policy` parameter is writable unless the `WANMGR_POLICY_TR181_READONLY` condition is set.

See [configuration-guide.md](configuration-guide.md) for the parameter reference.

### Key Interfaces

| Interface | Purpose | Notes |
| --------- | ------- | ----- |
| Message Bus (CCSP) | Component registration and data model access | Component name `eRT.com.cisco.spvtg.ccsp.wanmanager`, path `/com/cisco/spvtg/ccsp/wanmanager` |
| RBUS | Data model access and WAN-ready event subscription | Used when built with `RBUS_BUILD_FLAG_ENABLE` |
| WebConfig | Remote configuration of WAN Manager | Initialised by `WanMgrDmlWanWebConfigInit()` |
| nanomsg IPC | Messages between WAN Manager and DHCP client handlers | Uses `AF_SP` `NN_PULL` and `NN_PUSH` sockets |
| Netlink (`NETLINK_ROUTE`) | Kernel link and route change notifications | Opened by `WanMgr_StartNetWorkMonitor()` |

---

For system architecture, component internals, and data flow details, see [architecture/component-diagram.md](architecture/component-diagram.md).
