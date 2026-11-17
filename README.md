# RdkWanManager

**These are the mission objectives of the WAN Manager architecture:**
===================================================================

1. Interface Managers (e.g. XDSL, Eth, DOCSIS, GPON, Cellular) are expected to handle the physical interface bring up and report the status of the physical layer to WAN Manager.
    1. Along with reporting the status of the physical layer, they may also report additional configuration information such as the IP Mode (IPv4 only/IPv6 only/Dual Stack), any VLAN IDs to be used for egress traffic, or static IP addresses (e.g. received through PDP on a Cellular link).
2. WAN Manager will then handle all link and IP layer configuration by interfacing with other RDK components (e.g. VLAN Manager, DHCP Manager, etc...) or Linux utility commands (e.g. ip addr, ip ro, etc...)
3. WAN Manager will run all business logic to configure WAN interfaces and ensure Internet Connectivity.

WAN Manager comprises of several internal modules:
==================================================
1. WAN Manager will run a single instance of the Failover Policy, which provides runtime failover/switching between different Groups of interfaces.
2. WAN Manager will run N instances of a Selection Policy, one instance per interface Group.
    1. This Selection Policy may be AutoWAN, Parallel Scan. Different policies use different algorithms for selecting an interface to be used for WAN. (e.g. the AutoWAN policy tries one interface one by one until one has been validated for Internet Access.)
    2. The Selection Policies only run for interfaces within a selected Group. (E.g. if you want to run AutoWAN policy to select one interface between DOCSIS and EthWAN, you would mark both DOCSIS and EthWAN as belonging to Group 1, and then run the AutoWAN policy on Group 1 only.)
    3. For multiple Groups of interfaces, you need to run multiple Selection Policies, one for each Group.
        1. This allows for more flexible configurations, such as running an AutoWAN policy between DOCSIS and EthWAN (Group 1), and allowing for runtime failover between the Group 1 interface and a Group 2 interface (e.g. LTE).
3. WAN Manager will run N instances of the WAN Interface State Machine, one instance per virtual interface.
    1. A virtual interface is configured in the data model as being a combination of link layer and ip layer interfaces/protocols to be configured on top of the base interface. The WAN Interface State Machine ensures correct configuration and deconfiguration of a virtual interface by building the stack from the bottom up. 
4. WAN Manager supports both RBUS and WebConfig for remote configuration. RBUS is also used for internal communications between WAN Manager and Interface Managers.

### DHCP client event subscriptions

With `FEATURE_RDKB_DHCP_MANAGER`:

- On cold boot, when `/tmp/wanmanager_initialized` was absent at process startup,
  the interface state machine subscribes to DHCPv4 and DHCPv6 client events for
  configured DHCP interfaces.
- After a WAN Manager crash or restart, when the marker already existed,
  subscriptions are skipped at state-machine startup and deferred until the
  corresponding DHCP client is started.
- Each DHCP client start path subscribes before enabling the client if its
  subscription flag is not set. This also retries subscriptions that failed at
  state-machine startup. The flag is set only after a successful subscription.

Marker detection occurs before the current process creates the marker, so the
restart decision remains unchanged throughout that process's lifetime.
