# OT/ICS Protocol Reference

## Industrial Protocols & Ports

| Protocol | Port | Description | Vendor | Purdue Level |
|----------|------|-------------|--------|-------------|
| Modbus TCP | 502 | Most common ICS protocol, no authentication | Open | L1-L2 |
| S7Comm | 102 | Siemens S7 PLC communication | Siemens | L1-L2 |
| DNP3 | 20000 | Distributed Network Protocol (utilities/SCADA) | Open | L1-L2 |
| BACnet | 47808 | Building Automation and Control | ASHRAE | L1-L2 |
| EtherNet/IP | 44818 | CIP-based industrial ethernet | Rockwell/ODVA | L1-L2 |
| OPC-UA | 4840 | Open Platform Communications Unified Architecture | OPC Foundation | L2-L3 |
| PROFINET | 34964 | Siemens industrial networking | Siemens | L1-L2 |
| IEC 61850 MMS | 102 | Substation automation (power grid) | IEC | L1-L2 |
| IEC 104 | 2404 | Telecontrol protocol (power grid SCADA) | IEC | L2-L3 |
| MQTT | 1883/8883 | IoT messaging (increasingly in ICS) | OASIS | L2-L3 |
| Niagara Fox | 1911 | Tridium Niagara building automation | Tridium | L2-L3 |
| CODESYS | 2455 | PLC runtime (multi-vendor) | CODESYS | L1-L2 |
| GE SRTP | 18245 | GE PLC service request transport | GE | L1-L2 |

## Purdue Model Levels

| Level | Name | Examples |
|-------|------|---------|
| L0 | Physical Process | Sensors, actuators, field devices |
| L1 | Basic Control | PLCs, RTUs, safety controllers |
| L2 | Area Supervisory | HMIs, SCADA servers, engineering workstations |
| L3 | Site Operations | Historians, OPC servers, MES |
| L3.5 | DMZ | Data diodes, jump servers, patch management |
| L4 | Business Planning | ERP, email, file servers |
| L5 | Enterprise | Internet-facing services, cloud |

## ICS-Specific Subdomain Patterns

Look for these patterns in subdomain enumeration results:
- `scada*`, `ics*`, `plc*`, `hmi*`, `opc*`, `dcs*`, `rtu*`
- `historian*`, `pi*` (OSIsoft PI)
- `modbus*`, `bacnet*`, `profinet*`
- `factory*`, `plant*`, `production*`, `mfg*`
- `ot-*`, `ot.*`, `*-ot.*`

## ICS Malware Reference

| Malware | Year | Target | Capability |
|---------|------|--------|------------|
| Stuxnet | 2010 | Siemens S7-315/417 | Centrifuge sabotage |
| BlackEnergy | 2015 | Ukrainian power grid | HMI manipulation, outage |
| Industroyer/CrashOverride | 2016 | Ukrainian power grid | IEC 61850/104 manipulation |
| TRITON/TRISIS | 2017 | Schneider Triconex SIS | Safety system manipulation |
| Havex | 2014 | Energy sector OPC | OPC server reconnaissance |
| PIPEDREAM/INCONTROLLER | 2022 | Schneider, Omron, OPC-UA | Multi-protocol ICS attack |
| FrostyGoop | 2024 | Modbus-based heating systems | Modbus command manipulation |
| CosmicEnergy | 2023 | IEC 60870-5-104 | Power grid disruption |
