# Overview

## Summary

wazuh-ocsf-etl is a Rust pipeline that converts Wazuh alerts into OCSF 1.7.0 records and stores them in ClickHouse.

It is designed to replace large multi-component stacks with a single small binary.

## Data flow

```text
Wazuh manager
  -> alerts.json (file mode) or ZeroMQ PUB (zeromq mode)
  -> wazuh-ocsf-etl
     - classify to OCSF class
     - map fields to typed columns
     - batch and flush to ClickHouse
  -> ClickHouse tables (auto-created)
```

## Core capabilities

- OCSF 1.7.0 normalization
- Per-agent/per-location table routing
- Inode + offset state tracking for restart safety
- Hot-reload custom field mappings
- Optional ZeroMQ low-latency input mode
- Unmapped field discovery for iterative mapping

## Typical use cases

- Replace Elasticsearch-based Wazuh analytics backend
- Build SOC dashboards in Grafana using ClickHouse
- Centralize security telemetry in OCSF format
- Correlate Wazuh events with other OCSF data sources

## Read next

- Install: [installation.md](installation.md)
- Configure: [configuration.md](configuration.md)
- Operate: [operations.md](operations.md)
- Architecture details: [architecture.md](architecture.md)
