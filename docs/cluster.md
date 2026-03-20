# Wazuh Cluster Deployment

## Model

Run one ETL instance per Wazuh node (master and each worker).

Each instance reads that node's local alerts stream and writes to shared ClickHouse.

## Rules

- Use unique `STATE_FILE` path per node
- Keep same ClickHouse target database across nodes
- Use `manager_name` column to distinguish event origin

## Per-node checklist

1. Install binary on node
2. Create node-specific working directory
3. Configure node-specific `.env` (unique state path)
4. Enable node-specific systemd unit
5. Verify inserts in ClickHouse with `manager_name`

## ZeroMQ in cluster

If using ZeroMQ, configure each node to subscribe locally:
- `ZEROMQ_URI=tcp://localhost:11111`

Avoid multiple ETL instances sharing a single node socket unless duplication is intentional.
