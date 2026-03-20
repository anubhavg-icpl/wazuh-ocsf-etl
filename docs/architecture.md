# Architecture

## Pipeline model

The service has two main async stages:

1. Reader
- tails file or subscribes to ZeroMQ
- sends alerts through bounded channel

2. Processor/Writer
- transforms alert to OCSF record
- resolves mapped fields
- batches rows by destination table
- flushes to ClickHouse via HTTP

## Table strategy

Tables are auto-created in ClickHouse as data appears:

- Per-agent: `ocsf_<agent_name>`
- Shared-source routing via `SPECIAL_LOCATIONS`

## OCSF mapping

- Class and category are inferred from rule/decoder context
- Common source fields are normalized into typed OCSF columns
- Unmatched vendor fields are retained in `extensions`

## Validation

Optional OCSF validation checks run after transform.

- Warn-only behavior
- Events are still written to ClickHouse

## Deep reference

- Full field mapping matrix: [../FIELD_MAPPINGS.md](../FIELD_MAPPINGS.md)
- Full legacy technical reference: [reference-full.md](reference-full.md)
