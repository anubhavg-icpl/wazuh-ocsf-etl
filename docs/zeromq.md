# ZeroMQ Mode

## When to use

Use ZeroMQ mode if you need very low latency or remote subscription from another machine.

```dotenv
INPUT_MODE=zeromq
ZEROMQ_URI=tcp://localhost:11111
```

## Critical prerequisite

Default Wazuh binary packages do not include ZeroMQ output support.

You must build Wazuh manager from source with:

```bash
make TARGET=server USE_ZEROMQ=yes
```

## Minimal enablement steps

1. Install ZeroMQ development package on build host
2. Build Wazuh with `USE_ZEROMQ=yes`
3. Enable in `/var/ossec/etc/ossec.conf`:

```xml
<global>
  <zeromq_output>yes</zeromq_output>
  <zeromq_uri>tcp://0.0.0.0:11111/</zeromq_uri>
</global>
```

4. Restart Wazuh manager
5. Verify logs show ZeroMQ output enabled

## Trade-offs

- File mode:
  strongest reliability and replay ability
- ZeroMQ mode:
  lowest latency, but PUB/SUB is at-most-once

If zero data loss is mandatory, prefer file mode.
