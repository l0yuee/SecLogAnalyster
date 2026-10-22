# Synthetic Alibaba Cloud Aegis logs

The `aegis/` tree contains entirely invented records in the supported client
logging envelopes. It includes core and Python logs, a numeric context before
or after severity, multiline JSON, rotation names and temporary components.
No user evidence, machine identifiers, credentials or client software is copied
here. Additional encoding, malformed, oversized and binary inputs are generated
at test runtime.
