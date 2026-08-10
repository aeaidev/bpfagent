### Testing

## Always do test on 'fpu117'

1. `cd /home/igor/projects/rust/aya/bpfagent && cargo build --package bpfagent --release`

2. `ssh fpu117 'sudo pkill -f bpfagent || true'`

3. `scp target/release/bpfagent fpu117:/tmp/bpfagent_new`

4. `ssh fpu117 'sudo RUST_LOG=bpfagent::programs::sca=debug,sca=debug /tmp/bpfagent_new'`

### SCA Debugging

#### Lsof Command Fix

The lsof command in `bpfagent/src/programs/sca/mod.rs` has specific field positions:
- FD is in field 4 (e.g., "5u")
- Socket path is in field 9
- Type info is in fields 10-11: `type=STREAM (CONNECTED)`

The awk command should use:
- `$4 ~ /u$/` - FD ends with 'u'
- `$10 ~ /type=STREAM/` - field 10 contains type=STREAM
- `$11 ~ /CONNECTED/` - field 11 contains CONNECTED
- `gsub(/u$/,"",$4)` - strip trailing 'u' from FD

Example working command:
```bash
sudo -n lsof 2>/dev/null | awk '$4 ~ /u$/ && $10 ~ /type=STREAM/ && $11 ~ /CONNECTED/ {gsub(/u$/,"",$4); print "PID:"$2" FD:"$4" "$9}' | grep -E '/tmp/(DATA_L3_TO|DATA_L_TO|WF_L_TO|FRAG_TO|IRSS_L_TO)'
```

#### Timestamp Key

The TIMESTAMP_MAP key combines FD and Protocol:
- Key = (FD << 32) | Protocol
- This allows multiple protocols on the same FD to have separate timestamps
