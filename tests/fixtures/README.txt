Recorded responses of roamswitch-mcp
====================================

Each *.json file is one complete JSON-RPC response line that roamswitch-mcp
wrote for a tools/call request (the JSON payload block, then the notice block
about untrusted data). tests/common/mod.rs plays them back through a
stand-in roamswitch-mcp, so the tests need no RoamSwitch installation.

The file name is the tool name. A name after "__" is a variant of the same
tool (another input, edition or state).

How they were taken
-------------------

- Binary: roamswitch-mcp built from the roamswitch-linux working tree at
  commit 715a0aa2 (clean), in a rust:1-bookworm container, run as root.
- State: the container was fresh. Before the calls, files that the daemons
  write were put in place by hand (port scan incidents, SSH guard status,
  bans and incidents, entropy incidents, honeytoken placement, the incident
  timeline, the exec recorder status), the exec log was written with
  roamswitch-core's own ExecStore, a FIM baseline was built with
  roamswitch-core's CriticalPathFim, and a project folder with node_modules,
  a lockfile, MCP client and agent instruction files was created. The
  binary read and re-serialized all of it, so the field names are the
  server's own.
- get_privilege_escalation_paths and get_access_log_report: the real PathScope
  (commit 249616d, 1.0.3) and the real AccessScope (commit c22e05d, 1.0.4)
  were built and installed in the container, and the binary ran them. The
  AccessScope input was a hand-written nginx access log and auth.log.
- get_lan_sensor_overview and get_lan_network_threats: no Sensor was run. A
  stand-in listened on /run/roamswitch-sensor/daemon.sock and answered with
  JSON written from sensor-core/src/lan_summary.rs (the contract of schema
  1). The wrapping around "data" (available, coverageGaps, mcpCaution, ...)
  was written by the real roamswitch-mcp. The "__not_installed" variants are
  fully real.
- get_sensor_audit_results: a stand-in answered on the daemon socket. The
  "findings" object inside the completed result is invented, because its
  shape belongs to the Sensor and is passed on untyped.
- run_npm_audit_signatures: "__disabled" and "__npm_missing" are real. In
  "__issues" a stand-in "npm" script printed the text and exited 1, so
  nothing was sent to the npm registry.
- Source addresses are from the documentation ranges 198.51.100.0/24 and
  203.0.113.0/24; the LAN addresses are 192.168.x.x and 10.1.1.1. The keys in
  the secret scans are the public AWS documentation example key and a
  made-up token shape.
- The files for the 26 older tools were taken the same way in the same
  container, so most lists in them are empty.
