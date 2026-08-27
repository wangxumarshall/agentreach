# Antigravity (agy) harness

Point Google Antigravity (`agy` / `antigravity`) at any remote SSH host or container through `reach`.

## How reach gets in

Antigravity CLI executes terminal commands via `bash` by walking the system PATH. reach intercepts execution at this seam:

1. **PATH Shell Shim**: reach prepends a managed shim directory to `PATH` containing `bash`. All terminal and shell executions issued by Antigravity route through the shim to the remote target.
2. **Managed Settings**: reach runs Antigravity with a managed `HOME` containing `.gemini/antigravity-cli/settings.json` and `.gemini/settings.json`. Built-in file and edit tools (`read_file`, `write_file`, `replace`, `view_file`, etc.) are excluded via `excludeTools`, compelling the agent to use shell commands (`cat`, `sed`, `grep`, etc.) which execute remotely on the target.
3. **Credential Preservation**: Existing credentials in `~/.gemini` (OAuth tokens, API keys) are linked into the managed directory so authentication is seamless without copying keys to the remote host.

## Usage

```console
# Direct target launch with Claude or Antigravity
reach build-box agy
reach build-box antigravity

# In a specific directory
reach build-box:/srv/app agy
```
