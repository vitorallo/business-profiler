# Troubleshooting

## Plugin installation fails with "Permission denied (publickey)"

The plugin installer tries to clone via SSH (`git@github.com:...`). If you don't have SSH keys set up for GitHub, it fails with:

```
git@github.com: Permission denied (publickey).
fatal: Could not read from remote repository.
```

Tell git to use HTTPS instead:

```bash
git config --global url."https://github.com/".insteadOf "git@github.com:"
```

Then retry the install.

## Plugin installation fails with SSH host key prompt

When installing via `/plugin install business-profiler@peach-studio`, the git clone may hang on:

```
The authenticity of host 'github.com' can't be established.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

You can't type `yes` inside Claude Code's plugin installer. Fix it by adding GitHub's host key before installing:

```bash
ssh-keyscan github.com >> ~/.ssh/known_hosts
```

Then retry the install.

## Plugin fails to load in Claude Desktop

Claude Desktop runs plugins in a sandboxed VM. If the install fails with "Failed to clone repository", try installing via Claude Code CLI instead:

```bash
/plugin marketplace add vitorallo/peach-studio-marketplace
/plugin install business-profiler@peach-studio
```

Or load it as a local plugin by pointing Claude Desktop to your cloned directory.

## Dependencies missing after install

The plugin needs Python packages. If scripts fail with `ModuleNotFoundError`, set up a venv and install:

```bash
cd business-profiler
python3 scripts/setup.py --venv
source .venv/bin/activate
```

Always activate the venv before using the plugin.

## weasyprint fails to install

weasyprint needs system libraries (cairo, pango, gdk-pixbuf). On macOS:

```bash
brew install cairo pango gdk-pixbuf libffi
```

On Ubuntu/Debian:

```bash
sudo apt install libcairo2-dev libpango1.0-dev libgdk-pixbuf2.0-dev
```

Then retry `python3 scripts/setup.py --install`.

## Mermaid diagrams show as empty boxes in PDFs

If you see colored boxes with no text in the PDF, the Mermaid diagrams were rendered as inline SVG (which weasyprint can't handle). Two fixes:

1. Install mermaid-cli so diagrams render as PNG:
   ```bash
   npm install -g @mermaid-js/mermaid-cli
   ```

2. If you already generated a report without mmdc, regenerate the PDF:
   ```bash
   python3 scripts/pdf_generator.py --input ./reports/your_report.md --output ./reports/your_report.pdf
   ```

## Scripts time out or return empty results

Some data sources (crt.sh, AlienVault OTX) have rate limits. If you're running multiple profiles back-to-back, wait a few minutes between runs. The scripts handle failures gracefully — empty results won't break the report, but you'll get less data.
