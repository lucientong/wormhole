# Terminal Demo GIF Guide

How to create the terminal demo GIF for the README.

## Recommended Tool: VHS (charmbracelet/vhs)

[VHS](https://github.com/charmbracelet/vhs) is a CLI tool that records terminal sessions from a declarative `.tape` script. It produces reproducible GIFs — no manual screencasting needed.

### Install VHS

```bash
# macOS
brew install charmbracelet/tap/vhs

# Go install
go install github.com/charmbracelet/vhs@latest

# Also requires ffmpeg and ttyd
brew install ffmpeg ttyd
```

### Create the Tape Script

Create `docs/demo.tape`:

```tape
# Wormhole Demo
Output docs/demo.gif

# Terminal settings
Set FontSize 16
Set Width 1000
Set Height 600
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Set Padding 20

# --- Server side (split or sequential) ---
Type "# Start the wormhole server"
Enter
Sleep 500ms

Type "wormhole server --domain tunnel.example.com --port 7000"
Enter
Sleep 3s

# --- Client side ---
Type "# Expose local port 8080 to the internet"
Enter
Sleep 500ms

Type "wormhole 8080"
Enter
Sleep 3s

# Show the assigned URL
Type "# ✅ Your service is now live at https://abc123.tunnel.example.com"
Enter
Sleep 2s

# Demonstrate inspector
Type "# Enable traffic inspector"
Enter
Sleep 500ms

Type "wormhole client --local 8080 --inspector 4040"
Enter
Sleep 3s

# End
Type "# That's it! Zero config, one command."
Enter
Sleep 3s
```

### Record the GIF

```bash
# Generate the GIF
vhs docs/demo.tape

# The output file will be at docs/demo.gif
```

### Optimize the GIF (Optional)

```bash
# Using gifsicle for optimization
brew install gifsicle

gifsicle --optimize=3 --lossy=80 --colors=128 \
  docs/demo.gif -o docs/demo.gif

# Target: < 2MB for GitHub display
```

### Embed in README

Add the following to `README.md` (after the badges, before ## Features):

```markdown
<p align="center">
  <img src="docs/demo.gif" alt="Wormhole Demo" width="800">
</p>
```

## Alternative: asciinema + agg

If you prefer interactive recording:

```bash
# Install
brew install asciinema
go install github.com/asciinema/agg@latest

# Record a session interactively
asciinema rec docs/demo.cast

# Convert to GIF
agg --theme monokai docs/demo.cast docs/demo.gif
```

## Tips

1. **Keep it short** — 15-30 seconds max. Viewers lose interest quickly.
2. **Show the core value** — `wormhole 8080` → instant public URL. That's the money shot.
3. **Use a clean terminal** — Clear the history, use a nice prompt (e.g., `PS1="$ "`).
4. **Test the GIF size** — GitHub renders poorly above ~5MB. Use gifsicle to compress.
5. **Reproducibility** — VHS `.tape` files are version-controllable and CI-friendly.
