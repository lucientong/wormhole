# Homebrew Installation Guide

How to set up Homebrew tap so users can install Wormhole via `brew install`.

## Prerequisites

- A GitHub account (`lucientong`)
- GoReleaser already configured (`.goreleaser.yml` has a `brews` section)
- A GitHub release exists (at least `v0.1.0`)

## Step 1: Create the Homebrew Tap Repository

```bash
# Create a new public repository named "homebrew-tap" on GitHub
# URL: https://github.com/lucientong/homebrew-tap

# Option A: via GitHub CLI
gh repo create lucientong/homebrew-tap --public --description "Homebrew formulae for Wormhole"

# Option B: via the GitHub web UI
# Go to https://github.com/new and create "homebrew-tap" (public)
```

> **Important**: The repository name MUST start with `homebrew-` for Homebrew to recognize it as a tap.

## Step 2: Initialize the Repository

```bash
git clone https://github.com/lucientong/homebrew-tap.git
cd homebrew-tap
mkdir -p Formula
echo "# Homebrew Tap for Wormhole\n\nInstall: \`brew install lucientong/tap/wormhole\`" > README.md
git add .
git commit -m "Initial commit"
git push origin main
```

## Step 3: Configure GoReleaser (Already Done)

The `.goreleaser.yml` already contains the correct `brews` section:

```yaml
brews:
  - name: wormhole
    repository:
      owner: lucientong
      name: homebrew-tap
    folder: Formula
    homepage: https://github.com/lucientong/wormhole
    description: Zero-config tunnel tool to expose local services to the internet
    license: Apache-2.0
    install: |
      bin.install "wormhole"
    test: |
      system "#{bin}/wormhole", "version"
```

## Step 4: Set Up GitHub Token Permissions

GoReleaser needs a token with permission to push to the `homebrew-tap` repo.

### Option A: Use GITHUB_TOKEN (Same Owner)

If both repos are under `lucientong`, the default `GITHUB_TOKEN` in GitHub Actions has enough permissions **if** you add write permission:

```yaml
# In release.yml
permissions:
  contents: write
```

### Option B: Use a Personal Access Token (PAT)

If the default token doesn't work (e.g., cross-org), create a PAT:

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Create a token with:
   - **Repository access**: `lucientong/homebrew-tap`
   - **Permissions**: Contents → Read and write
3. Add the token as a secret in the `wormhole` repo:
   - Go to **Settings → Secrets and variables → Actions**
   - Add `HOMEBREW_TAP_TOKEN` with the PAT value
4. Update `release.yml`:
   ```yaml
   - name: Run GoReleaser
     uses: goreleaser/goreleaser-action@v5
     with:
       args: release --clean
     env:
       GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
       HOMEBREW_TAP_GITHUB_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
   ```
5. Update `.goreleaser.yml`:
   ```yaml
   brews:
     - name: wormhole
       repository:
         owner: lucientong
         name: homebrew-tap
         token: "{{ .Env.HOMEBREW_TAP_GITHUB_TOKEN }}"
   ```

## Step 5: Create a Release

```bash
# Tag a version
git tag v0.1.0
git push origin v0.1.0

# GoReleaser will automatically:
# 1. Build binaries for all platforms
# 2. Create a GitHub Release
# 3. Push a Formula/wormhole.rb to lucientong/homebrew-tap
```

## Step 6: Verify Installation

After the release pipeline completes:

```bash
# Add the tap
brew tap lucientong/tap

# Install wormhole
brew install wormhole

# Or in one command
brew install lucientong/tap/wormhole

# Verify
wormhole version
```

## Step 7: Update README

Add to the Installation section:

```markdown
### Homebrew (macOS/Linux)

```bash
brew install lucientong/tap/wormhole
```
```

## Updating the Formula

When you push a new tag (e.g., `v0.2.0`), GoReleaser will automatically update the formula in the tap repository. No manual action needed.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Error: No available formula with the name "wormhole"` | Run `brew tap lucientong/tap` first |
| GoReleaser fails to push formula | Check token permissions (needs Contents: write on `homebrew-tap`) |
| Formula has wrong SHA | GoReleaser computes it automatically — ensure the release completed |
| `brew install` fails on Linux | Verify `goos: linux` is in `.goreleaser.yml` builds |
