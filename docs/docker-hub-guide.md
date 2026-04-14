# Docker Hub Publishing Guide

How to set up Docker Hub so the release pipeline can automatically push Wormhole images.

## Prerequisites

- A Docker Hub account
- The `release.yml` workflow already has a Docker build-and-push job
- A `Dockerfile` exists at `deployments/docker/Dockerfile`

## Step 1: Create a Docker Hub Account

1. Go to [https://hub.docker.com/signup](https://hub.docker.com/signup)
2. Create an account (e.g., username: `lucientong`)

## Step 2: Create the Repository

1. Go to [https://hub.docker.com/repositories](https://hub.docker.com/repositories)
2. Click **Create repository**
3. Fill in:
   - **Name**: `wormhole`
   - **Description**: Zero-config tunnel tool to expose local services to the internet
   - **Visibility**: Public
4. Click **Create**

The image will be available as: `lucientong/wormhole`

## Step 3: Create an Access Token

Using an access token (instead of your password) is more secure and recommended:

1. Go to **Account Settings → Security → Access Tokens**
   (URL: https://hub.docker.com/settings/security)
2. Click **New Access Token**
3. Fill in:
   - **Description**: `wormhole-github-actions`
   - **Access permissions**: Read & Write
4. Click **Generate**
5. **Copy the token** — you won't see it again!

## Step 4: Add Secrets to GitHub

1. Go to your GitHub repository **Settings → Secrets and variables → Actions**
2. Add two secrets:

| Secret Name | Value |
|---|---|
| `DOCKERHUB_USERNAME` | Your Docker Hub username (e.g., `lucientong`) |
| `DOCKERHUB_TOKEN` | The access token from Step 3 |

## Step 5: Update the Release Workflow

The `release.yml` docker job already references these secrets. Make sure the image name matches your Docker Hub repository:

```yaml
# In .github/workflows/release.yml → docker job
- name: Extract metadata
  id: meta
  uses: docker/metadata-action@v5
  with:
    images: lucientong/wormhole  # ← Must match your Docker Hub repo
    tags: |
      type=semver,pattern={{version}}
      type=semver,pattern={{major}}.{{minor}}
      type=semver,pattern={{major}}
      type=sha
```

> **Note**: The current `release.yml` uses `wormhole/wormhole` as the image name. Update it to `lucientong/wormhole` (or your chosen namespace).

## Step 6: Trigger a Release

```bash
# Tag and push
git tag v0.1.0
git push origin v0.1.0

# The release workflow will:
# 1. Run GoReleaser (release job)
# 2. Build multi-arch Docker images (docker job)
#    - linux/amd64
#    - linux/arm64
# 3. Push to Docker Hub with tags:
#    - lucientong/wormhole:0.1.0
#    - lucientong/wormhole:0.1
#    - lucientong/wormhole:0
#    - lucientong/wormhole:sha-abc1234
```

## Step 7: Verify

```bash
# Pull the image
docker pull lucientong/wormhole:latest

# Run the server
docker run -d \
  -p 7000:7000 -p 80:80 -p 443:443 \
  -e WORMHOLE_DOMAIN=tunnel.example.com \
  lucientong/wormhole:latest server

# Check version
docker run --rm lucientong/wormhole:latest version
```

## Step 8: Update README

Update Docker references in `README.md` and `README_zh.md` to use your actual Docker Hub image name:

```markdown
### Docker (Recommended)

```bash
docker pull lucientong/wormhole:latest

docker run -d \
  -p 7000:7000 -p 80:80 -p 443:443 \
  -e WORMHOLE_DOMAIN=tunnel.example.com \
  lucientong/wormhole:latest server
```
```

## Step 9: Add Docker Hub README (Optional)

You can sync your GitHub README to Docker Hub:

1. Go to your Docker Hub repository → **General**
2. In the **Repository overview** section, paste or link your README
3. Or use the [peter-evans/dockerhub-description](https://github.com/peter-evans/dockerhub-description) GitHub Action to auto-sync

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `denied: requested access to the resource is denied` | Check `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets |
| Multi-arch build fails | Ensure `docker/setup-qemu-action@v3` is in the workflow |
| Image tag `latest` not created | Add `type=raw,value=latest,enable={{is_default_branch}}` to metadata tags |
| Large image size | Current alpine-based image is ~15MB. Use `docker images` to verify |
