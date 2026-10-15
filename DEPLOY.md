# Deploying to the cloud

The app ships as a single container (see `Dockerfile`): the FastAPI backend serves the API and the built
React frontend, runs as a non-root user, and keeps all state in `/data`. Any platform that runs a
container behind HTTPS works. Below is the recommended path (Azure Container Apps) plus Google Cloud Run.

**Before you deploy, decide three things:**

1. **Passwords** for the `exec`, `analyst`, and `admin` accounts (long and unique — this URL is public).
2. **An encryption key** for stored integration credentials:
   ```bash
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
3. **One instance only.** SQLite and server-side sessions live in the container, so run exactly one replica.
   Storage is ephemeral: on restart the demo data regenerates and edits (roadmap, goals) are lost.
   Production would move to a managed database (Azure Database for PostgreSQL / Cloud SQL) and allow scaling out.

All secrets go into the platform's secret store and reach the app as environment variables. They are never baked into the image.

---

## Option A — Azure Container Apps (recommended)

Requires the Azure CLI (`brew install azure-cli`) and an Azure subscription.

```bash
az login
az extension add --name containerapp --upgrade
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights

# Build the image in Azure (no local Docker needed) and create the app with an HTTPS URL
az containerapp up \
  --name cyber-risk-dashboard \
  --resource-group cyber-risk-rg \
  --location eastus \
  --source . \
  --ingress external \
  --target-port 8000
```

Store the secrets and wire them to environment variables (replace the `<...>` values):

```bash
az containerapp secret set -n cyber-risk-dashboard -g cyber-risk-rg --secrets \
  exec-pw='<exec password>' analyst-pw='<analyst password>' admin-pw='<admin password>' fernet-key='<key>' \
  anthropic-key='<Claude API key>'

az containerapp update -n cyber-risk-dashboard -g cyber-risk-rg \
  --min-replicas 1 --max-replicas 1 \
  --set-env-vars \
    DASHBOARD_PASSWORD_EXECUTIVE=secretref:exec-pw \
    DASHBOARD_PASSWORD_ANALYST=secretref:analyst-pw \
    DASHBOARD_PASSWORD_ADMIN=secretref:admin-pw \
    DASHBOARD_SECRET_KEY=secretref:fernet-key \
    ANTHROPIC_API_KEY=secretref:anthropic-key
```

Get the URL:

```bash
az containerapp show -n cyber-risk-dashboard -g cyber-risk-rg --query properties.configuration.ingress.fqdn -o tsv
```

Redeploy after code changes: run the same `az containerapp up ... --source .` command.

Remove everything (stops all charges):

```bash
az group delete -n cyber-risk-rg --yes
```

---

## Option B — Google Cloud Run

Requires the gcloud CLI and a project with billing enabled.

```bash
gcloud auth login
gcloud config set project <project-id>
gcloud services enable run.googleapis.com cloudbuild.googleapis.com secretmanager.googleapis.com

# Secrets
printf '%s' '<exec password>'    | gcloud secrets create crd-exec-pw --data-file=-
printf '%s' '<analyst password>' | gcloud secrets create crd-analyst-pw --data-file=-
printf '%s' '<admin password>'   | gcloud secrets create crd-admin-pw --data-file=-
printf '%s' '<fernet key>'       | gcloud secrets create crd-fernet-key --data-file=-
printf '%s' '<Claude API key>'   | gcloud secrets create crd-anthropic-key --data-file=-

# Build from the Dockerfile and deploy (the app's own sign-in protects it)
gcloud run deploy cyber-risk-dashboard --source . --region us-east4 \
  --allow-unauthenticated --min-instances 1 --max-instances 1 \
  --set-secrets DASHBOARD_PASSWORD_EXECUTIVE=crd-exec-pw:latest,DASHBOARD_PASSWORD_ANALYST=crd-analyst-pw:latest,DASHBOARD_PASSWORD_ADMIN=crd-admin-pw:latest,DASHBOARD_SECRET_KEY=crd-fernet-key:latest,ANTHROPIC_API_KEY=crd-anthropic-key:latest
```

The service account Cloud Run uses needs the *Secret Manager Secret Accessor* role. Cloud Run sets `PORT`
automatically, and the container already listens on it.

Remove: `gcloud run services delete cyber-risk-dashboard --region us-east4`

---

## After deploying — verify

- `https://<your-url>/api/health` returns `{"status":"ok"}`.
- The site opens on the sign-in page, and `https://<your-url>/api/summary` returns 401 when signed out.
- Response headers include `Strict-Transport-Security` and `Content-Security-Policy`.
- Sign in as each role and check the sidebar changes (Settings → Access & Audit shows the sign-ins).
- Wait ~30 seconds after the first start for live threat feeds to load.

## Production hardening (talking points)

- Replace local passwords with SSO (Entra ID / Okta via OIDC), mapping identity-provider groups to the three roles.
- Managed PostgreSQL with private networking; multiple replicas; sessions in the database or Redis.
- Store the encryption key in Key Vault / Cloud KMS and rotate it.
- Restrict egress to the vendor API and feed domains; a WAF in front of the ingress.
- Container image scanning and signing in CI before deployment.
