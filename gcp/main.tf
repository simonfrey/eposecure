# Read-only service account for org-wide discovery. Applied by hand by an org
# admin (needs roles/resourcemanager.organizationAdmin), not from CI.
#
#   terraform init && terraform apply -var org_id=... -var project_id=...
#   gcloud secrets versions access latest --secret exposure-scanner-key | jq -c .
#
# Rotate: terraform apply -replace=google_service_account_key.scanner, then
# update GCP_SERVICE_ACCOUNT_KEY in .env and restart the scanner.

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "8.8.0"
    }
  }
}

variable "org_id" {
  type        = string
  description = "Numeric GCP organization id"
}

variable "project_id" {
  type        = string
  description = "Project that hosts the service account and secret"
}

provider "google" {
  project = var.project_id
}

resource "google_project_service" "cloudasset" {
  service            = "cloudasset.googleapis.com"
  disable_on_destroy = false
}

resource "google_service_account" "scanner" {
  account_id   = "exposure-scanner"
  display_name = "External exposure scanner (read-only inventory)"
}

# Minimum for cloudlist org mode plus the Cloud Asset search gap fill.
resource "google_organization_iam_member" "scanner" {
  for_each = toset([
    "roles/cloudasset.viewer",
    "roles/resourcemanager.organizationViewer",
    "roles/resourcemanager.folderViewer",
    "roles/browser",
  ])
  org_id = var.org_id
  role   = each.value
  member = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_service_account_key" "scanner" {
  service_account_id = google_service_account.scanner.name
}

resource "google_secret_manager_secret" "key" {
  secret_id = "exposure-scanner-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "key" {
  secret      = google_secret_manager_secret.key.id
  secret_data = base64decode(google_service_account_key.scanner.private_key)
}

output "service_account" {
  value = google_service_account.scanner.email
}
