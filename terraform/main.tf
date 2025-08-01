/**
 * # Istio Ingress Terraform Module
 *
 * This is a Terraform module facilitating the deployment of istio-ingress-k8s, using the [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).
 *
 * For detailed information on Istio Ingress and the Canonical Service Mesh, see the [official documentation](https://canonical-service-mesh-documentation.readthedocs-hosted.com/en/latest/).
 *
 * ## Usage
 *
 * Create `main.tf`:
 *
 * ```hcl
 * module "istio-ingress" {
 *   source  = "git::https://github.com/canonical/istio-ingress-k8s-operator//terraform"
 *   model   = juju_model.k8s.name
 *   channel = "1/stable"
 * }
 * ```
 *
 * ```sh
 * $ terraform apply
 * ```
 */

resource "juju_application" "this_app" {
  name               = var.app_name
  config             = var.config
  constraints        = var.constraints
  model              = var.model
  storage_directives = var.storage_directives
  trust              = true
  units              = var.units

  charm {
    name     = "istio-ingress-k8s"
    channel  = var.channel
    revision = var.revision
  }
}
