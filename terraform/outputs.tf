output "app_name" {
  value = juju_application.this_app.name
}

output "endpoints" {
  value = {
    # Requires
    certificates  = "certificates"
    charm-tracing = "charm-tracing"
    forward-auth  = "forward-auth"

    # Provides
    ingress                 = "ingress"
    ingress-unauthenticated = "ingress-unauthenticated"
    metrics-endpoint        = "metrics-endpoint"
  }
}
