import pytest
from ops.testing import Harness

from charm import IstioIngressCharm

# Example inputs for the test cases
test_inputs = [
    # Valid Hostnames
    ("example.com", True),
    ("subdomain.example.com", True),
    ("my-app.service.local", True),
    ("a1b2c3.example.co.uk", True),
    ("xn--d1acufc.xn--p1ai", True),  # Punycode for internationalized domain name
    ("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z", True),  # Maximum label count
    ("localhost", True),
    # Edge Cases (should match)
    ("a.b", True),  # Very short hostname with two labels
    ("a--b.example.com", True),  # Double hyphen inside label
    ("1234567890.com", True),  # All numeric but with a valid TLD
    ("xn--80ak6aa92e.com", True),  # Punycode for internationalized domain
    # Invalid Hostnames
    ("-example.com", False),  # Starts with a hyphen
    ("*-valid.example.org", False),
    ("example-.com", False),  # Ends with a hyphen
    ("*.example.com", False),  # Wildcard at the start
    ("example..com", False),  # Double dot
    (".example.com", False),  # Starts with a dot
    ("example.com.", False),  # Ends with a dot
    ("exa$mple.com", False),  # Contains invalid characters
    ("example.com..", False),  # Ends with a double dot
    # IP Addresses (Should Not Match)
    ("192.168.1.192", False),
    ("10.0.0.1", False),
    ("255.255.255.255", False),
    # Edge Cases (Should Not Match)
    ("a.*.com", False),  # Wildcard in the middle, which is not valid
    ("a.b-", False),  # Label ends with a hyphen
    ("1.2.3.example.com", False),  # Mix of numeric and alphabetical labels
]


@pytest.fixture()
def harness():
    harness = Harness(IstioIngressCharm)
    harness.set_model_name("istio-system")
    yield harness
    harness.cleanup()


@pytest.mark.parametrize("hostname, expected", test_inputs)
def test_is_valid_hostname(hostname: str, expected: bool, harness: Harness[IstioIngressCharm]):
    """Test the _is_valid_hostname method with various hostname inputs."""
    harness.begin()
    charm = harness.charm
    result = charm._is_valid_hostname(hostname)
    assert result == expected, f"Hostname {hostname}: expected {expected}, got {result}"
