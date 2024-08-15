import re

HOSTNAME_REGEX = re.compile(
    r"^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z]([-a-z0-9]*[a-z0-9])?)*$"
)

test_inputs = [
    # Valid Hostnames
    "example.com",
    "subdomain.example.com",
    "my-app.service.local",
    "a1b2c3.example.co.uk",
    "*.example.com",
    "xn--d1acufc.xn--p1ai",  # Punycode for internationalized domain name
    "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z",  # Maximum label count
    "localhost",

    # Edge Cases (should match)
    "a.b",  # Very short hostname with two labels 
    "a--b.example.com",  # Double hyphen inside label 
    "1234567890.com",  # All numeric but with a valid TLD 
    "*.example.com",  # Wildcard at the start, which should be valid 
    "xn--80ak6aa92e.com"  # Punycode for internationalized domain

    # Invalid Hostnames
    "-example.com",  # Starts with a hyphen
    "*-valid.example.org",
    "example-.com",  # Ends with a hyphen
    "example..com",  # Double dot
    ".example.com",  # Starts with a dot
    "example.com.",  # Ends with a dot
    "exa$mple.com",  # Contains invalid characters
    "example@com",  # Contains invalid characters
    "example.com..",  # Ends with a double dot
    "192.168.-1.1",  # Invalid label within an IP-like format
    "192.168.1.01",  # Invalid format for an IP address if it should match a hostname

    # IP Addresses (Should Not Match)
    "192.168.1.192",
    "10.0.0.1",
    "255.255.255.255",
    "172.232.192.78",
    "127.0.0.1",
    "8.8.8.8",

    # Edge Cases (Should Not Match)
    "a.*.com",  # Wildcard in the middle, which is not valid
    "a.b-",  # Label ends with a hyphen 
    "a.b.c.d.e.f.g-",  # Label ends with a hyphen at the end of a long sequence 
    "192.168.001.1",  # IP address with leading zeros, should not match
    "1.2.3.example.com",  # Mix of numeric and alphabetical labels
]


for test_input in test_inputs:
    if HOSTNAME_REGEX.match(test_input):
        print(f"Matched: {test_input}")
    else:
        print(f"Did Not Match: {test_input}")