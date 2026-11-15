"""Shared domain zones for optional direct routing in both VPN cores."""

# Browsers send the IDNA form of .рф. Match complete DNS labels, not keywords.
RUSSIAN_DOMAIN_SUFFIXES = ("xn--p1ai", "su", "ru")
