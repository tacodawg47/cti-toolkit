"""Compose trusted module catalogs without transferring collection authority."""


def catalog():
    from ..modules.vulnerability_intelligence.scheduled import catalog as vulnerability
    from ..modules.ransomware.ransomlook import catalog as ransomware
    from ..modules.breaches.hibp import catalog as breaches
    return vulnerability() + ransomware() + breaches()
