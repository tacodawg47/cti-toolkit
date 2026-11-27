"""Compose trusted module catalogs without transferring collection authority."""


def catalog():
    from ..modules.vulnerability_intelligence.scheduled import catalog as vulnerability
    from ..modules.ransomware.ransomlook import catalog as ransomware
    from ..modules.breaches.hibp import catalog as breaches
    from ..modules.ct_watch.crtsh import catalog as ct_watch
    return vulnerability() + ransomware() + breaches() + ct_watch()
