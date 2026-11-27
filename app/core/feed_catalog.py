"""Compose trusted module catalogs without transferring collection authority."""


def catalog():
    from ..modules.vulnerability_intelligence.scheduled import catalog as vulnerability
    from ..modules.ransomware.ransomlook import catalog as ransomware
    from ..modules.breaches.hibp import catalog as breaches
    from ..modules.ct_watch.crtsh import catalog as ct_watch
    from ..modules.github_exposure.github import catalog as github_exposure
    from ..modules.subdomains.ctlogs import catalog as subdomains
    from ..modules.cloud_exposure.shodan import catalog as cloud_exposure
    return vulnerability() + ransomware() + breaches() + ct_watch() + github_exposure() + subdomains() + cloud_exposure()
