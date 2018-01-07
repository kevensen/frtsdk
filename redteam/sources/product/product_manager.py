import logging
from redteam.core import Resource

#TODO: Yeah, I know this is HTTP vs. HTTPS.  Will implement checksum at some point.
RELEASES = dict(Fedora21Server=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/21/Server/x86_64/os/repodata/5b8af56df46c99e22dc9e9efcf8fbf2611bb066cb7d5496f124bead00ce01b5b-primary.xml.gz',
                                    name="Fedora Linux Server (v. 21)"),
                Fedora21Workstation=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/22/Workstation/x86_64/os/repodata/b65bce004d51d04e3b72bb097fde9a2cc89cd28ace5eff6b6dbf38db994952a4-primary.xml.gz',
                                         name='Fedora Linux Workstation (v. 22)'),
                Fedora22Server=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/22/Server/x86_64/os/repodata/2cc69387ff1588f824cab8840b83ccad6f53cf10d4251baed39ccf16fc7e2089-primary.xml.gz',
                                    name="Fedora Linux Server (v. 22)"),
                Fedora22Workstation=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/22/Workstation/x86_64/os/repodata/b65bce004d51d04e3b72bb097fde9a2cc89cd28ace5eff6b6dbf38db994952a4-primary.xml.gz',
                                         name='Fedora Linux Workstation (v. 22)'),
                Fedora23Server=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/23/Server/x86_64/os/repodata/74cc4dea9aa03468388e1167737143d67e94daa62cfd91d3361349372523ac6d-primary.xml.gz',
                                    name="Fedora Linux Server (v. 23)"),
                Fedora23Workstation=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/23/Workstation/x86_64/os/repodata/e234313a9baab9bcc6384ba41be5b6d082b3a13600e231fe3ccdf4f79dbc4ddb-primary.xml.gz',
                                         name='Fedora Linux Workstation (v. 23)'),
                Fedora24Server=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/24/Server/source/tree/repodata/b87a68126a8506600883daac917fb9ab0e4bf614c563507149f38674ba0c668a-primary.xml.gz',
                                    name='Fedora Linux Server (v. 24)'),
                Fedora24Workstation=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/24/Workstation/source/tree/repodata/217ed940397ddd02a917143be2dca586ecb6955217c7fee1de402021dfb0e187-primary.xml.gz',
                                         name='Fedora Linux Workstation (v. 24)'),
                Fedora25Server=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/25/Server/source/tree/repodata/046f30aeb62e3a907bd98fb52f9b330c218e23cbddd6d60bbebe653d967e74cc-primary.xml.gz',
                                    name='Fedora Linux Server (v. 25)'),
                Fedora25Workstation=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/25/Workstation/source/tree/repodata/f0ecf609b4e5c511b8241c1d8c56186b21b514ce77795718916f668b4ae764f3-primary.xml.gz',
                                         name='Fedora Linux Workstation (v. 25)'),
                Fedora26Server=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/26/Server/source/tree/repodata/68d205b6ca59559ea61b773bd7f3f90e7669a1ba27d3937d8adcd24dce1ffc83-primary.xml.gz',
                                    name='Fedora Linux Server (v.26)'),
                Fedora26Workstation=dict(location='http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/26/Workstation/source/tree/repodata/7dea74e1cbf9820821f42e731b27da1eddf1aeab626749774677701e6ebeb888-primary.xml.gz',
                                         name="Fedora Linux Workstation (v. 26)"))

class ProductManager(Resource):
    def __init__(self, **kwargs):
        if kwargs and kwargs['location']:
            super(ProductManager, self).__init__(kwargs['location'])
            kwargs.pop('location')
            self.connector.open()
        self.log = None
        if kwargs and kwargs['logger']:
            self.log = logging.getLogger(kwargs['logger'])
            kwargs.pop('logger')

        self.tlsverify = kwargs['tlsverify']

        self.product_sources = dict()

    # https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/export/announce@lists.fedoraproject.org-May-2006.mbox.gz?start=2006-05-01&end=2006-06-01
    # https://lists.centos.org/pipermail/centos-announce/2005-March.txt.gz
    def build(self, force=False, alldata=False):
        pass