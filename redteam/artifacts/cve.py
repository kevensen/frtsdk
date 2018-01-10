import os
from redteamcore import Resource
from redteam.sources.nvd import CveItem
from redteam.sources.update_announce import UpdateAnnounceMessage


class CVE(Resource):
    def __init__(self, cveid, data_dir=None, output_format='json', logger=None, basehost=None):
        self.cveid = cveid
        self.output_format = output_format

        if logger:
            self.log = logger


        if data_dir:
            location = os.path.join(data_dir, 'cve', cveid)
            location = '.'.join([location, output_format])
            super(CVE, self).__init__(location, logger=logger)

    def write(self):
        if self.output_format.startswith('j'):
            super(CVE, self).write(dict(self))

    @property
    def name(self):
        return self.cveid

    @property
    def cve_item(self):
        # pylint: disable=E1101
        cve_item = CveItem.objects.filter(cveid=self.cveid).first()
        if cve_item:
            return cve_item
        raise CVENotFoundError("CVE %s was not found in NVD Data." % self.cveid)

    @property
    def threat_severity(self):
        return self.cve_item.cvss3severity

    @property
    def public_date(self):
        return self.cve_item.publishedDate.isoformat()

    @property 
    def bugzilla(self):
        return dict()

    @property
    def cvss(self):
        return dict(cvss_base_score=self.cve_item.cvss3score,
                    cvss_scoring_vector=self.cve_item.cvss3vector,
                    status='unverified')
    @property
    def cwe(self):
        return self.cve_item.cwe

    @property
    def iava(self):
        return ""

    @property
    def details(self):
        return []

    @property
    def acknowledgement(self):
        return ""

    @property
    def references(self):
        # pylint: disable=E1101
        return list(set([reference['url'] for cve_item in CveItem.objects.filter(cveid=self.cveid) for reference in cve_item.references]))

    @property
    def document_distribution(self):
        return ""

    @property
    def update_announce_messages(self):
        # pylint: disable=E1101
        return UpdateAnnounceMessage.objects.filter(__raw__={'cves': self.cveid})

    @property
    def affected_releases(self):
        affected_releases = []
        for uam in self.update_announce_messages:
            if not any(affected_release['product_name'] == uam.product for affected_release in affected_releases):
                affected_releases.append(dict(product_name=uam.product,
                                              release_date=uam.message_date.isoformat(),
                                              advisory=uam.advisory_id,
                                              package=uam.rpm,
                                              cpe=uam.cpe))
        return affected_releases

    @property
    def package_state(self):
        return [dict(product_name=uam.product, fix_state="Affected", package_name=uam.rpmname, cpe=uam.cpe)for uam in self.update_announce_messages]


    #TODO: Re-implement dictionary output
    def __iter__(self):
        return dict(threat_severity=self.threat_severity,
                    public_date=self.public_date,
                    bugzilla=self.bugzilla,
                    cvss=self.cvss,
                    cwe=self.cwe,
                    iava=self.iava,
                    details=self.details,
                    acknowledgement=self.acknowledgement,
                    affected_release=self.affected_releases,
                    package_state=self.package_state,
                    references=self.references,
                    name=self.name,
                    document_distribution=self.document_distribution).iteritems()

class CVENotFoundError(Exception):
    def __init__(self, message):
        super(CVENotFoundError, self).__init__(message)