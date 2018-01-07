import os
from redteam.sources.nvd import CveItem
from redteam.sources.update_announce import UpdateAnnounceMessage
from redteam.core import SaveableLoadableDict

class CVE(SaveableLoadableDict):
    def __init__(self, cveid, data_dir=None, logger=None):
        self.cveid = cveid
        kwargs = dict()
        args = []
        if data_dir:
            kwargs['location'] = os.path.join(data_dir, 'cvrf', self.cveid) + '.json'
        if logger:
            kwargs['logger'] = logger

        super(CVE, self).__init__(*args, **kwargs)

        if self.exists:
            self['threat_severity'] = self.data['threat_severity']
            self['public_date'] = self.data['public_date']
            self['bugzilla'] = self.data['bugzilla']
            self['cvss'] = self.data['cvss']
            self['cwe'] = self.data['cwe']
            self['iava'] = self.data['iava']
            self['details'] = self.data['details']
            self['acknowledgement'] = self.data['acknowledgement']
            self['affected_release'] = self.data['affected_releases']
            self['package_state'] = self.data['package_state']
            self['references'] = self.data['references']
            self['document_distribution'] = self.data['document_distribution']
            self['name'] = self.data['name']
        else:
            self['threat_severity'] = self.threat_severity
            self['public_date'] = self.public_date
            self['bugzilla'] = self.bugzilla
            self['cvss'] = self.cvss
            self['cwe'] = self.cwe
            self['iava'] = self.iava
            self['details'] = self.details
            self['acknowledgement'] = self.acknowledgement
            self['affected_release'] = self.affected_releases
            self['package_state'] = self.package_state
            self['references'] = self.references
            self['document_distribution'] = self.document_distribution
            self['name'] = self.name

    @property
    def name(self):
        return self.cveid

    @property
    def cve_item(self):
        return CveItem.objects.filter(cveid=self.cveid).first()

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
        return list(set([reference['url'] for cve in self.cves for cve_item in CveItem.objects.filter(cveid=cve) for reference in cve_item.references]))

    @property
    def document_distribution(self):
        return ""

    @property
    def update_announce_messages(self):
        return UpdateAnnounceMessage.objects.filter(__raw__={'cves': self.cveid})

    @property
    def affected_releases(self):
        return [dict(product_name=uam.product, release_date=uam.message_date, advisory=uam.advisory_id, package=uam.rpm, cpe=uam.cpe) for uam in self.update_announce_messages]

    @property
    def package_state(self):
        return [dict(product_name=uam.product, fix_state="Affected", package_name=uam.rpmname, cpe=uam.cpe)for uam in self.update_announce_messages]

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
                    document_distribution=self.document_distribution,
                    name=self.name).iteritems()

