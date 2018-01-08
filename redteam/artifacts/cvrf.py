from datetime import datetime
from redteamcore import TransformableDict
from redteam.sources.update_announce.update_announce_message import UpdateAnnounceMessage
from redteam.sources.nvd import CveItem



SEVERITIES = dict(LOW=1, MEDIUM=2, MODERATE=2, HIGH=3, CRITICAL=4, NONE=0)

class CVRF(TransformableDict):

    def __init__(self, advisory_id, data_dir=None, logger=None):
        self.advisory_id = advisory_id
        self.version_number = 1
        kwargs = dict()
        args = []
        
        super(CVRF, self).__init__(*args, **kwargs)
        self['cvrfdoc'] = self.cvrfdoc
        

    @property
    #TODO: THis ain't working well
    def revision(self):
        try:
            return self['cvrfdoc']['version'] + 1
        except KeyError:
            return self.version_number

    @property
    def revision_date(self):
        return datetime.now().replace(microsecond=0).isoformat()

    @property
    def initial_release_date(self):
        try:
            return self['cvrfdoc']['initial_release_date']
        except KeyError:
            return datetime.now().replace(microsecond=0).isoformat()


    @property
    def document_type(self):
        return "Security Advisory"

    @property
    def document_publisher(self):
        return dict(contact_details="IRC: #fedora-security",
                    issuing_authority="Fedora Red Team SIG",
                    type="Other")
    @property
    def cves(self):
        # pylint: disable=E1101
        return list(set([cve for uam in UpdateAnnounceMessage.objects.filter(advisory_id=self.advisory_id) for cve in uam.cves]))


    @property
    def references(self):
        # pylint: disable=E1101
        return list(set([reference['url'] for cve in self.cves for cve_item in CveItem.objects.filter(cveid=cve) for reference in cve_item.references]))

    @property
    def product_relationships(self):
        # pylint: disable=E1101
        return [uam.product_relationship for uam in UpdateAnnounceMessage.objects.filter(advisory_id=self.advisory_id)]

    @property
    def product_version_branches(self):
        # pylint: disable=E1101
        return [uam.version_branch for uam in UpdateAnnounceMessage.objects.filter(advisory_id=self.advisory_id)]

    @property
    def product_families(self):
        # pylint: disable=E1101
        return [uam.product_family for uam in UpdateAnnounceMessage.objects.filter(advisory_id=self.advisory_id)]


    def product_family_branch(self, family_name):
        # pylint: disable=E1101
        return [uam.family_branch for uam in UpdateAnnounceMessage.objects.filter(advisory_id=self.advisory_id) if uam.product_family == family_name]

    @property
    def product_family_branches(self):
        return [dict(name=family, type="Product Family", branch=self.product_family_branch(family)) for family in self.product_families]

    @property
    def branches(self):
        return self.product_version_branches + self.product_family_branches

    @property
    def cvrfdoc(self):
        return dict(cvrfdoc=dict(document_type=self.document_type,
                                 document_publisher=self.document_publisher,
                                 document_tracking=dict(identification=dict(id=self.advisory_id)),
                                 status="Final",
                                 version=self.revision,
                                 revision_history=dict(revision=dict(number=self.revision,
                                                                     # pylint: disable=E1101
                                                                     date=self.revision_date,
                                                                     description='Current version')),
                                 # pylint: disable=E1101
                                 initial_release_date=self.initial_release_date,
                                 # pylint: disable=E1101
                                 current_release_date=self.revision_date,
                                 generator=dict(engine="Fedora Red Team Software Development Kit",
                                                date=datetime.now().isoformat()),
                                 document_notes=dict(notes=[]),
                                 document_references=dict(reference=[dict(url=reference, description=reference) for reference in self.references]),
                                 product_tree=dict(relationship=self.product_relationships,
                                                   xmlns="http://www.icasi.org/CVRF/schema/prod/1.1",
                                                   branch=self.branches),
                                                   
                                 xmlns='http://www.icasi.org/CVRF/schema/cvrf/1.1',
                                 xmlnscvrf="http://www.icasi.org/CVRF/schema/cvrf/1.1"))
