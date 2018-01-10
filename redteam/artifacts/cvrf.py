import os
from datetime import datetime
from redteamcore import Resource
from redteam.sources.update_announce.update_announce_message import UpdateAnnounceMessage
from redteam.sources.nvd import CveItem

SEVERITIES = dict(LOW=1, MEDIUM=2, MODERATE=2, HIGH=3, CRITICAL=4, NONE=0)

class CVRF(Resource):

    def __init__(self, advisory_id, data_dir=None, output_format='json', logger=None, basehost=None):
        self.advisory_id = advisory_id
        self.basehost = basehost
        self.new = True
        self.version_number = 1

        self.output_format = output_format

        if logger:
            self.log = logger

        if data_dir:
            location = os.path.join(data_dir, 'cvrf', advisory_id)
            location = '.'.join([location, output_format])
            super(CVRF, self).__init__(location, logger=logger)
            if self.exists:
                self.new = False
                try:
                    self.version_number = self.data['version']
                except KeyError:
                    pass

    def write(self):
        if self.output_format.startswith('j'):
            super(CVRF, self).write(self.cvrfdoc)

    @property
    def revision_date(self):
        try:
            return self.data['revision_date']
        except (AttributeError, IOError):
            pass
        return datetime.now().replace(microsecond=0).isoformat()

    @property
    def initial_release_date(self):
        # pylint: disable=E1101
        UpdateAnnounceMessage.objects.filter(advisory_id=self.advisory_id).first().advisory_release_date

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
                                 version=1,
                                 revision_history=dict(revision=dict(number=1,
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
