import re
from datetime import datetime
from mongoengine import DictField
from mongoengine import Document
from mongoengine import StringField
from mongoengine import IntField
from mongoengine import DateTimeField
from redteam.sources.update_announce.update_announce_message import UpdateAnnounceMessage
from redteam.sources.nvd import CveItem



BUGZILLA_REGEX = re.compile(r"""(\s*\[ \d \] Bug \#(\d+) - (.+)
\s*(https:\/\/bugzilla\.redhat\.com.*))+?""", re.MULTILINE)
ADVISORY_REGEX = re.compile(r"""(^\s*FEDORA\-.*|^\s*RHSA-.*|^\s*CEBA-.*)
(\d\d\d\d-\d\d-\d\d\s*\d\d:\d\d|\d\d\d\d-\d\d-\d\d)""", re.MULTILINE)
SUMMARY_REGEX = re.compile(r'^Summary\W*(.*)$', re.MULTILINE)

SEVERITIES = dict(LOW=1, MEDIUM=2, MODERATE=2, HIGH=3, CRITICAL=4, NONE=0)

class CVRF(Document):
    advisory_id = StringField(required=True, primary_key=True)
    document_type = StringField(required=True, default="Security Advisory")
    document_publisher = DictField(required=True, default=dict(contact_details="IRC: #fedora-security",
                                                               issuing_authority="Fedora Red Team SIG",
                                                               type="Other"))
    revision_number = IntField(required=True, default=1)
    revision_date = DateTimeField()
    initial_release_date = DateTimeField()

    def __init__(self, **data):
        Document.__init__(self)
        if not self.advisory_id:
            try:
                self.advisory_id = data['advisory_id']
            except KeyError:
                pass

        if not self.initial_release_date:
            self.initial_release_date = datetime.now()

        if not self.revision_date:
            self.revision_date = datetime.now()

    def revise(self):
        self.revision_date = datetime.now()
        self.revision_number += 1

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
    def todict(self):
        return dict(cvrfdoc=dict(document_type=self.document_type,
                                 document_publisher=self.document_publisher,
                                 document_tracking=dict(identification=dict(id=self.advisory_id)),
                                 status="Final",
                                 version=self.revision_number,
                                 revision_history=dict(revision=dict(number=self.revision_number,
                                                                     # pylint: disable=E1101
                                                                     date=self.revision_date.replace(microsecond=0).isoformat(),
                                                                     description='Current version')),
                                 # pylint: disable=E1101
                                 initial_release_date=self.initial_release_date.replace(microsecond=0).isoformat(),
                                 # pylint: disable=E1101
                                 current_release_date=self.revision_date.replace(microsecond=0).isoformat(),
                                 generator=dict(engine="Fedora Red Team Software Development Kit",
                                                date=datetime.now().isoformat()),
                                 document_notes=dict(notes=[]),
                                 document_references=dict(reference=[dict(url=reference, description=reference) for reference in self.references]),
                                 product_tree=dict(relationship=self.product_relationships,
                                                   xmlns="http://www.icasi.org/CVRF/schema/prod/1.1",
                                                   branch=self.branches)))
