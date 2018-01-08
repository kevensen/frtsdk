from datetime import datetime
from mongoengine import Document
from mongoengine import DateTimeField
from mongoengine import URLField
from mongoengine import ListField
from mongoengine import ReferenceField
from redteamcore import Resource
from redteam.sources.nvd import CveItem


class NvdSource(Resource, Document):

    lastUpdated = DateTimeField(required=True)
    location = URLField(required=True, primary_key=True)
    cve_items = ListField(ReferenceField(CveItem))

    def __init__(self, **data):
        location = data['location']
        try:
            tlsverify = data['tlsverify']
            logger = data['logger']

            Resource.__init__(self, location=location,
                              tlsverify=tlsverify,
                              logger=logger)
        except KeyError:
            pass
        
        Document.__init__(self)

        self.location = location
        self.lastUpdated = datetime.now()

    def cve_item(self, cveid):
        # pylint: disable=E1101
        return CveItem.objects.filter(cveid=cveid).first()

    def has_cve_item(self, cveid):
        if self.cve_item(cveid):
            return True
        return False

    def build(self):
        cves_added = []
        cves_modified = []
        cves_untouched = []
        for cve_item_def in self.cves:
            cveid_to_add = cve_item_def['cve']['CVE_data_meta']['ID']
            cve_to_add_last_modified = datetime.strptime(cve_item_def['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')

            if not self.has_cve_item(cveid_to_add):
                cve_item = CveItem(**cve_item_def)
                cve_item.save()
                cves_added.append(cve_item.cveid)
            elif cve_to_add_last_modified > self.cve_item(cveid_to_add).lastModifiedDate:
                cve_item = CveItem(**cve_item_def)
                cve_item.save()
                cves_modified.append(cve_item.cveid)
            else:
                cves_untouched.append(cveid_to_add)
        return cves_added, cves_modified, cves_untouched

    @property
    def cves(self):
        return [cveitem for cveitem in self.data['CVE_Items']]

    def __len__(self):
        return len(self.cves)