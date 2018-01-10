from datetime import datetime
from mongoengine import Document
from mongoengine import DictField
from mongoengine import DateTimeField
from mongoengine import StringField


class CveItem(Document):
    cve = DictField(required=True)
    configurations = DictField(required=False)
    impact = DictField(required=False)
    publishedDate = DateTimeField(required=False)
    lastModifiedDate = DateTimeField(required=False)
    cveid = StringField(required=True, primary_key=True)

    def __init__(self, **cve_item_definition):
        super(CveItem, self).__init__()
        self.set_data(**cve_item_definition)

    def set_data(self, **cve_item_definition):
        self.cve = cve_item_definition['cve']

        if not self.cveid:
            self.cveid = self.cve['CVE_data_meta']['ID']

        try:
            self.configurations = cve_item_definition['configurations']
        except KeyError:
            pass

        try:
            self.impact = cve_item_definition['impact']
        except KeyError:
            pass

        try:
            if isinstance(cve_item_definition['publishedDate'], datetime):
                self.publishedDate = cve_item_definition['publishedDate']
            else:
                self.publishedDate = datetime.strptime(cve_item_definition['publishedDate'], '%Y-%m-%dT%H:%MZ')
                
        except KeyError:
            pass

        try:
            if isinstance(cve_item_definition['lastModifiedDate'], datetime):
                self.lastModifiedDate = cve_item_definition['lastModifiedDate']
            else:
                self.lastModifiedDate = datetime.strptime(cve_item_definition['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')
        except KeyError:
            pass

        
    @property
    def cvss3vector(self):
        try:
            return self.impact['baseMetricV3']['cvssV3']['vectorString']
        except KeyError:
            pass
        return ""

    @property
    def cvss3score(self):
        try:
            return self.impact['baseMetricV3']['cvssV3']['baseScore']
        except KeyError:
            pass
        return ""

    @property
    def cvss3severity(self):
        try:
            return self.impact['baseMetricV3']['cvssV3']['baseSeverity']
        except KeyError:
            pass
        return ""

    @property
    def cwe(self):
        try:
            return self.cve['problemtype']['problemtype_data'][0]['description'][0]['value']
        except (KeyError, IndexError):
            pass
        return ""

    @property
    def description(self):
        try:
            return self.cve['description']['description_data']['value']
        except KeyError:
            pass
        return ""

    @property
    def references(self):
        return self.cve['references']['reference_data']


        

        