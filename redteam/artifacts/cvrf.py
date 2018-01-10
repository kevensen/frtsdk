
from datetime import datetime
from mongoengine import Document
from mongoengine import StringField
from mongoengine import DateTimeField
from mongoengine import ListField
from mongoengine import ReferenceField
from mongoengine import EmbeddedDocumentListField
from redteam.sources.update_announce_message import UpdateAnnounceMessage
from redteam.artifacts import ProductName
from redteam.artifacts import Package
from redteam.artifacts import ProductRelationship
from redteam.artifacts import Bugzilla

SEVERITIES = dict(LOW=1, MEDIUM=2, MODERATE=2, HIGH=3, CRITICAL=4, NONE=0)

class CVRF(Document):
    advisory_id = StringField(required=True, primary_key=True)
    summary = StringField()
    messages = ListField(ReferenceField(UpdateAnnounceMessage))
    cves = ListField()
    product_names = EmbeddedDocumentListField(ProductName)
    packages = EmbeddedDocumentListField(Package)
    relationships = EmbeddedDocumentListField(ProductRelationship)
    bugzillas = EmbeddedDocumentListField(Bugzilla)
    advisory_date = DateTimeField()

    def __init__(self, **kwargs):
        super(CVRF, self).__init__(**kwargs)

    @classmethod
    def advisory_ids_for_rpm(cls, package_name=None, package_version=None, package_release=None):
        code = """
        function() {
            var doc_list = [];
            db[collection].find(query).forEach(function(doc) {
                var packages = doc[~packages];
                if (typeof packages !== 'undefined') {
                    packages.forEach(function(package) {
                        if (package.name === options.package_name) {
                            if (options.package_version === null) {
                                doc_list.push(doc._id);
                            } else {
                                var ver1_pieces = options.package_version.split(".");
                                var ver2_pieces = package.version.split(".");
                                if ((ver1_pieces.length == 1.0) && (ver1_pieces[0] < ver2_pieces[0])) {
                                    doc_list.push(doc._id);
                                } else if (ver1_pieces.length === 2.0) {
                                    if (ver1_pieces[0] < ver2_pieces[0]) {
                                        doc_list.push(doc._id);
                                    } else if ((ver1_pieces[0] == ver2_pieces[0]) && (ver1_pieces[1] < ver2_pieces[1])) {
                                        doc_list.push(doc._id);
                                    }
                                } else if (ver1_pieces.length === 3.0) {
                                    if (ver1_pieces[0] < ver2_pieces[0]) {
                                        doc_list.push(doc._id);
                                    } else if ((ver1_pieces[0] == ver2_pieces[0]) && (ver1_pieces[1] < ver2_pieces[1])) {
                                        doc_list.push(doc._id);
                                    } else if ((ver1_pieces[0] == ver2_pieces[0]) && (ver1_pieces[1] == ver2_pieces[1]) && (ver1_pieces[2] < ver2_pieces[2])) {
                                        doc_list.push(doc._id);
                                    }
                                }
                            }
                        }
                    });
                }
            });
            return doc_list;
        }
        """
        options = {'package_name': package_name,
                   'package_version': package_version,
                   'package_release': package_release}
        return list(set(cls.objects.exec_js(code, **options)))
        

