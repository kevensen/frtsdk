from mongoengine import EmbeddedDocument
from mongoengine import EmbeddedDocumentField
from redteam.artifacts import ProductName
from redteam.artifacts import Package

class ProductRelationship(EmbeddedDocument):
    product_name = EmbeddedDocumentField(ProductName)
    package = EmbeddedDocumentField(Package)

    def __init__(self, **data):
        super(ProductRelationship, self).__init__(**data)