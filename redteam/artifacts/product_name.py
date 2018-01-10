from mongoengine import EmbeddedDocument
from mongoengine import StringField
class ProductName(EmbeddedDocument):
    name = StringField(required=True, unique=True)

    def __init__(self, **data):
        super(ProductName, self).__init__(**data)

    @property
    def version_number(self):
        return self.name.split(" ")[-1]

    @property
    def product_simple_name(self):
        return self.name.split(" ")[:-1]

    @property
    def full_product_name(self):
        return " ".join([self.product_simple_name,
                         '(v. ',
                         self.version_number,
                         ')'])

    @property
    def summary(self):
        return dict(full_product_name=self.full_product_name,
                    type="Product Name",
                    product_name=self.full_product_name)


