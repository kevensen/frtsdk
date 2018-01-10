import re
from datetime import datetime
from mongoengine import Document
from mongoengine import StringField
from mongoengine import DateTimeField
from mongoengine import ListField

CVE_REGEX = re.compile(r'CVE-\d{4}-\d{1,}', re.MULTILINE)
ADVISORY_REGEX = re.compile(r"""(^\s*FEDORA\-.*|^\s*RHSA-.*|^\s*CEBA-.*)
(\d\d\d\d-\d\d-\d\d\s*\d\d:\d\d|\d\d\d\d-\d\d-\d\d)""", re.MULTILINE)
ADVISORY_DATE_REGEX = re.compile(r'^([\d]{4}-[\d]{2}-[\d]{2})[\s\d:\.]*$', re.MULTILINE)
SUMMARY_REGEX = re.compile(r'^Summary\W*(.*)$', re.MULTILINE)
PRODUCT_REGEX = re.compile(r"\s*Product\s*:\s*(.*)", re.MULTILINE)
PACAKGE_NAME_REGEX = re.compile(r"^\s*Name\s*:\s*(.*)", re.MULTILINE)
PACAKGE_VERSION_REGEX = re.compile(r"^\s*Version\s*:\s*(.*)", re.MULTILINE)
PACAKGE_RELEASE_REGEX = re.compile(r"\s*Release\s*:\s*(.*)", re.MULTILINE)
ARCH_REGEX = re.compile(r'(i386|i486|i586|i686|athlon|geode|pentium3|pentium4|x86_64|amd64|ia64|alpha|alphaev5|alphaev56|alphapca56|alphaev6|alphaev67|sparcsparcv8|sparcv9|sparc64|sparc64v|sun4|sun4csun4d|sun4m|sun4u|armv3l|armv4b|armv4larmv5tel|armv5tejl|armv6l|armv7l|mips|mipselppc|ppciseries|ppcpseries|ppc64|ppc8260|ppc8560|ppc32dy4|m68k|m68kmint|atarist|atariste|ataritt|falcon|atariclone|milan|hades|Sgi|rs6000|i370|s390x|s390|noarch)')
BUGZILLA_REGEX = re.compile(r"""(\s*\[ \d \] Bug \#(\d+) - (.+)
\s*(https:\/\/bugzilla\.redhat\.com.*))+?""", re.MULTILINE)

class UpdateAnnounceMessage(Document):
    message_id = StringField(primary_key=True)
    message_date = DateTimeField(required=True)
    summary = StringField()
    advisory_id = StringField(required=True)
    advisory_date = DateTimeField()
    cves = ListField()
    rpmname = StringField()
    rpmversion = StringField()
    rpmrelease = StringField()
    product = StringField()
    
    meta = {'ordering': ['-message_date']}

    def __init__(self, **kwargs):
        super(UpdateAnnounceMessage, self).__init__()
        if not self.message_id:
            try:
                self.message_id = kwargs['message_id']
            except KeyError:
                self.message_id = kwargs['messageId']
        try:
            if isinstance(kwargs['message_date'], datetime):
                self.message_date = kwargs['message_date']
            else:
                simple_date = kwargs['message_date']
                if '+' in simple_date:
                    simple_date = simple_date.split('+')[0].strip()
                elif '-' in simple_date:
                    simple_date = simple_date.split('-')[0].strip()

                self.message_date = datetime.strptime(simple_date, '%a, %d %b %Y %H:%M:%S')
            if 'text' in kwargs.keys():
                self.advisory_id = ADVISORY_REGEX.search(kwargs['text']).group(1)
                self.summary = SUMMARY_REGEX.search(kwargs['text']).group(1)
                self.cves = list(set(CVE_REGEX.findall(kwargs['text'])))


                self.rpmname = PACAKGE_NAME_REGEX.search(kwargs['text']).group(1)
                self.rpmversion = PACAKGE_VERSION_REGEX.search(kwargs['text']).group(1)
                self.rpmrelease = PACAKGE_RELEASE_REGEX.search(kwargs['text']).group(1)

                self.product = PRODUCT_REGEX.search(kwargs['text']).group(1)
                self.advisory_date = datetime.strptime(ADVISORY_DATE_REGEX.search(kwargs['text']).group(1), '%Y-%m-%d')

            else:
                if 'advisory_id' in kwargs.keys():
                    self.advisory_id = kwargs['advisory_id']
                if 'summary' in kwargs.keys():
                    self.summary = kwargs['summary']
                if 'cves' in kwargs.keys():
                    self.cves = kwargs['cves']
                if 'rpmname' in kwargs.keys():
                    self.rpmname = kwargs['rpmname']
                if 'rpmversion' in kwargs.keys():
                    self.rpmversion = kwargs['rpmversion'].replace(" ", "").replace("=","")
                if 'rpmrelease' in kwargs.keys():
                    self.rpmrelease = kwargs['rpmrelease'].replace(" ", "").replace("=","")
                if 'product' in kwargs.keys():
                    self.product = kwargs['product']
                if 'advisory_date' in kwargs.keys():
                    self.advisory_date = kwargs['advisory_date']

        except KeyError:
            pass
            

    @property
    def rpm(self):
        try:
           return '-'.join([self.rpmname, self.rpmversion, self.rpmrelease])
        except TypeError:
            pass
        print self.rpmname
        return ""

    @property
    def product_name(self):
        return ' '.join(self.product.split(' ')[:-1])

    @property
    def product_version(self):
        return self.product.split(' ')[-1]

    @property
    def product_family(self):
        if self.advisory_id.startswith("FEDORA"):
            return "Fedora Linux"
        elif self.advisory_id.startswith("CEBA") or self.advisory_id.startswith("CESA"):
            return "CentOS"
        return "Red Hat Enterprise Linux"

    @property
    def product_reference(self):
        return ''.join([self.product_version, self.product_name]).replace(' ','')

    @property
    def full_product_name(self):
        return ' '.join([self.product_family,
                         '(v.',
                         self.product_version]) + ')'

    @property
    def product_relationship(self):
        return dict(full_product_name=self.rpm + " as a component of " + self.full_product_name,
                    product_reference=self.rpm,
                    relation_type="Default Component Of",
                    relates_to_product_reference=self.product_reference)

    @property
    def version_branch(self):
        return dict(full_product_name=self.rpm + '.src.rpm',
                    type="Product Version",
                    name=self.rpm)

    @property
    def family_branch(self):
        return dict(full_product_name=self.full_product_name,
                    type="Product Name",
                    name=self.full_product_name)

    @property
    def cpe(self):
        if 'Fedora' in self.product:
            cpestring = "cpe:/o:fedoraproject:fedora:" + self.product_version
        return cpestring

    @property
    def advisory_release_date(self):
        return self.advisory_date or self.message_date