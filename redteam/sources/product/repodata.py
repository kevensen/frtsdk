import re
try:
    from xml.etree import cElementTree as ElementTree
except ImportError:
    from xml.etree import ElementTree
from redteamcore import Resource
from redteam.sources.product import Rpm

class RepoData(Resource):
    def __init__(self, location, **kwargs):
        super(RepoData, self).__init__(location, **kwargs)
        self.xml = b""
        self.packages = dict()

    def _parse(self):
        self.xml = ElementTree.fromstring(self.data)
        rpm_predicate = ".//*[@type=\'rpm\']"

        if "{" in self.xml.tag:
            namespace = re.findall(r'({.*})', self.xml.tag)[0]

        for package_element in self.xml.findall(rpm_predicate):
            name_predicate = './/' + namespace + 'name'
            version_predicate = './/' + namespace + 'version'
            arch_predicate = './/' + namespace + 'arch'
            name = package_element.findall(name_predicate)[0].text
            arch = package_element.findall(arch_predicate)[0].text

            version = package_element.findall(version_predicate)[0]
            ver = version.get('ver')
            rel = version.get('rel')
            new_rpm = Rpm(name, ver, rel, arch)
            self.packages[new_rpm.full_name] = new_rpm

    def list_packages(self, name=""):
        if not self.xml:
            self._parse()
        if not name:
            return self.packages

        return {rpm.full_name: rpm for fullname, rpm in self.packages.iteritems() if name in fullname}

    @property
    def rpms(self):
        rpmxml = ElementTree.fromstring(self.data)
        rpm_predicate = ".//*[@type=\'rpm\']"

        if "{" in rpmxml.tag:
            namespace = re.findall(r'({.*})', rpmxml.tag)[0]

        for package_element in rpmxml.findall(rpm_predicate):
            name_predicate = './/' + namespace + 'name'
            version_predicate = './/' + namespace + 'version'
            arch_predicate = './/' + namespace + 'arch'
            name = package_element.findall(name_predicate)[0].text
            arch = package_element.findall(arch_predicate)[0].text

            version = package_element.findall(version_predicate)[0]
            ver = version.get('ver')
            rel = version.get('rel')
            yield Rpm(name, ver, rel, arch)

if __name__ == "__main__":


    repomd = RepoData('http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/24/Server/source/tree/repodata/b87a68126a8506600883daac917fb9ab0e4bf614c563507149f38674ba0c668a-primary.xml.gz')

    for rpm in repomd.rpms:
        print rpm.full_name