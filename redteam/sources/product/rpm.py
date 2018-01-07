from cpe import CPE

class Rpm(object):

    def __init__(self, name, version, release, arch):
        self.name = name
        self.version = version


        self.release = release
        self.arch = arch

        if '.' in self.version:
            version_pieces = self.version.split('.')
            try:
                self.major = int(version_pieces[0])
            except ValueError:
                self.major = version_pieces[0]
            try:
                self.minor = int(version_pieces[1])
            except ValueError:
                self.minor = version_pieces[1]
            if len(version_pieces) == 3:
                try:
                    self.micro = int(version_pieces[2])
                except ValueError:
                    self.micro = version_pieces[2]
        else:
            self.major = self.version

        if '.' in self.release:
            release_pieces = self.release.split('.')
            try:
                self.update = int(release_pieces[0])
            except ValueError:
                self.update = release_pieces[0]

            self.target_sw = release_pieces[1]

        self.target_hw = self.arch

        self.full_name = self.name + '-' + self.version + '-' + self.release + '.' + self.arch

    def cpe(self):
        cpe_string = ['cpe']
        cpe_string.append('2.3')
        cpe_string.append('a')
        cpe_string.append('*')
        cpe_string.append(self.name())
        cpe_string.append(self.version())
        cpe_fs = ":".join(cpe_string) + ":*:*:*:*:*:*:*"
        return CPE(cpe_fs, CPE.VERSION_2_3)

    def version_less_than(self, other_rpm):
        if not isinstance(other_rpm, Rpm):
            return False
        if self.name == other_rpm.name:
            if self.major < other_rpm.major:
                return True
            elif self.major == other_rpm.major and self.minor < other_rpm.minor:
                return True
            elif self.major == other_rpm.major and self.minor == other_rpm.minor and self.micro < other_rpm.micro:
                return True
            elif self.major == other_rpm.major and self.minor == other_rpm.minor and self.micro == other_rpm.micro and self.update < other_rpm.update:
                return True
        return False

    def version_greater_than(self, other_rpm):
        if not isinstance(other_rpm, Rpm):
            return False
        if self.name == other_rpm.name:
            if self.major > other_rpm.major:
                return True
            elif self.major == other_rpm.major and self.minor > other_rpm.minor:
                return True
            elif self.major == other_rpm.major and self.minor == other_rpm.minor and self.micro > other_rpm.micro:
                return True
            elif self.major == other_rpm.major and self.minor == other_rpm.minor and self.micro == other_rpm.micro and self.update > other_rpm.update:
                return True
        return False