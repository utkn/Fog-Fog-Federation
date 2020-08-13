import subprocess
import time

config_file_template = '''ctrl_interface=/tmp/wpa_supplicant
ctrl_interface_group=0
ap_scan=0
network={{
key_mgmt=IEEE8021X
eap=MD5
identity="{username}"
password="{password}"
eapol_flags=0
}}'''

class VirtualSupplicant(object):
    def __init__(self, iface):
        self.username = None
        self.password = None
        self.authenticated = False
    
    # sets the credentials.
    def set_credentials(self, username, password):
        self.username = username
        self.password = password
    
    # resets the stored credentials.
    def reset_credentials(self):
        self.username = None
        self.password = None
        self.authenticated = False
    
    def login(self):
        # first, create the configuration files.
        with open('wpasupplicant/wired-md5.conf', 'w') as configfile:
            configfile.write(config_file_template.format(username=self.username, password=self.password))
        # then, run the authentication procedure.
        cmd = 'wpa_supplicant -dd -c/tmp/wpasupplicant/wired-md5.conf -ieth0 -Dwired'
        proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        try:
            # run the wpa supplicant for 5 seconds.
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            # kill the supplicant.
            proc.kill()
            output, _ = proc.communicate()
            # check the results.
            if 'result=SUCCESS' in str(output):
                self.authenticated = True
                return True
            else:
                return False