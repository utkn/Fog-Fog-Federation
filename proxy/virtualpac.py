from lxml import etree
import subprocess
import time
import signal

class VirtualPaC(object):
    def __init__(self):
        self.username = None
        self.password = None
        self.authenticated = False
        self.endpoint = None
    
    # sets the credentials.
    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    # sets the endpoint
    def set_endpoint(self, endpoint):
        self.endpoint = endpoint
    
    # resets the stored credentials.
    def reset_credentials(self):
        self.username = None
        self.password = None
        self.authenticated = False
    
    def login(self):
        config_root = etree.parse('/etc/openpana/config.xml')
        username_node = config_root.xpath('/CONFIG/PAC/USER')
        password_node = config_root.xpath('/CONFIG/PAC/PASSWORD')
        endpoint_node = config_root.xpath('/CONFIG/PAC/IP_PAA')
        username_node[0].text = self.username
        password_node[0].text = self.password
        endpoint_node[0].text = self.endpoint
        etree.ElementTree(config_root.getroot()).write('/etc/openpana/config.xml', pretty_print=True)
        p = subprocess.Popen(['openpac'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        time.sleep(5)
        p.send_signal(signal.SIGINT)
        for line in p.stdout:
            if "EAP: Received EAP-Success" in line:
                self.authenticated = True
                break
        p.kill()
        return self.authenticated