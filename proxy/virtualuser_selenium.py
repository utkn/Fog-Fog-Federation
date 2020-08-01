from virtualuser import VirtualUser
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.keys import Keys
import requests
import json

class SeleniumVirtualUser(VirtualUser):
    def __init__(self):
        super()
        self.rp_url = None
        self.driver = None
    
    def perform_login(self, driver, target_url):
        login_url = driver.current_url
        username_elements = driver.find_elements_by_css_selector('input[type="text"]')
        if len(username_elements) < 1:
            return False
        username_elements[0].send_keys(self.username)
        password_elements = driver.find_elements_by_css_selector('input[type="password"]')
        if len(password_elements) < 1:
            return False 
        password_elements[0].send_keys(self.password)
        password_elements[0].submit()
        # now, let's wait for the redirect. if we do not get redirected after 5 seconds,
        # we stop waiting.
        wait = WebDriverWait(driver, 5)
        wait.until(lambda driver: driver.current_url != login_url)
        # we should be redirected back to the consent page if the log in was successful.
        return driver.current_url == target_url
    
    def login(self, rp_url):
        # open the browser.
        if self.driver is None:
            self.driver = webdriver.Firefox()
        self.rp_url = rp_url
        rp_response = requests.get(rp_url, allow_redirects=False)
        consent_url = rp_response.headers['Location']
        # go to the redirected page.
        self.driver.get(consent_url)
        # if we were redirected again to the log in page, try to log in.
        if self.driver.current_url != consent_url:
            return self.perform_login(self.driver, consent_url)
        return True
    
    def give_consent(self):
        self.driver.get(self.rp_url)
        consent_url = self.driver.current_url
        consent_button_elements = self.driver.find_elements_by_name('allow')
        # if there is no consent button, we cannot possibly consent...
        if len(consent_button_elements) < 1:
            return None
        consent_button_elements[0].click()
        # wait until we are redirected away from the consent page
        wait = WebDriverWait(self.driver, 5)
        wait.until(lambda driver: driver.current_url != consent_url)
        self.token = json.loads(self.driver.find_element_by_id('json').text)
        # close the browser as we do not need it any further.
        self.driver.quit()
        self.driver = None
        return self.token
            


