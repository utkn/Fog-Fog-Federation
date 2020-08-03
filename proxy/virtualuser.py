import requests
import json
import time

from bs4 import BeautifulSoup
from flask import jsonify

# creates a session to (1) connect to vRP (2) login through idP and (3) give consent on behalf of the user.
class VirtualUser(object):
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.waiting_consent_page = None
        self.token = None
    
    # sets the credentials.
    def set_credentials(self, username, password):
        self.username = username
        self.password = password
    
    # resets the stored credentials.
    def reset_credentials(self):
        self.username = None
        self.password = None

    # returns whether the login was successful or not.
    def login(self, rp_url):
        # connect to the vRP
        rp_response = self.session.get(rp_url, allow_redirects=False)
        consent_url = rp_response.headers['Location']
        consent_response = self.session.get(consent_url)
        # try to login with the given credentials if we were redirected to the login page.
        if consent_response.url != consent_url:
            login_page_url = consent_response.url
            login_response = consent_response
            login_response_parsed = BeautifulSoup(login_response.text)
            # scrap the additional info from the login page to bypass CSRF checks
            csrf_token = login_response_parsed.find('input', {'name': 'csrfmiddlewaretoken'})['value']
            nxt = login_response_parsed.find('input', {'name': 'next'})['value']
            # after submitting the form, we should be redirected to the consent page
            consent_response = self.session.post(login_page_url, data={
                'csrfmiddlewaretoken': csrf_token, 
                'next': nxt,
                'username': self.username, 
                'password': self.password}, headers={'referer': login_page_url})
            print("LOGIN PAGE URL: ", login_page_url)
            print("CONSENT PAGE URL: ", consent_response.url)
            # if we were not redirected away from the login page, login was unsuccessful
            if consent_response.url == login_page_url:
                return False
        self.waiting_consent_page = consent_response
        return True

    # returns the id token.
    def give_consent(self):
        # if the consent page was not received by the vUser yet, return none
        if self.waiting_consent_page is None:
            return None
        # now, we should give consent on behalf of the user
        consent_response_parsed = BeautifulSoup(self.waiting_consent_page.text)
        consent_url = self.waiting_consent_page.url
        # first, get the OIDC parameters to be POSTed
        redirect_uri = consent_response_parsed.find('input', {'name': 'redirect_uri'})['value']
        client_id = consent_response_parsed.find('input', {'name': 'client_id'})['value']
        response_type = consent_response_parsed.find('input', {'name': 'response_type'})['value']
        scope = consent_response_parsed.find('input', {'name': 'scope'})['value']
        state = consent_response_parsed.find('input', {'name': 'state'})['value']
        nonce = consent_response_parsed.find('input', {'name': 'nonce'})['value']
        # then, scrap the page for additional info to bypass CSRF checks
        csrf_token = consent_response_parsed.find('input', {'name': 'csrfmiddlewaretoken'})['value']
        authorize_response = self.session.post(consent_url, data={
            'allow': 'Accept',
            'csrfmiddlewaretoken': csrf_token,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': response_type,
            'scope': scope,
            'state': state,
            'nonce': nonce}, headers={'referer': consent_url})
        print(authorize_response.text)
        self.token = json.loads(authorize_response.text)
        # return the token
        return self.token

            