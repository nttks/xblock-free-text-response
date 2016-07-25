import json
import unittest

from ..models import TestAssociation
from .oauth import OAuth2Test
from .open_id import OpenIdConnectTestMixin


class DAccountOpenIdConnectTest(OpenIdConnectTestMixin, OAuth2Test):
    backend_path = 'social.backends.daccount.DAccountOpenIdConnect'
    expected_username = 'foo'
    user_data_url = 'https://conf.uw.docomo.ne.jp/userinfo'
    user_data_body = json.dumps({
        'email': 'foo@example.com',
    })

    def access_token_body(self, request, _url, headers):
        """
        Get the nonce from the request parameters, add it to the id_token, and
        return the complete response.
        """
        # get nonce generated at authorization
        nonce = filter(
            lambda x: x.server_url == self.backend.authorization_url(),
            TestAssociation.cache.values()
        )[0].handle
        body = self.prepare_access_token_body(nonce=nonce)
        return 200, headers, body

    @unittest.skip('Not verified until daccount fix signature')
    def test_invalid_secret(self):
        pass

    @unittest.skip('Not verified until daccount fix signature')
    def test_expired_signature(self):
        pass

    @unittest.skip('Not verified until daccount fix signature')
    def test_invalid_issuer(self):
        pass

    @unittest.skip('Not verified until daccount fix signature')
    def test_invalid_audience(self):
        pass

    def test_login(self):
        user = self.do_login()
        user_data = json.loads(self.user_data_body)
        self.assertEqual(user_data['email'], user.email)
