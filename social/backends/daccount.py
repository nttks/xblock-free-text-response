"""
Docomo d-account, OpenID Connect
"""
from calendar import timegm
import datetime
from jwt import InvalidTokenError, decode as jwt_decode
from requests.auth import HTTPBasicAuth

from .open_id import OpenIdConnectAuth, OpenIdConnectAssociation
from ..exceptions import AuthTokenError


class DAccountOpenIdConnect(OpenIdConnectAuth):
    name = 'd-account'
    AUTHORIZATION_URL = 'https://id.smt.docomo.ne.jp/cgi8/oidc/authorize'
    ACCESS_TOKEN_URL = 'https://conf.uw.docomo.ne.jp/token'
    USERINFO_URL = 'https://conf.uw.docomo.ne.jp/userinfo'
    ACCESS_TOKEN_METHOD = 'POST'
    DEFAULT_SCOPE = ['openid', 'profile1']
    RESPONSE_TYPE = 'code'
    REDIRECT_STATE = False
    ID_TOKEN_ISSUER = 'https://conf.uw.docomo.ne.jp/'
    ID_KEY = 'sub'

    def auth_complete_params(self, state=None):
        # client_id and client_secret will set in the HTTP Header
        return {
            'grant_type': 'authorization_code',
            'code': self.data.get('code', ''),
            'redirect_uri': self.get_redirect_uri(state),
        }

    def get_and_store_nonce(self, url, state):
        """Inherit in order to change the length of the nonce"""
        # Create a nonce
        nonce = self.strategy.random_string(60)
        # Store the nonce
        association = OpenIdConnectAssociation(nonce, assoc_type=state)
        self.strategy.storage.association.store(url, association)
        return nonce

    def get_nonce(self, nonce):
        """Inherit because we shold use AUTHORIZATION_URL, not ACCESS_TOKEN_URL"""
        try:
            return self.strategy.storage.association.get(
                server_url=self.AUTHORIZATION_URL,
                handle=nonce
            )[0]
        except IndexError:
            pass

    def validate_and_return_id_token(self, id_token):
        """
        Validates the id_token according to the steps at
        http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation.
        """
        client_id, client_secret = self.get_key_and_secret()
        try:
            # Decode the JWT and raise an error if the secret is invalid or
            # the response has expired.
            # TODO not verify until d-account fix signature
            id_token = jwt_decode(id_token, client_secret, audience=client_id,
                                  issuer=self.ID_TOKEN_ISSUER,
                                  verify=False)
        except InvalidTokenError as err:
            raise AuthTokenError(self, err)

        # Verify the token was issued in the last 10 minutes
        utc_timestamp = timegm(datetime.datetime.utcnow().utctimetuple())
        if id_token['iat'] < (utc_timestamp - 600):
            raise AuthTokenError(self, 'Incorrect id_token: iat')

        # Validate the nonce to ensure the request was not modified
        nonce = id_token.get('nonce')
        if not nonce:
            raise AuthTokenError(self, 'Incorrect id_token: nonce')

        nonce_obj = self.get_nonce(nonce)
        if nonce_obj:
            self.remove_nonce(nonce_obj.id)
        else:
            raise AuthTokenError(self, 'Incorrect id_token: nonce')
        return id_token

    def request_access_token(self, *args, **kwargs):
        kwargs['auth'] = HTTPBasicAuth(*self.get_key_and_secret())
        return super(DAccountOpenIdConnect, self).request_access_token(*args, **kwargs)

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service."""
        return self.get_json(
            self.USERINFO_URL,
            headers={'Authorization': 'Bearer {0}'.format(access_token)}
        )

    def get_user_details(self, response):
        """Return user details from d-account API account"""
        email = response.get('email', '')
        fullname, first_name, last_name = self.get_user_names(
            response.get('name', ''),
            response.get('given_name', ''),
            response.get('family_name', '')
        )
        return {
            'username': email.split('@', 1)[0],
            'email': email,
            'fullname': fullname,
            'first_name': first_name,
            'last_name': last_name,
        }
