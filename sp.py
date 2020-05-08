#!/usr/bin/env python3
from flask import Flask, url_for, request

from signxml import XMLVerifier

from flask_saml2.sp.idphandler import IdPHandler
from flask_saml2.sp.parser import ResponseParser
from flask_saml2.sp import ServiceProvider
from flask_saml2.utils import certificate_from_file, private_key_from_file

CERTIFICATE = certificate_from_file('sp.crt')
PRIVATE_KEY = private_key_from_file('saml.key')
PORT = 7000


class ExampleServiceProvider(ServiceProvider):
    def get_logout_return_url(self):
        return url_for('index', _external=True)

    def get_default_login_return_url(self):
        return url_for('index', _external=True)


sp = ExampleServiceProvider()

app = Flask(__name__)
app.debug = True
app.secret_key = 'not a secret'

app.config['SERVER_NAME'] = f'localhost:{port}'
app.config['SAML2_SP'] = {
    'certificate': CERTIFICATE,
    'private_key': PRIVATE_KEY,
}

IDP_CERTIFICATE = certificate_from_file('idp.crt')


class X509IdPHandler(IdPHandler):
    def get_response_parser(self, saml_response):
        return X509XmlParser(
            self.decode_saml_string(saml_response),
            certificate=self.certificate
        )


class X509XmlParser(ResponseParser):

    def parse_signed(self, xml_tree, certificate):
        """
        Passes ignore_ambiguous_key_info=True to ignore KeyValue and validate using X509Data only.
        """
        return XMLVerifier().verify(xml_tree, x509_cert=certificate, ignore_ambiguous_key_info=True).signed_xml


app.config['SAML2_IDENTITY_PROVIDERS'] = [
    {
        'CLASS': 'sp.X509IdPHandler',
        'OPTIONS': {
            'display_name': 'keycloak',
            'entity_id': 'http://localhost:8080/auth/realms/master',
            'sso_url': 'http://localhost:8080/auth/realms/master/protocol/saml',
            'slo_url': 'http://localhost:8080/auth/realms/master/protocol/saml',
            'certificate': IDP_CERTIFICATE,
        },
    },
]


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        sp.logout()

    if sp.is_user_logged_in():
        auth_data = sp.get_auth_data_in_session()

        message = f'''
        <p>You are logged in as <strong>{auth_data.nameid}</strong>.
        The IdP sent back the following attributes:<p>
        '''

        attrs = '<dl>{}</dl>'.format(''.join(
            f'<dt>{attr}</dt><dd>{value}</dd>'
            for attr, value in auth_data.attributes.items()))

        logout_url = url_for('flask_saml2_sp.logout')
        logout = f'<form action="/" method="POST"><input type="submit" value="Log out"></form>'

        return message + attrs + logout
    else:
        message = '<p>You are logged out.</p>'

        login_url = url_for('flask_saml2_sp.login')
        link = f'<p><a href="{login_url}">Log in to continue</a></p>'

        return message + link


app.register_blueprint(sp.create_blueprint(), url_prefix='/saml/')


if __name__ == '__main__':
    app.run(port=port)
