import adal
from msrestazure.azure_active_directory import AdalAuthentication
from flask import current_app
from azure.mgmt.dns import DnsManagementClient


def create_dns_client(tenant_id, client, key, subscription_id):
    login_endpoint = 'https://login.microsoftonline.com/'
    resource = 'https://management.core.windows.net/'

    context = adal.AuthenticationContext(login_endpoint + tenant_id)
    credentials = AdalAuthentication(
        context.acquire_token_with_client_credentials,
        resource,
        client,
        key
    )

    current_app.logger.debug("Got Azure credentials: {0}".format(credentials))

    dns_client = DnsManagementClient(
        credentials,
        subscription_id
    )
    return dns_client

def delete_txt_record(change_id, account_number, host, value):
    current_app.logger.debug("Delete record")

def create_txt_record(account_number, host, value):
    current_app.logger.debug("Create record")

def wait_for_r53_change(change_id, client=None):
    current_app.logger.debug("Wait")