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


def find_zone(client, resource_group, domain):
    paginator = client.zones.list_by_resource_group(resource_group)
    for dns_zone in paginator:
        if domain.endswith(dns_zone.name):
            return dns_zone
    return None

def delete_txt_record(client, resource_group, host):
    current_app.logger.debug("Delete record")
    dns_zone = find_zone(client, resource_group, host)
    if dns_zone is None:
        raise ValueError(
            "Unable to find a Azure DNS hosted zone for {}".format(host)
        )
    relative_name = host.replace(dns_zone.name + ".", "")
    client.record_sets.delete(resource_group, dns_zone.name, relative_name, "TXT")

def create_txt_record(client, resource_group, host, value):
    current_app.logger.debug("Create record for {0}".format(host))
    dns_zone = find_zone(client, resource_group, host)
    if dns_zone is None:
        raise ValueError(
            "Unable to find a Azure DNS hosted zone for {}".format(host)
        )
    relative_name = host.replace(dns_zone.name + ".", "")
    record = client.record_sets.create_or_update(resource_group, dns_zone.name, relative_name, "TXT", {
        "ttl": 300,
        "txt_records": [
            {
                "value": value
            }
        ]
    })
    return record.name
