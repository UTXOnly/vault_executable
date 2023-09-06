# vault_executable
A python script to serve secrets fetched from HashiCorp Vault  to a Datadog agent

Introduction

Customers can fetch secrets from providers like HashiCorp Vault and serve those secrets to the Datadog agent via executable file. Customers often ask us for support with creating the executable, we do have basic examples of a python executable in our documentation but wanted to take it a step further and provide a simple but working example of a executable that fetches secrets from HashiCorp Vault and serves them to the Datadog agent.

Setup

You will need a HashiCorp Vault secret cluster is necessary to store secrets in the vault.



You can add secrets to the vault using the steps below

![Screen Recording 2023-09-06 at 05 22 35 PM 2](https://github.com/UTXOnly/vault_executable/assets/49233513/45ff1997-ff03-4570-9b53-4fabfd6e8a9c)






Fetching Secrets from the Vault

When you create a HashiCorp Vault cluster with the default settings, you should be greeted with instructions like this on the overview page allowing you to fetch 

![Image 2023-09-06 at 5 10 33 PM](https://github.com/UTXOnly/vault_executable/assets/49233513/ad6f6e17-14b3-4b18-8383-2167f1827857)


The Script
```
#!opt/datadog-agent/embedded/bin/python3
import json
import sys
import requests

secret_id = "<YOUR_SECRET_ID_HERE>"
role_id = "<YOUR_ROLE_ID_HERE>"
VAULT_ADDR= "https://<YOUR_VAULT_ADDRESS_HERE"
VAULT_NAMESPACE = "admin"

def fetch_secrets_from_vault():

    try:
        # Authenticate and get the client token
        response = requests.post(
            url=f"{VAULT_ADDR}/v1/auth/approle/login",
            headers={
                "X-Vault-Namespace": VAULT_NAMESPACE
            },
            json={
                "role_id": role_id,
                "secret_id": secret_id
            }
        )
        response.raise_for_status()
        vault_token = response.json()["auth"]["client_token"]
        
        # Fetch the secret from Vault
        response = requests.get(
            url=f"{VAULT_ADDR}/v1/secret/data/sample-secret",
            headers={
                "X-Vault-Token": vault_token,
                "X-Vault-Namespace": VAULT_NAMESPACE
            }
        )
        response.raise_for_status()
        secret_data = response.json()["data"]["data"]
        return secret_data
    
    except Exception as e:
        print(f"An error occurred while fetching secrets from Vault: {e}")

def retrieve_secrets():

    try:

      secret_request = json.load(sys.stdin)
      secrets = fetch_secrets_from_vault()
  
      secret_response = {}
  
      for secret in secret_request["secrets"]:
          if secret in secrets.keys():
              
              secret_response[secret] = {
                  "value": str(secrets[secret]),
                  "error": None
              }
          else:
              secret_response[secret] = {
                  "value": None,
                  "error": "Unable to retrieve secret."
              }
    except Exception as e:
        print("There was an error retrieving secrets", e)

    sys.stdin.close()
    return secret_response

if __name__ == "__main__" :

    secrets = retrieve_secrets()
    print(json.dumps(secrets))
 ```



Results Returned from Vault

The results are returned in `<KEY>:<VALUE>` pairs like below. You can test massing secret keys as defined in your agent configuration to see what your executable returns (as the agent sees it).
```
❯ bash -c "echo '{\"version\": \"1.0\", \"secrets\": [\"host\", \"test-snmp\"]}' | python3 /Users/brian.hartford/Documents/secrets/hashi_vault_api.py"
api-key: <REDACTED>
first-secret: Vault Is The Way
host: localhost
test-key: test
test-snmp: test-snmp-password
{"host": {"value": "localhost", "error": null}, "test-snmp": {"value": "test-snmp-password", "error": null}}
```
