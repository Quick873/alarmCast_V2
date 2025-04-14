import requests


def get_alarms(api_url, username, password):
    response = requests.get(api_url, auth=(username, password), verify=false)
    data = response.json
    return data

