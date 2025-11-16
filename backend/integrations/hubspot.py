import datetime
import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
from dotenv import load_dotenv
import os

import requests
from integrations.integration_item import IntegrationItem

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

# Load environment variables
load_dotenv()

# HubSpot OAuth credentials - loaded from .env file
CLIENT_ID = os.getenv('HUBSPOT_CLIENT_ID', 'XXX')
CLIENT_SECRET = os.getenv('HUBSPOT_CLIENT_SECRET', 'XXX')
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
SCOPES = 'crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read'

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    auth_url = f'https://app.hubapi.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPES}&state={encoded_state}'
    
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)

    return auth_url

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        )

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

def create_integration_item_metadata_object(response_json: dict, item_type: str) -> IntegrationItem:
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', None),
        name=response_json.get('properties', {}).get('hs_object_id', response_json.get('id', 'Unknown')),
        type=item_type,
    )
    return integration_item_metadata

async def get_items_hubspot(credentials) -> list[IntegrationItem]:
    credentials = json.loads(credentials)
    access_token = credentials.get('access_token')
    
    if not access_token:
        raise HTTPException(status_code=400, detail='No access token found in credentials.')

    list_of_integration_item_metadata = []
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }

    # Fetch contacts
    try:
        contacts_response = requests.get(
            'https://api.hubapi.com/crm/v3/objects/contacts',
            headers=headers,
            params={'limit': 100}
        )
        if contacts_response.status_code == 200:
            contacts_data = contacts_response.json()
            for contact in contacts_data.get('results', []):
                list_of_integration_item_metadata.append(
                    create_integration_item_metadata_object(contact, 'Contact')
                )
    except Exception as e:
        print(f'Error fetching contacts: {e}')

    # Fetch companies
    try:
        companies_response = requests.get(
            'https://api.hubapi.com/crm/v3/objects/companies',
            headers=headers,
            params={'limit': 100}
        )
        if companies_response.status_code == 200:
            companies_data = companies_response.json()
            for company in companies_data.get('results', []):
                list_of_integration_item_metadata.append(
                    create_integration_item_metadata_object(company, 'Company')
                )
    except Exception as e:
        print(f'Error fetching companies: {e}')

    # Fetch deals
    try:
        deals_response = requests.get(
            'https://api.hubapi.com/crm/v3/objects/deals',
            headers=headers,
            params={'limit': 100}
        )
        if deals_response.status_code == 200:
            deals_data = deals_response.json()
            for deal in deals_data.get('results', []):
                list_of_integration_item_metadata.append(
                    create_integration_item_metadata_object(deal, 'Deal')
                )
    except Exception as e:
        print(f'Error fetching deals: {e}')

    print(f'list_of_integration_item_metadata: {list_of_integration_item_metadata}')
    return list_of_integration_item_metadata