import time 

import boto3
import pytest

from .user import User

ssm_client = boto3.client("ssm")


#Assuming client and user pool ids are stored in SSM
@pytest.fixture(scope="module")
def client_id():
    id = ssm_client.get_parameter(Name="PATH_TO_YOUR_CLIENT_ID", WithDecryption=True)["Parameter"]["Value"]
    return id 
@pytest.fixture(scope="module")
def up_id():
    id = ssm_client.get_parameter(Name="PATH_TO_YOUR_CLIENT_ID", WithDecryption=True)["Parameter"]["Value"]
    return up_id 

#creates a user with no group and deletes them as part of cleanup
@pytest.fixture(scope="module")
def user_nogroup(up_id,client_id):
    user = User(up_id,client_id)
    yield user
    user.delete_user()

#Generates the header to be included in calls to aws with cognito user
@pytest.fixture(scope="module")
def user_nogroup_header(user_nogroup:User):
    time.sleep(30)
     
    return {
        "Accept": "application/json",
        "Authorization": f'Bearer {user_nogroup.get_token()}',
    }


#Generates a user and adds them to admin group, assuming it already exists. user is deleted after pytest completes
@pytest.fixture(scope="module")
def user_admin(idp_id,client_id):
    user = User(idp_id,client_id)
    user.add_to_group("admingroup")
    yield user
    user.delete_user

@pytest.fixture(scope="module")
def user_admin_header(user_admin:User):
    time.sleep(30)
     
    return {
        "Accept": "application/json",
        "Authorization": f'Bearer {user_admin.get_token()}',
    }