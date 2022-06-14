from random import choice
from string import  ascii_letters, digits
import re

import boto3,pyotp

cognito_client = boto3.client("cognito-idp")


def generate_password()->str:
    """Generates a random 25 character string assuming some basic requirements for the password"""
    tmp = ''.join(choice(ascii_letters+digits+"%&.!-") for _ in range(25))
    #catching the unlikely but possible edge case where generated password does not contain one of the required values
    if(re.search(r"\d",tmp) and re.search(r"[a-zA-Z]",tmp) and re.search(r"[%&.!-]",tmp)):
        return tmp
    return generate_password()


class User:
    """Base User Class that handles user creation and aws interaction"""
    def __init__(self,up_id, client_id) -> None:
        """neews to know the user pool id for user creation and the client id of the app being tested for init auth"""
        self.username = "testuser+"+''.join(choice(ascii_letters+digits) for _ in range(5))+"@test.com"
        self.password = generate_password()
        
        self.up_id = up_id
        self.client_id = client_id
        
        self.mfa = None
        self.friendly_device_name = None
        
        #in the true spirit of fixtures, it might make more sense to do these in two different fixtures. This would ensure that
        #the user is deleted even if the password rotation or mfa association fails
        self._create_user()
        self._rotate_password_and_assoc_mfa()
        
    def add_mfa(self, aws_secret:str)->None:
        """Adds an MFA based on the encoded string provided by aws as part of the flow"""
        self.mfa = pyotp.TOTP(aws_secret)
        self.friendly_device_name = "".join(choice(ascii_letters) for _ in range(10))
    def get_mfa_code(self)->str:
        """
        Returns the mfa code for the current time
        NOTE: Using this code more than once will cause an error. This example adds 30 sec wait to ensure this doesn't happen
        """
        if(self.mfa):
            return self.mfa.now()
                
        else:
            raise ValueError("Trying to get MFA code, but MFA has not been configured yet")
    
    def _create_user(self):
        """Abstracts aws call to initially create user with temporary credentials"""
        response = cognito_client.admin_create_user(
            UserPoolId=self.up_id,
            Username=self.username,
            UserAttributes=[{"Name": "email", "Value": self.username}],
            TemporaryPassword=self.password,
            MessageAction='SUPPRESS')
    
    def delete_user(self):
        """Deletes user from AWS should be called in fixture as part of cleanup"""
        response = cognito_client.admin_delete_user(
            UserPoolId=self.up_id,
            Username=self.username
            )
    
    def _rotate_password_and_assoc_mfa(self):
        """Initiates a user's log in with the temp/current password, chamges it and associates mfa to the user"""
        
        #Rotating the password
        result = cognito_client.admin_initiate_auth(
            UserPoolId=self.up_id,
            ClientId=self.client_id,
            AuthFlow="ADMIN_NO_SRP_AUTH",
            AuthParameters={"USERNAME": self.username, "PASSWORD": self.password},
        )

        self.password = generate_password()
        
        result = cognito_client.respond_to_auth_challenge(
            Session=result["Session"],
            ClientId=self.client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            ChallengeResponses={"USERNAME": self.username, "NEW_PASSWORD": self.password},
        )

        #MFA association flow with verification of generated token
        result = cognito_client.associate_software_token(Session=result["Session"])
        self.add_mfa(result["SecretCode"])
        result = cognito_client.verify_software_token(Session=result["Session"],UserCode= self.get_mfa_code(),FriendlyDeviceName=self.friendly_device_name)
    
    def get_token(self)->str:
        """Get access token to be used in future calls on behalf of user"""
        #initiate login
        result = cognito_client.admin_initiate_auth(
            UserPoolId=self.up_id,
            ClientId=self.client_id,
            AuthFlow="ADMIN_NO_SRP_AUTH",
            AuthParameters={"USERNAME": self.username, "PASSWORD": self.password},
        )
        #respond to challenge with mfa code
        #NOTE, for the purposes of demo, we are not verifying that this was the actual challenge received. We just assume it was
        result = cognito_client.respond_to_auth_challenge(
            Session=result["Session"],
            ClientId=self.client_id,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            ChallengeResponses={"USERNAME": self.username, "SOFTWARE_TOKEN_MFA_CODE":  self.get_mfa_code()},
        )
        return result["AuthenticationResult"]["AccessToken"]

    def add_to_group(self,group:str)->None:
        """Adds user to cognito group assuming said group exists"""
        cognito_client.admin_add_user_to_group(
            UserPoolId=self.up_id, Username=self.username, GroupName=group
        )
