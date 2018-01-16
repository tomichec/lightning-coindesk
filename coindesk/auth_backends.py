from coindesk import rpc_pb2 as ln, rpc_pb2_grpc as lnrpc
from coindesk.models import Profile
from django.conf import settings
from django.contrib.auth.models import User

import grpc

import os


class SignatureBackend(object):

    def authenticate(self, request, signature, csrf_token, username=None):

        os.environ["GRPC_SSL_CIPHER_SUITES"] = "HIGH+ECDSA"
        
        cert = open('/home/tom/.lnd/tls.cert').read()
        creds = grpc.ssl_channel_credentials(cert)
        channel = grpc.secure_channel('localhost:10002', creds)
        # Create a new 'stub' object that will allow us to interact with our "Bob" lnd node.
        stub = lnrpc.LightningStub(channel)

        # channel = grpc.insecure_channel(settings.LND_RPCHOST)
        # stub = lnrpc.LightningStub(channel)

        verifymessage_resp = stub.VerifyMessage(ln.VerifyMessageRequest(msg=csrf_token, signature=signature))

        if not verifymessage_resp.valid:
            print "Invalid signature"
            return None

        pubkey = verifymessage_resp.pubkey
        # Try fetching an existing profile
        try:
            profile = Profile.objects.get(identity_pubkey=pubkey)
            return profile.user
        except Profile.DoesNotExist:
            # Create a new profile if they provided a username
            if len(username) > 3 and len(username) < 36:
                user = User(username=username)
                user.save()
                profile, created = Profile.objects.get_or_create(
                    user=user,
                    identity_pubkey=pubkey)
                assert created is True
                # TODO Auth them in
            else:
                raise Exception("No username provided")
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
