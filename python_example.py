import urllib
import base64
import json
import time
import binascii
import os
from hashlib import sha1
import hmac

class Looker:
  def __init__(self, host, secret):
    self.secret = secret
    self.host = host


class User:
  def __init__(self, id=id, first_name=None, last_name=None,
               permissions=[], models=[], group_ids=[], access_filters={}):
    self.external_user_id = json.dumps(id)
    self.first_name = json.dumps(first_name)
    self.last_name = json.dumps(last_name)
    self.permissions = json.dumps(permissions)
    self.models = json.dumps(models)
    self.access_filters = json.dumps(access_filters)
    self.group_ids = json.dumps(group_ids)


class URL:
  def __init__(self, looker, user, session_length, embed_url, force_logout_login=False):
    self.looker = looker
    self.user = user
    self.path = '/login/embed/' + urllib.quote_plus(embed_url)
    self.session_length = json.dumps(session_length)
    self.force_logout_login = json.dumps(force_logout_login)

  def set_time(self):
    self.time = json.dumps(int(time.time()))

  def set_nonce(self):
    self.nonce = json.dumps(binascii.hexlify(os.urandom(16)))

  def sign(self):
    string_to_sign = ""
    string_to_sign = string_to_sign + self.looker.host           + "\n"
    string_to_sign = string_to_sign + self.path                  + "\n"
    string_to_sign = string_to_sign + self.nonce                 + "\n"
    string_to_sign = string_to_sign + self.time                  + "\n"
    string_to_sign = string_to_sign + self.session_length        + "\n"
    string_to_sign = string_to_sign + self.user.external_user_id + "\n"
    string_to_sign = string_to_sign + self.user.permissions      + "\n"
    string_to_sign = string_to_sign + self.user.models           + "\n"
    string_to_sign = string_to_sign + self.user.group_ids        + "\n"
    string_to_sign = string_to_sign + self.user.access_filters

    signer = hmac.new(self.looker.secret, string_to_sign.encode('utf8'), sha1)
    self.signature = base64.b64encode(signer.digest().rstrip('\n'))

  def to_string(self):
    self.set_time()
    self.set_nonce()
    self.sign()

    params = {'nonce':               self.nonce,
              'time':                self.time,
              'session_length':      self.session_length,
              'external_user_id':    self.user.external_user_id,
              'permissions':         self.user.permissions,
              'models':              self.user.models,
              'group_ids':           self.user.group_ids,
              'access_filters':      self.user.access_filters,
              'signature':           self.signature,
              'first_name':          self.user.first_name,
              'last_name':           self.user.last_name,
              'force_logout_login':  self.force_logout_login}

    query_string = '&'.join(["%s=%s" % (key, urllib.quote_plus(val)) for key, val in params.iteritems()])

    return "%s%s?%s" % (self.looker.host, self.path, query_string)


def test():
  looker = Looker('localhost:9999', 'b167c4998c1faadf5bf7742675aa6018aaa2e296f2eec5442b208d2cb6fdf1bd')

  user = User(57,
              first_name='Embed Wil',
              last_name='Krouse',
              permissions=['see_lookml_dashboards', 'access_data'],
              models=['wilg_thelook'],
              access_filters={'fake_model': {'id': 1}})

  fifteen_minutes = 15 * 60

  url = URL(looker, user, fifteen_minutes, "/embed/sso/dashboards/wilg_thelook/1_business_pulse?date=Last+90+Days", force_logout_login=True)

  print "https://" + url.to_string()
