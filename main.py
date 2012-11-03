import json
import os
import re

from google.appengine.api import memcache, users
from google.appengine.ext import db
import jinja2
import webapp2

import evelink
from evelink import appengine as elink_appengine
import models

jinja_environment = jinja2.Environment(
  loader=jinja2.FileSystemLoader(os.path.dirname(__file__)))

class HomeHandler(webapp2.RequestHandler):

  def get(self):
    template = jinja_environment.get_template('index.html')
    self.response.out.write(template.render({}))

class APIKeysHandler(webapp2.RequestHandler):

  KEY_LIST_CACHE_KEY_FORMAT = "key-list-1-%s"

  def get(self):
    action = self.request.get('action')

    if action == 'refresh':
      return self.refresh_key()
    elif action == 'remove':
      return self.remove_key()

    return self.list_keys()

  def post(self):
    action = self.request.get('action')

    if action == 'add':
      return self.add_key()

    self.error(500)

  def list_keys(self):
    user = users.get_current_user()
    mc_key = self.KEY_LIST_CACHE_KEY_FORMAT % user.user_id()

    page = memcache.get(mc_key)

    if not page:
      keys = []
      for key in models.APIKey.all().filter("owner =", user):
        key_data = {
          'id': key.key_id,
          'vcode': key.vcode,
          'characters': ", ".join(c.name for c in key.character_set),
        }
        keys.append(key_data)

      template = jinja_environment.get_template("apikeys.html")
      page = template.render({'keys': keys})
      memcache.set(mc_key, page)

    self.response.out.write(page)

  def add_key(self):
    key_id, vcode = self.validate_key()

    if not (key_id and vcode):
      self.error(500)
      self.response.out.write("Invalid key ID or verification code."
        " Please press Back and enter a valid set of API credentials.")
      return

    user = users.get_current_user()

    user_keys = models.APIKey.all().filter("owner =", user)
    for key in user_keys:
      if key.key_id == key_id and key.vcode == vcode:
        return self.redirect("/apikeys")

    new_key = models.APIKey(key_id=key_id, vcode=vcode, owner=user)
    new_key.put()
    memcache.delete(self.KEY_LIST_CACHE_KEY_FORMAT % user.user_id())

    self.redirect("/apikeys?action=refresh&id=%d" % key_id)

  def remove_key(self):
    user = users.get_current_user()

    try:
      key_id = int(self.request.get('id'))
    except (ValueError, TypeError):
      self.error(500)
      return self.response.out.write("Invalid key id.")

    user_keys = models.APIKey.all().filter("owner = ", user)
    existing_key = user_keys.filter("key_id =", key_id).get()
    if existing_key:
      existing_key.delete()

    memcache.delete(self.KEY_LIST_CACHE_KEY_FORMAT % user.user_id())

    self.redirect("/apikeys")

  def validate_key(self):
    key_id, vcode = self.request.get('id'), self.request.get('vcode')
    try:
      key_id = int(self.request.get('id'))
      if not key_id > 0:
        raise ValueError()
    except (ValueError, TypeError):
      return None, None

    if not vcode or not re.match(r'^[a-zA-Z0-9]{64}$', vcode):
      return None, None

    return key_id, vcode

  def refresh_key(self):
    user = users.get_current_user()

    try:
      key_id = int(self.request.get('id'))
    except (ValueError, TypeError):
      self.error(500)
      return self.response.out.write("Invalid key id.")

    user_keys = models.APIKey.all().filter("owner =", user)
    existing_key = user_keys.filter("key_id = ", key_id).get()

    if not existing_key:
      self.error(500)
      return self.response.out.write("Unable to refresh key.")

    try:
      self.refresh_characters(user, existing_key)
    except evelink.api.APIError:
      self.error(500)
      return self.response.write("API Error.")

    memcache.delete(self.KEY_LIST_CACHE_KEY_FORMAT % user.user_id())

    self.redirect("/apikeys")

  def refresh_characters(self, user, key):
    elink_api = elink_appengine.AppEngineAPI(api_key=(key.key_id, key.vcode))
    elink_account = evelink.account.Account(api=elink_api)
    info = elink_account.key_info()

    retrieved_characters = info['characters']
    existing_characters = list(key.character_set)

    old_ids = set(c.char_id for c in existing_characters)
    new_ids = set(retrieved_characters)

    ids_to_delete = old_ids - new_ids
    ids_to_add = new_ids - old_ids

    models_to_add = []
    for char_id in ids_to_add:
      name = retrieved_characters[char_id]['name']
      model = models.Character(char_id=char_id, name=name, api_key=key)
      models_to_add.append(model)
    if models_to_add:
      db.put(models_to_add)

    models_to_delete = [c for c in existing_characters
      if c.char_id in ids_to_delete]
    if models_to_delete:
      db.delete(models_to_delete)

class SkillTreeHandler(webapp2.RequestHandler):

  SKILL_TREE_CACHE_KEY = 'skill-tree-1'

  def get(self):
    skilltree = models.SkillTree.all().get()

    elink_api = elink_appengine.AppEngineAPI()
    elink_eve = evelink.eve.EVE(api=elink_api)
    treedata = elink_eve.skill_tree()
    memcache.set(self.SKILL_TREE_CACHE_KEY, treedata)

    if skilltree:
      skilltree.json_data = json.dumps(treedata)
    else:
      skilltree = models.SkillTree(json_data = json.dumps(treedata))
    skilltree.put()

    self.response.out.write("Successfully retrieved skills for %d groups." %
      len(treedata))

class CertificationsHandler(webapp2.RequestHandler):

  CERT_LIST_CACHE_KEY_FORMAT = "cert-list-1-%s"

  def get(self):
    action = self.request.get('action')

    return self.list_certs()

  def list_certs(self):
    user = users.get_current_user()
    mc_key = self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id()

    page = memcache.get(mc_key)

    if not page:
      certs = []
      for cert in models.Certification.all().filter("owner =", user):
        cert_data = {
          'name': cert.name,
          'id': cert.key().id(),
          'modified': cert.modified.strftime("%x %X"),
          'skills': cert.required_skills.count(),
        }
        certs.append(cert_data)
      template = jinja_environment.get_template("certs.html")
      page = template.render({'certs': certs})
      memcache.set(mc_key, page)

    self.response.out.write(page)

application = webapp2.WSGIApplication(
  [
    ('/apikeys', APIKeysHandler),
    ('/certs', CertificationsHandler),
    ('/skilltree', SkillTreeHandler),
    ('/', HomeHandler),
  ],
  debug=True,
)
