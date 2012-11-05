import json
import os
import random
import re
import string

from google.appengine.api import app_identity, memcache, users
from google.appengine.ext import db
import jinja2
import webapp2

import evelink
from evelink import appengine as elink_appengine
import models

def random_string(N):
  choices = string.ascii_letters + string.digits
  return ''.join(random.choice(choices) for _ in range(N))

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

    if not (info['access_mask'] & 8):
      self.error(500)
      return self.response.out.write(
        "This key does not have Character Sheet access, which is required.")

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
  SKILL_NAMES_CACHE_KEY = 'skill-names-1'

  def get(self):
    skilltree = models.SkillTree.all().get()

    elink_api = elink_appengine.AppEngineAPI()
    elink_eve = evelink.eve.EVE(api=elink_api)
    treedata = elink_eve.skill_tree()
    SkillTreeHandler.cache_skill_data(treedata)

    if skilltree:
      skilltree.json_data = json.dumps(treedata)
    else:
      skilltree = models.SkillTree(json_data = json.dumps(treedata))
    skilltree.put()

    self.response.out.write("Successfully retrieved skills for %d groups." %
      len(treedata))

  @classmethod
  def cache_skill_data(cls, treedata):
    memcache.set(cls.SKILL_TREE_CACHE_KEY, treedata)
    memcache.delete(CertificationsHandler.SKILL_GROUPS_CACHE_KEY)
    cls.get_skill_data()

  @classmethod
  def get_skill_data(cls):
    treedata = memcache.get(cls.SKILL_TREE_CACHE_KEY)
    if not treedata:
      skilltree = models.SkillTree.all().get()
      treedata = json.loads(skilltree.json_data)
      memcache.set(cls.SKILL_TREE_CACHE_KEY, treedata)

    skill_names = memcache.get(cls.SKILL_NAMES_CACHE_KEY)
    if not skill_names:
      skill_names = {}
      for skillgroup in treedata.itervalues():
        for skill in skillgroup['skills'].itervalues():
          skill_names[skill['id']] = skill['name']
      memcache.set(cls.SKILL_NAMES_CACHE_KEY, skill_names)

    return treedata, skill_names

class CertificationsHandler(webapp2.RequestHandler):

  CERT_LIST_CACHE_KEY_FORMAT = "cert-list-1-%s"
  CERT_SKILLS_CACHE_KEY_FORMAT = "cert-skills-1-%s"
  SKILL_GROUPS_CACHE_KEY = 'skill-groups'

  def get(self):
    action = self.request.get('action')

    if action == 'edit':
      return self.edit_cert()
    elif action == 'remove':
      return self.remove_cert()
    elif action == 'removeskill':
      return self.remove_skill()
    elif action == 'togglelock':
      return self.toggle_lock()
    elif action == 'resetlink':
      return self.reset_link()

    return self.list_certs()

  def post(self):
    action = self.request.get('action')

    if action == 'add':
      return self.add_cert()
    elif action == 'addskill':
      return self.add_skill()

    self.error(500)

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
          'public': cert.public,
          'authkey': cert.authkey,
        }
        certs.append(cert_data)
      template = jinja_environment.get_template("certs.html")
      page = template.render({'certs': certs})
      memcache.set(mc_key, page)

    self.response.out.write(page)

  def add_cert(self):
    name = self.request.get('name')

    if not (3 < len(name) < 101):
      self.error(500)
      return self.response.out.write("Name is too long or too short."
        " Please press Back and enter a name between 4 and 100 characters.")

    user = users.get_current_user()

    cert = models.Certification(name=name, owner=user)
    cert.put()

    memcache.delete(self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id())

    self.redirect("/certs?action=edit&id=%d" % cert.key().id())

  def remove_cert(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))

    cert = models.Certification.get_by_id(cert_id)
    if cert:
      cert.delete()

      memcache.delete(self.CERT_SKILLS_CACHE_KEY_FORMAT % cert_id)
      memcache.delete(self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id())

    self.redirect("/certs")

  def edit_cert(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))

    cert = models.Certification.get_by_id(cert_id)
    if not cert or cert.owner != user:
      return self.error(403)

    skill_tree, skill_names = SkillTreeHandler.get_skill_data()

    mc_key = self.CERT_SKILLS_CACHE_KEY_FORMAT % cert_id
    skills = memcache.get(mc_key)
    if not skills:
      skills = []
      for skill in cert.required_skills:
        skills.append({
          'name': skill_names[skill.skill_id],
          'rank': skill.level,
          'id': skill.skill_id,
        })
      memcache.set(mc_key, skills)

    skillgroups = memcache.get(self.SKILL_GROUPS_CACHE_KEY)
    if not skillgroups:
      skillgroups = []
      for group in skill_tree.itervalues():
        s = [s for s in group['skills'].itervalues() if s['published']]
        if not s:
          continue
        skillgroup = {
          'name': group['name'],
          'skills': sorted(s, key=lambda x: x['name'])
        }
        skillgroups.append(skillgroup)
      skillgroups.sort(key=lambda x: x['name'])
      memcache.set(self.SKILL_GROUPS_CACHE_KEY, skillgroups)

    data = {
      'cert': cert,
      'skills': skills,
      'skillgroups': skillgroups,
    }

    template = jinja_environment.get_template("edit_cert.html")
    page = template.render(data)

    self.response.out.write(page)

  def add_skill(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))
    skill_id = int(self.request.get('skillid'))
    rank = int(self.request.get('rank'))

    cert = models.Certification.get_by_id(cert_id)
    if not cert or cert.owner != user:
      return self.error(403)

    skill_tree, skill_names = SkillTreeHandler.get_skill_data()

    if skill_id not in skill_names:
      return self.error(500)

    if not (0 < rank < 6):
      return self.error(500)

    for required_skill in cert.required_skills:
      if required_skill.skill_id == skill_id:
        if required_skill.level < rank:
          required_skill.level = rank
          required_skill.put()
        break
    else:
      required_skill = models.RequiredSkill(
        skill_id=skill_id, level=rank, cert=cert)
      required_skill.put()

    memcache.delete(self.CERT_SKILLS_CACHE_KEY_FORMAT % cert_id)

    return self.redirect("/certs?action=edit&id=%d" % cert_id)

  def remove_skill(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))
    skill_id = int(self.request.get('skillid'))

    cert = models.Certification.get_by_id(cert_id)
    if not cert or cert.owner != user:
      return self.error(403)

    for skill in cert.required_skills:
      if skill.skill_id == skill_id:
        skill.delete()
        break

    memcache.delete(self.CERT_SKILLS_CACHE_KEY_FORMAT % cert_id)

    return self.redirect("/certs?action=edit&id=%d" % cert_id)

  def toggle_lock(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))

    cert = models.Certification.get_by_id(cert_id)
    if not cert or cert.owner != user:
      return self.error(403)

    if cert.public:
      cert.public = False
      if not cert.authkey:
        cert.authkey = random_string(8)
    else:
      cert.public = True

    cert.put()

    memcache.delete(self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id())

    return self.redirect("/certs")

  def reset_link(self):
    user = users.get_current_user()
    cert_id = int(self.request.get('id'))

    cert = models.Certification.get_by_id(cert_id)
    if not cert or cert.owner != user:
      return self.error(403)

    cert.authkey = random_string(8)
    cert.put()

    memcache.delete(self.CERT_LIST_CACHE_KEY_FORMAT % user.user_id())

    return self.redirect("/cert?id=%d" % cert.key().id())



class CertificationHandler(webapp2.RequestHandler):

  ranks = {
    -1: '-',
    0: 'Injected',
    1: '1',
    2: '2',
    3: '3',
    4: '4',
    5: '5',
  }

  def get(self):
    try:
      cert_id = int(self.request.get('id'))
    except (ValueError, TypeError):
      return self.error(404)


    self.show_cert(cert_id)

  def show_cert(self, cert_id):
    cert = models.Certification.get_by_id(cert_id)
    if not cert:
      return self.error(404)

    user = users.get_current_user()
    if not cert.public and cert.owner != user:
      authkey = self.request.get('auth')
      if authkey != cert.authkey:
        return self.error(403)

    if user:
      characters = []
      keys = models.APIKey.all().filter("owner =", user)
      for key in keys:
        characters.extend(key.character_set)
      characters.sort(key=lambda c:c.name)
    else:
      characters = []

    skill_tree, skill_names = SkillTreeHandler.get_skill_data()

    skills = []
    for skill in cert.required_skills:
      skills.append({
        'name': skill_names[skill.skill_id],
        'rank': skill.level,
        'id': skill.skill_id,
      })

    sharelink = "%s.appspot.com/cert?id=%d" % (
      app_identity.get_application_id(), cert.key().id())
    if not cert.public:
      sharelink += "&auth=%s" % cert.authkey

    data = {
      'cert': cert,
      'sharelink': sharelink,
      'owner': cert.owner == user,
      'characters': characters,
      'skills': skills,
    }

    char_id = self.request.get('character')
    if char_id:
      char_id = int(char_id)
      return self.show_cert_progress(data, char_id)

    template = jinja_environment.get_template("view_cert.html")
    page = template.render(data)
    self.response.out.write(page)

  def show_cert_progress(self, data, char_id):
    character = None
    for char in data['characters']:
      if char.char_id == char_id:
        character = char
        break

    if character is None:
      return self.redirect("/progress?id=%d" % data['cert'].key().id())

    key = character.api_key

    elink_api = elink_appengine.AppEngineAPI(api_key=(key.key_id, key.vcode))
    elink_char = evelink.char.Char(character.char_id, api=elink_api)
    charsheet = elink_char.character_sheet()

    skill_to_rank = {}
    for skill in charsheet['skills']:
      skill_to_rank[skill['id']] = skill['level']

    totals = {
      'overall': 0,
      'green': 0,
      'yellow': 0,
      'red': 0,
    }

    for skill in data['skills']:
      totals['overall'] += 1
      skill['trained_rank'] = skill_to_rank.get(skill['id'], -1)
      skill['display_rank'] = self.ranks[skill['trained_rank']]
      if skill['trained_rank'] >= skill['rank']:
        skill['row_class'] = 'success'
        totals['green'] += 1
      elif skill['trained_rank'] > 0:
        skill['row_class'] = 'warning'
        totals['yellow'] += 1
      elif skill['trained_rank'] == 0:
        skill['row_class'] = 'warning'
        totals['yellow'] += 1
      else:
        skill['row_class'] = 'error'

    percents = {
      'green': 100 * totals['green'] / totals['overall'],
      'yellow': 100 * totals['yellow'] / totals['overall'],
    }

    data['active_character'] = character
    data['percents'] = percents

    template = jinja_environment.get_template("view_cert.html")
    page = template.render(data)
    self.response.out.write(page)

application = webapp2.WSGIApplication(
  [
    ('/apikeys', APIKeysHandler),
    ('/certs', CertificationsHandler),
    ('/skilltree', SkillTreeHandler),
    ('/cert', CertificationHandler),
    ('/', HomeHandler),
  ],
  debug=os.environ.get('SERVER_SOFTWARE', '').startswith('Dev'),
)
