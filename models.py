from google.appengine.ext import db

class APIKey(db.Model):
  key_id = db.IntegerProperty(required=True)
  vcode = db.StringProperty(required=True)
  owner = db.UserProperty(required=True)

class Character(db.Model):
  char_id = db.IntegerProperty(required=True)
  name = db.StringProperty(required=True)
  api_key = db.ReferenceProperty(APIKey)

class Certification(db.Model):
  name = db.StringProperty(required=True)
  owner = db.UserProperty(required=True)
  modified = db.DateTimeProperty(auto_now=True)
  authkey = db.StringProperty(default="")
  public = db.BooleanProperty(default=True)

class RequiredSkill(db.Model):
  skill_id = db.IntegerProperty(required=True)
  level = db.IntegerProperty(required=True)
  cert = db.ReferenceProperty(Certification, collection_name='required_skills')

class SkillTree(db.Model):
  json_data = db.TextProperty(required=True)
