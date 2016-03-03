# First cut at ORM models for rcynicng.

from django.db import models

# HTTP/HTTPS/RSYNC fetch event.

class Retrieval(models.Model):
    uri        = models.TextField()
    started    = models.DateTimeField()
    finished   = models.DateTimeField()
    successful = models.BooleanField()

    def __repr__(self):
        try:
            return "<Retrieval: {0.uri} started {0.started} finished {0.finished} successful {0.successful}>".format(self)
        except:
            return "<Retrieval: {}>".format(id(self))

# Collection of validated objects.

class Authenticated(models.Model):
    started  = models.DateTimeField()
    finished = models.DateTimeField(null = True)

    def __repr__(self):
        try:
            return "<Authenticated: started {0.started} finished {0.finished}>".format(self)
        except:
            return "<Authenticated: {}>".format(id(self))

# One instance of an RRDP snapshot.

class RRDPSnapshot(models.Model):
    session_id = models.UUIDField()
    serial     = models.BigIntegerField()
    retrieved  = models.OneToOneField(Retrieval, null = True)

    def __repr__(self):
        try:
            return "<RRDPSnapshot: serial {0.serial} session_id {0.session_id} retrieved {0.retrieved!r}>".format(self)
        except:
            return "<RRDPSnapshot: {}>".format(id(self))


# RPKI objects.
#
# Might need to add an on_delete argument to the ForeignKey for the
# retrieved field: the default behavior is CASCADE, which is may not
# what we want in this case.
#
# https://docs.djangoproject.com/en/1.9/ref/models/fields/#django.db.models.ForeignKey.on_delete
#
# Might also want to provide names for the reverse relationships, code
# uses blah_set for now.

# Setting unique = True on the der field breaks with PostgreSQL, see
# https://code.djangoproject.com/ticket/14904
#
# In theory collisions on sha256 are possible, but in practice they're
# not going to occur by accident.  Setting unique = True on the sha256
# field risks deliberate collisions, defending against that would
# require detecting the collision and figuring out which is the
# attacking object (easy in theory, as it probably won't validate),
# then figuring out what to do about it (possibly harder -- do we drop
# an entire RRDP zone because of one evil object?).

class RPKIObject(models.Model):
    der           = models.BinaryField() # unique = True
    uri           = models.TextField()
    aki           = models.SlugField(max_length = 40)  # hex SHA-1
    ski           = models.SlugField(max_length = 40)  # hex SHA-1
    sha256        = models.SlugField(max_length = 64, unique = True) # hex SHA-256
    retrieved     = models.ForeignKey(Retrieval)
    authenticated = models.ManyToManyField(Authenticated)
    snapshot      = models.ManyToManyField(RRDPSnapshot)

    def __repr__(self):
        try:
            return "<RPKIObject: uri {0.uri} sha256 {0.sha256} ski {0.ski} aki {0.aki} retrieved {0.retrieved!r}>".format(self)
        except:
            return "<RPKIObject: {}>".format(id(self))
