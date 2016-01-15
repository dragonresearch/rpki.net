# First cut at ORM models for rcynicng.

from django.db import models

# HTTP/HTTPS/RSYNC fetch event.

class Retrieval(models.Model):
    uri        = models.TextField()
    started    = models.DateTimeField()
    finished   = models.DateTimeField()
    successful = models.BooleanField()

# Collection of validated objects.

class Authenticated(models.Model):
    started  = models.DateTimeField()
    finished = models.DateTimeField(null = True)

# One instance of an RRDP snapshot.

class RRDPSnapshot(models.Model):
    session_id = models.UUIDField()
    serial     = models.BigIntegerField()
    retrieved  = models.OneToOneField(Retrieval)

# RPKI objects.
#
# Might need to add an on_delete argument to the ForeignKey for the
# retrieved field: the default behavior is CASCADE, which is may not
# what we want in this case.
#
# https://docs.djangoproject.com/en/1.9/ref/models/fields/#django.db.models.ForeignKey.on_delete
#
# Might also want to provide names for the reverse relationships, code uses blah_set for now.

class RPKIObject(models.Model):
    der           = models.BinaryField(unique = True)
    uri           = models.TextField()
    aki           = models.SlugField(max_length = 40)  # hex SHA-1
    ski           = models.SlugField(max_length = 40)  # hex SHA-1
    sha256        = models.SlugField(max_length = 64) # hex SHA-256
    retrieved     = models.ForeignKey(Retrieval)
    authenticated = models.ManyToManyField(Authenticated)
    snapshot      = models.ManyToManyField(RRDPSnapshot)
