# First cut at ORM models for rcynicng, assuming for now that we're
# going to go with Django rather than raw SQL.

from django.db import models

# HTTP/HTTPS/RSYNC fetch event.
#
# Open issue: for RRDP, are we just recording the notification fetch,
# or the snapshot/delta fetches as well?  If the latter, to which
# retrieval event does the RRDPSnapshot 1:1 relationship refer?  For
# that matter, should we somehow be recording the relationship between
# the notification and snapshot/delta fetches?  Given that, at least
# in the current protocol, we will only do either one snapshot fetch
# or one delta fetch after the notify fetch, we could just use two
# URIs in the retrieval record, if we allow the second to be empty
# (which we would have to do anyway for rsync).
#
# Or we could add some kind of fun SQL self-reference, which, in
# Django, looks like:
#
#   models.ForeignKey('self', on_delete = models.CASCADE)
#
# except that it's more like a 1:1 recursive relationship, which isn't
# mentioned in the Django docs, but which supposedly
# (http://stackoverflow.com/questions/18271001/django-recursive-relationship)
# works the same way:
#
#   models.OneToOneField('self', null = True)
#
# Unclear whether we still need "on_delete = models.CASCADE", probably.
# Example on StackOverflow has a complex .save() method, but that may
# be specific to the original poster's desired semantics.

class Retrieval(models.Model):
    uri        = models.TextField()
    started    = models.DateTimeField()
    finished   = models.DateTimeField()
    successful = models.BooleanField()

# Collection of validated objects (like current
# rsync-data/authenticated.yyyy-mm-ddTHH:MM:SS/ tree)

class Authenticated(models.Model):
    started  = models.DateTimeField()
    finished = models.DateTimeField(null = True)

# One instance of an RRDP snapshot.
#
# Deltas are processed by finding the RRDPSnapshot holding the
# starting point, creating a new RRDPSnapshot for the endpoint, and
# applying all necessary deltas (with consistency checks all along the
# way) to get from one to the other; we don't commit the endpoint (or
# anything created during the process) until and unless it all works.
#
# Not sure we want uuid field, drop if not useful.
# Not sure we want timestamp, 1:1 relationship with retrieval may suffice.

class RRDPSnapshot(models.Model):
    timestamp = models.DateTimeField()
    uuid      = models.UUIDField()
    serial    = models.BigIntegerField()
    retrieved = models.OneToOneField(Retrieval)

# RPKI objects.
#
# Might need to add an on_delete argument to the ForeignKey for the
# retrieved field: the default behavior is CASCADE, which is may not
# what we want in this case.
#
# https://docs.djangoproject.com/en/1.9/ref/models/fields/#django.db.models.ForeignKey.on_delete

class RPKIObject(models.Model):
    der           = models.BinaryField(unique = True)
    uri           = models.TextField()
    aki           = models.SlugField(max_length = 40)  # hex SHA-1
    ski           = models.SlugField(max_length = 40)  # hex SHA-1
    sha256        = models.SlugField(max_length = 64) # hex SHA-256
    retrieved     = models.ForeignKey(Retrieval)
    authenticated = models.ManyToManyField(Authenticated)
    snapshot      = models.ManyToManyField(RRDPSnapshot)
