# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import dbs
from south.v2 import SchemaMigration
from django.db import models

db = dbs["pubdb"]

class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Client'
        db.create_table(u'pubdb_client', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('client_handle', self.gf('django.db.models.fields.CharField')(unique=True, max_length=255)),
            ('base_uri', self.gf('django.db.models.fields.TextField')()),
            ('bpki_cert', self.gf('rpki.fields.BlobField')(default=None, blank=True)),
            ('bpki_glue', self.gf('rpki.fields.BlobField')(default=None, null=True, blank=True)),
            ('last_cms_timestamp', self.gf('rpki.fields.SundialField')(null=True, blank=True)),
        ))
        db.send_create_signal(u'pubdb', ['Client'])

        # Adding model 'Session'
        db.create_table(u'pubdb_session', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('uuid', self.gf('django.db.models.fields.CharField')(unique=True, max_length=36)),
            ('serial', self.gf('django.db.models.fields.BigIntegerField')()),
            ('snapshot', self.gf('django.db.models.fields.TextField')(blank=True)),
            ('hash', self.gf('django.db.models.fields.CharField')(max_length=64, blank=True)),
        ))
        db.send_create_signal(u'pubdb', ['Session'])

        # Adding model 'Delta'
        db.create_table(u'pubdb_delta', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('serial', self.gf('django.db.models.fields.BigIntegerField')()),
            ('xml', self.gf('django.db.models.fields.TextField')()),
            ('hash', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('expires', self.gf('rpki.fields.SundialField')()),
            ('session', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['pubdb.Session'])),
        ))
        db.send_create_signal(u'pubdb', ['Delta'])

        # Adding model 'PublishedObject'
        db.create_table(u'pubdb_publishedobject', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('uri', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('der', self.gf('rpki.fields.BlobField')(default=None, blank=True)),
            ('hash', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('client', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['pubdb.Client'])),
            ('session', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['pubdb.Session'])),
        ))
        db.send_create_signal(u'pubdb', ['PublishedObject'])

        # Adding unique constraint on 'PublishedObject', fields ['session', 'hash']
        db.create_unique(u'pubdb_publishedobject', ['session_id', 'hash'])

        # Adding unique constraint on 'PublishedObject', fields ['session', 'uri']
        db.create_unique(u'pubdb_publishedobject', ['session_id', 'uri'])


    def backwards(self, orm):
        # Removing unique constraint on 'PublishedObject', fields ['session', 'uri']
        db.delete_unique(u'pubdb_publishedobject', ['session_id', 'uri'])

        # Removing unique constraint on 'PublishedObject', fields ['session', 'hash']
        db.delete_unique(u'pubdb_publishedobject', ['session_id', 'hash'])

        # Deleting model 'Client'
        db.delete_table(u'pubdb_client')

        # Deleting model 'Session'
        db.delete_table(u'pubdb_session')

        # Deleting model 'Delta'
        db.delete_table(u'pubdb_delta')

        # Deleting model 'PublishedObject'
        db.delete_table(u'pubdb_publishedobject')


    models = {
        u'pubdb.client': {
            'Meta': {'object_name': 'Client'},
            'base_uri': ('django.db.models.fields.TextField', [], {}),
            'bpki_cert': ('rpki.fields.BlobField', [], {'default': 'None', 'blank': 'True'}),
            'bpki_glue': ('rpki.fields.BlobField', [], {'default': 'None', 'null': 'True', 'blank': 'True'}),
            'client_handle': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '255'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'last_cms_timestamp': ('rpki.fields.SundialField', [], {'null': 'True', 'blank': 'True'})
        },
        u'pubdb.delta': {
            'Meta': {'object_name': 'Delta'},
            'expires': ('rpki.fields.SundialField', [], {}),
            'hash': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'serial': ('django.db.models.fields.BigIntegerField', [], {}),
            'session': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['pubdb.Session']"}),
            'xml': ('django.db.models.fields.TextField', [], {})
        },
        u'pubdb.publishedobject': {
            'Meta': {'unique_together': "((u'session', u'hash'), (u'session', u'uri'))", 'object_name': 'PublishedObject'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['pubdb.Client']"}),
            'der': ('rpki.fields.BlobField', [], {'default': 'None', 'blank': 'True'}),
            'hash': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'session': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['pubdb.Session']"}),
            'uri': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        },
        u'pubdb.session': {
            'Meta': {'object_name': 'Session'},
            'hash': ('django.db.models.fields.CharField', [], {'max_length': '64', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'serial': ('django.db.models.fields.BigIntegerField', [], {}),
            'snapshot': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'uuid': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '36'})
        }
    }

    complete_apps = ['pubdb']
