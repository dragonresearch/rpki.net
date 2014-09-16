# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'ServerCA'
        db.create_table(u'irdb_serverca', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('private_key', self.gf('rpki.fields.KeyField')(default=None, blank=True)),
            ('latest_crl', self.gf('rpki.fields.CRLField')(default=None, blank=True)),
            ('next_serial', self.gf('django.db.models.fields.BigIntegerField')(default=1)),
            ('next_crl_number', self.gf('django.db.models.fields.BigIntegerField')(default=1)),
            ('last_crl_update', self.gf('rpki.fields.SundialField')()),
            ('next_crl_update', self.gf('rpki.fields.SundialField')()),
        ))
        db.send_create_signal(u'irdb', ['ServerCA'])

        # Adding model 'ResourceHolderCA'
        db.create_table(u'irdb_resourceholderca', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('private_key', self.gf('rpki.fields.KeyField')(default=None, blank=True)),
            ('latest_crl', self.gf('rpki.fields.CRLField')(default=None, blank=True)),
            ('next_serial', self.gf('django.db.models.fields.BigIntegerField')(default=1)),
            ('next_crl_number', self.gf('django.db.models.fields.BigIntegerField')(default=1)),
            ('last_crl_update', self.gf('rpki.fields.SundialField')()),
            ('next_crl_update', self.gf('rpki.fields.SundialField')()),
            ('handle', self.gf('rpki.irdb.models.HandleField')(unique=True, max_length=120)),
        ))
        db.send_create_signal(u'irdb', ['ResourceHolderCA'])

        # Adding model 'HostedCA'
        db.create_table(u'irdb_hostedca', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['irdb.ServerCA'])),
            ('hosted', self.gf('django.db.models.fields.related.OneToOneField')(related_name='hosted_by', unique=True, to=orm['irdb.ResourceHolderCA'])),
        ))
        db.send_create_signal(u'irdb', ['HostedCA'])

        # Adding unique constraint on 'HostedCA', fields ['issuer', 'hosted']
        db.create_unique(u'irdb_hostedca', ['issuer_id', 'hosted_id'])

        # Adding model 'ServerRevocation'
        db.create_table(u'irdb_serverrevocation', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('serial', self.gf('django.db.models.fields.BigIntegerField')()),
            ('revoked', self.gf('rpki.fields.SundialField')()),
            ('expires', self.gf('rpki.fields.SundialField')()),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='revocations', to=orm['irdb.ServerCA'])),
        ))
        db.send_create_signal(u'irdb', ['ServerRevocation'])

        # Adding unique constraint on 'ServerRevocation', fields ['issuer', 'serial']
        db.create_unique(u'irdb_serverrevocation', ['issuer_id', 'serial'])

        # Adding model 'ResourceHolderRevocation'
        db.create_table(u'irdb_resourceholderrevocation', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('serial', self.gf('django.db.models.fields.BigIntegerField')()),
            ('revoked', self.gf('rpki.fields.SundialField')()),
            ('expires', self.gf('rpki.fields.SundialField')()),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='revocations', to=orm['irdb.ResourceHolderCA'])),
        ))
        db.send_create_signal(u'irdb', ['ResourceHolderRevocation'])

        # Adding unique constraint on 'ResourceHolderRevocation', fields ['issuer', 'serial']
        db.create_unique(u'irdb_resourceholderrevocation', ['issuer_id', 'serial'])

        # Adding model 'ServerEE'
        db.create_table(u'irdb_serveree', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('private_key', self.gf('rpki.fields.KeyField')(default=None, blank=True)),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='ee_certificates', to=orm['irdb.ServerCA'])),
            ('purpose', self.gf('rpki.fields.EnumField')()),
        ))
        db.send_create_signal(u'irdb', ['ServerEE'])

        # Adding unique constraint on 'ServerEE', fields ['issuer', 'purpose']
        db.create_unique(u'irdb_serveree', ['issuer_id', 'purpose'])

        # Adding model 'Referral'
        db.create_table(u'irdb_referral', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('private_key', self.gf('rpki.fields.KeyField')(default=None, blank=True)),
            ('issuer', self.gf('django.db.models.fields.related.OneToOneField')(related_name='referral_certificate', unique=True, to=orm['irdb.ResourceHolderCA'])),
        ))
        db.send_create_signal(u'irdb', ['Referral'])

        # Adding model 'Turtle'
        db.create_table(u'irdb_turtle', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('service_uri', self.gf('django.db.models.fields.CharField')(max_length=255)),
        ))
        db.send_create_signal(u'irdb', ['Turtle'])

        # Adding model 'Rootd'
        db.create_table(u'irdb_rootd', (
            (u'turtle_ptr', self.gf('django.db.models.fields.related.OneToOneField')(to=orm['irdb.Turtle'], unique=True, primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('private_key', self.gf('rpki.fields.KeyField')(default=None, blank=True)),
            ('issuer', self.gf('django.db.models.fields.related.OneToOneField')(related_name='rootd', unique=True, to=orm['irdb.ResourceHolderCA'])),
        ))
        db.send_create_signal(u'irdb', ['Rootd'])

        # Adding model 'BSC'
        db.create_table(u'irdb_bsc', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='bscs', to=orm['irdb.ResourceHolderCA'])),
            ('handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
            ('pkcs10', self.gf('rpki.fields.PKCS10Field')(default=None, blank=True)),
        ))
        db.send_create_signal(u'irdb', ['BSC'])

        # Adding unique constraint on 'BSC', fields ['issuer', 'handle']
        db.create_unique(u'irdb_bsc', ['issuer_id', 'handle'])

        # Adding model 'Child'
        db.create_table(u'irdb_child', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
            ('ta', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('valid_until', self.gf('rpki.fields.SundialField')()),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='children', to=orm['irdb.ResourceHolderCA'])),
            ('name', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
        ))
        db.send_create_signal(u'irdb', ['Child'])

        # Adding unique constraint on 'Child', fields ['issuer', 'handle']
        db.create_unique(u'irdb_child', ['issuer_id', 'handle'])

        # Adding model 'ChildASN'
        db.create_table(u'irdb_childasn', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('start_as', self.gf('django.db.models.fields.BigIntegerField')()),
            ('end_as', self.gf('django.db.models.fields.BigIntegerField')()),
            ('child', self.gf('django.db.models.fields.related.ForeignKey')(related_name='asns', to=orm['irdb.Child'])),
        ))
        db.send_create_signal(u'irdb', ['ChildASN'])

        # Adding unique constraint on 'ChildASN', fields ['child', 'start_as', 'end_as']
        db.create_unique(u'irdb_childasn', ['child_id', 'start_as', 'end_as'])

        # Adding model 'ChildNet'
        db.create_table(u'irdb_childnet', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('start_ip', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('end_ip', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('version', self.gf('rpki.fields.EnumField')()),
            ('child', self.gf('django.db.models.fields.related.ForeignKey')(related_name='address_ranges', to=orm['irdb.Child'])),
        ))
        db.send_create_signal(u'irdb', ['ChildNet'])

        # Adding unique constraint on 'ChildNet', fields ['child', 'start_ip', 'end_ip', 'version']
        db.create_unique(u'irdb_childnet', ['child_id', 'start_ip', 'end_ip', 'version'])

        # Adding model 'Parent'
        db.create_table(u'irdb_parent', (
            (u'turtle_ptr', self.gf('django.db.models.fields.related.OneToOneField')(to=orm['irdb.Turtle'], unique=True, primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
            ('ta', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='parents', to=orm['irdb.ResourceHolderCA'])),
            ('parent_handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
            ('child_handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
            ('repository_type', self.gf('rpki.fields.EnumField')()),
            ('referrer', self.gf('rpki.irdb.models.HandleField')(max_length=120, null=True, blank=True)),
            ('referral_authorization', self.gf('rpki.irdb.models.SignedReferralField')(default=None, null=True, blank=True)),
        ))
        db.send_create_signal(u'irdb', ['Parent'])

        # Adding unique constraint on 'Parent', fields ['issuer', 'handle']
        db.create_unique(u'irdb_parent', ['issuer_id', 'handle'])

        # Adding model 'ROARequest'
        db.create_table(u'irdb_roarequest', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='roa_requests', to=orm['irdb.ResourceHolderCA'])),
            ('asn', self.gf('django.db.models.fields.BigIntegerField')()),
        ))
        db.send_create_signal(u'irdb', ['ROARequest'])

        # Adding model 'ROARequestPrefix'
        db.create_table(u'irdb_roarequestprefix', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('roa_request', self.gf('django.db.models.fields.related.ForeignKey')(related_name='prefixes', to=orm['irdb.ROARequest'])),
            ('version', self.gf('rpki.fields.EnumField')()),
            ('prefix', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('prefixlen', self.gf('django.db.models.fields.PositiveSmallIntegerField')()),
            ('max_prefixlen', self.gf('django.db.models.fields.PositiveSmallIntegerField')()),
        ))
        db.send_create_signal(u'irdb', ['ROARequestPrefix'])

        # Adding unique constraint on 'ROARequestPrefix', fields ['roa_request', 'version', 'prefix', 'prefixlen', 'max_prefixlen']
        db.create_unique(u'irdb_roarequestprefix', ['roa_request_id', 'version', 'prefix', 'prefixlen', 'max_prefixlen'])

        # Adding model 'GhostbusterRequest'
        db.create_table(u'irdb_ghostbusterrequest', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='ghostbuster_requests', to=orm['irdb.ResourceHolderCA'])),
            ('parent', self.gf('django.db.models.fields.related.ForeignKey')(related_name='ghostbuster_requests', null=True, to=orm['irdb.Parent'])),
            ('vcard', self.gf('django.db.models.fields.TextField')()),
        ))
        db.send_create_signal(u'irdb', ['GhostbusterRequest'])

        # Adding model 'EECertificateRequest'
        db.create_table(u'irdb_eecertificaterequest', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('valid_until', self.gf('rpki.fields.SundialField')()),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='ee_certificate_requests', to=orm['irdb.ResourceHolderCA'])),
            ('pkcs10', self.gf('rpki.fields.PKCS10Field')(default=None, blank=True)),
            ('gski', self.gf('django.db.models.fields.CharField')(max_length=27)),
            ('cn', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('sn', self.gf('django.db.models.fields.CharField')(max_length=64)),
            ('eku', self.gf('django.db.models.fields.TextField')(null=True)),
        ))
        db.send_create_signal(u'irdb', ['EECertificateRequest'])

        # Adding unique constraint on 'EECertificateRequest', fields ['issuer', 'gski']
        db.create_unique(u'irdb_eecertificaterequest', ['issuer_id', 'gski'])

        # Adding model 'EECertificateRequestASN'
        db.create_table(u'irdb_eecertificaterequestasn', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('start_as', self.gf('django.db.models.fields.BigIntegerField')()),
            ('end_as', self.gf('django.db.models.fields.BigIntegerField')()),
            ('ee_certificate_request', self.gf('django.db.models.fields.related.ForeignKey')(related_name='asns', to=orm['irdb.EECertificateRequest'])),
        ))
        db.send_create_signal(u'irdb', ['EECertificateRequestASN'])

        # Adding unique constraint on 'EECertificateRequestASN', fields ['ee_certificate_request', 'start_as', 'end_as']
        db.create_unique(u'irdb_eecertificaterequestasn', ['ee_certificate_request_id', 'start_as', 'end_as'])

        # Adding model 'EECertificateRequestNet'
        db.create_table(u'irdb_eecertificaterequestnet', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('start_ip', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('end_ip', self.gf('django.db.models.fields.CharField')(max_length=40)),
            ('version', self.gf('rpki.fields.EnumField')()),
            ('ee_certificate_request', self.gf('django.db.models.fields.related.ForeignKey')(related_name='address_ranges', to=orm['irdb.EECertificateRequest'])),
        ))
        db.send_create_signal(u'irdb', ['EECertificateRequestNet'])

        # Adding unique constraint on 'EECertificateRequestNet', fields ['ee_certificate_request', 'start_ip', 'end_ip', 'version']
        db.create_unique(u'irdb_eecertificaterequestnet', ['ee_certificate_request_id', 'start_ip', 'end_ip', 'version'])

        # Adding model 'Repository'
        db.create_table(u'irdb_repository', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
            ('ta', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='repositories', to=orm['irdb.ResourceHolderCA'])),
            ('client_handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
            ('service_uri', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('sia_base', self.gf('django.db.models.fields.TextField')()),
            ('turtle', self.gf('django.db.models.fields.related.OneToOneField')(related_name='repository', unique=True, to=orm['irdb.Turtle'])),
        ))
        db.send_create_signal(u'irdb', ['Repository'])

        # Adding unique constraint on 'Repository', fields ['issuer', 'handle']
        db.create_unique(u'irdb_repository', ['issuer_id', 'handle'])

        # Adding model 'Client'
        db.create_table(u'irdb_client', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('certificate', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
            ('ta', self.gf('rpki.fields.CertificateField')(default=None, blank=True)),
            ('issuer', self.gf('django.db.models.fields.related.ForeignKey')(related_name='clients', to=orm['irdb.ServerCA'])),
            ('sia_base', self.gf('django.db.models.fields.TextField')()),
            ('parent_handle', self.gf('rpki.irdb.models.HandleField')(max_length=120)),
        ))
        db.send_create_signal(u'irdb', ['Client'])

        # Adding unique constraint on 'Client', fields ['issuer', 'handle']
        db.create_unique(u'irdb_client', ['issuer_id', 'handle'])


    def backwards(self, orm):
        # Removing unique constraint on 'Client', fields ['issuer', 'handle']
        db.delete_unique(u'irdb_client', ['issuer_id', 'handle'])

        # Removing unique constraint on 'Repository', fields ['issuer', 'handle']
        db.delete_unique(u'irdb_repository', ['issuer_id', 'handle'])

        # Removing unique constraint on 'EECertificateRequestNet', fields ['ee_certificate_request', 'start_ip', 'end_ip', 'version']
        db.delete_unique(u'irdb_eecertificaterequestnet', ['ee_certificate_request_id', 'start_ip', 'end_ip', 'version'])

        # Removing unique constraint on 'EECertificateRequestASN', fields ['ee_certificate_request', 'start_as', 'end_as']
        db.delete_unique(u'irdb_eecertificaterequestasn', ['ee_certificate_request_id', 'start_as', 'end_as'])

        # Removing unique constraint on 'EECertificateRequest', fields ['issuer', 'gski']
        db.delete_unique(u'irdb_eecertificaterequest', ['issuer_id', 'gski'])

        # Removing unique constraint on 'ROARequestPrefix', fields ['roa_request', 'version', 'prefix', 'prefixlen', 'max_prefixlen']
        db.delete_unique(u'irdb_roarequestprefix', ['roa_request_id', 'version', 'prefix', 'prefixlen', 'max_prefixlen'])

        # Removing unique constraint on 'Parent', fields ['issuer', 'handle']
        db.delete_unique(u'irdb_parent', ['issuer_id', 'handle'])

        # Removing unique constraint on 'ChildNet', fields ['child', 'start_ip', 'end_ip', 'version']
        db.delete_unique(u'irdb_childnet', ['child_id', 'start_ip', 'end_ip', 'version'])

        # Removing unique constraint on 'ChildASN', fields ['child', 'start_as', 'end_as']
        db.delete_unique(u'irdb_childasn', ['child_id', 'start_as', 'end_as'])

        # Removing unique constraint on 'Child', fields ['issuer', 'handle']
        db.delete_unique(u'irdb_child', ['issuer_id', 'handle'])

        # Removing unique constraint on 'BSC', fields ['issuer', 'handle']
        db.delete_unique(u'irdb_bsc', ['issuer_id', 'handle'])

        # Removing unique constraint on 'ServerEE', fields ['issuer', 'purpose']
        db.delete_unique(u'irdb_serveree', ['issuer_id', 'purpose'])

        # Removing unique constraint on 'ResourceHolderRevocation', fields ['issuer', 'serial']
        db.delete_unique(u'irdb_resourceholderrevocation', ['issuer_id', 'serial'])

        # Removing unique constraint on 'ServerRevocation', fields ['issuer', 'serial']
        db.delete_unique(u'irdb_serverrevocation', ['issuer_id', 'serial'])

        # Removing unique constraint on 'HostedCA', fields ['issuer', 'hosted']
        db.delete_unique(u'irdb_hostedca', ['issuer_id', 'hosted_id'])

        # Deleting model 'ServerCA'
        db.delete_table(u'irdb_serverca')

        # Deleting model 'ResourceHolderCA'
        db.delete_table(u'irdb_resourceholderca')

        # Deleting model 'HostedCA'
        db.delete_table(u'irdb_hostedca')

        # Deleting model 'ServerRevocation'
        db.delete_table(u'irdb_serverrevocation')

        # Deleting model 'ResourceHolderRevocation'
        db.delete_table(u'irdb_resourceholderrevocation')

        # Deleting model 'ServerEE'
        db.delete_table(u'irdb_serveree')

        # Deleting model 'Referral'
        db.delete_table(u'irdb_referral')

        # Deleting model 'Turtle'
        db.delete_table(u'irdb_turtle')

        # Deleting model 'Rootd'
        db.delete_table(u'irdb_rootd')

        # Deleting model 'BSC'
        db.delete_table(u'irdb_bsc')

        # Deleting model 'Child'
        db.delete_table(u'irdb_child')

        # Deleting model 'ChildASN'
        db.delete_table(u'irdb_childasn')

        # Deleting model 'ChildNet'
        db.delete_table(u'irdb_childnet')

        # Deleting model 'Parent'
        db.delete_table(u'irdb_parent')

        # Deleting model 'ROARequest'
        db.delete_table(u'irdb_roarequest')

        # Deleting model 'ROARequestPrefix'
        db.delete_table(u'irdb_roarequestprefix')

        # Deleting model 'GhostbusterRequest'
        db.delete_table(u'irdb_ghostbusterrequest')

        # Deleting model 'EECertificateRequest'
        db.delete_table(u'irdb_eecertificaterequest')

        # Deleting model 'EECertificateRequestASN'
        db.delete_table(u'irdb_eecertificaterequestasn')

        # Deleting model 'EECertificateRequestNet'
        db.delete_table(u'irdb_eecertificaterequestnet')

        # Deleting model 'Repository'
        db.delete_table(u'irdb_repository')

        # Deleting model 'Client'
        db.delete_table(u'irdb_client')


    models = {
        u'irdb.bsc': {
            'Meta': {'unique_together': "(('issuer', 'handle'),)", 'object_name': 'BSC'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'bscs'", 'to': u"orm['irdb.ResourceHolderCA']"}),
            'pkcs10': ('rpki.fields.PKCS10Field', [], {'default': 'None', 'blank': 'True'})
        },
        u'irdb.child': {
            'Meta': {'unique_together': "(('issuer', 'handle'),)", 'object_name': 'Child'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'children'", 'to': u"orm['irdb.ResourceHolderCA']"}),
            'name': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'ta': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'valid_until': ('rpki.fields.SundialField', [], {})
        },
        u'irdb.childasn': {
            'Meta': {'unique_together': "(('child', 'start_as', 'end_as'),)", 'object_name': 'ChildASN'},
            'child': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'asns'", 'to': u"orm['irdb.Child']"}),
            'end_as': ('django.db.models.fields.BigIntegerField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'start_as': ('django.db.models.fields.BigIntegerField', [], {})
        },
        u'irdb.childnet': {
            'Meta': {'unique_together': "(('child', 'start_ip', 'end_ip', 'version'),)", 'object_name': 'ChildNet'},
            'child': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'address_ranges'", 'to': u"orm['irdb.Child']"}),
            'end_ip': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'start_ip': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'version': ('rpki.fields.EnumField', [], {})
        },
        u'irdb.client': {
            'Meta': {'unique_together': "(('issuer', 'handle'),)", 'object_name': 'Client'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'clients'", 'to': u"orm['irdb.ServerCA']"}),
            'parent_handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            'sia_base': ('django.db.models.fields.TextField', [], {}),
            'ta': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'})
        },
        u'irdb.eecertificaterequest': {
            'Meta': {'unique_together': "(('issuer', 'gski'),)", 'object_name': 'EECertificateRequest'},
            'cn': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'eku': ('django.db.models.fields.TextField', [], {'null': 'True'}),
            'gski': ('django.db.models.fields.CharField', [], {'max_length': '27'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'ee_certificate_requests'", 'to': u"orm['irdb.ResourceHolderCA']"}),
            'pkcs10': ('rpki.fields.PKCS10Field', [], {'default': 'None', 'blank': 'True'}),
            'sn': ('django.db.models.fields.CharField', [], {'max_length': '64'}),
            'valid_until': ('rpki.fields.SundialField', [], {})
        },
        u'irdb.eecertificaterequestasn': {
            'Meta': {'unique_together': "(('ee_certificate_request', 'start_as', 'end_as'),)", 'object_name': 'EECertificateRequestASN'},
            'ee_certificate_request': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'asns'", 'to': u"orm['irdb.EECertificateRequest']"}),
            'end_as': ('django.db.models.fields.BigIntegerField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'start_as': ('django.db.models.fields.BigIntegerField', [], {})
        },
        u'irdb.eecertificaterequestnet': {
            'Meta': {'unique_together': "(('ee_certificate_request', 'start_ip', 'end_ip', 'version'),)", 'object_name': 'EECertificateRequestNet'},
            'ee_certificate_request': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'address_ranges'", 'to': u"orm['irdb.EECertificateRequest']"}),
            'end_ip': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'start_ip': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'version': ('rpki.fields.EnumField', [], {})
        },
        u'irdb.ghostbusterrequest': {
            'Meta': {'object_name': 'GhostbusterRequest'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'ghostbuster_requests'", 'to': u"orm['irdb.ResourceHolderCA']"}),
            'parent': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'ghostbuster_requests'", 'null': 'True', 'to': u"orm['irdb.Parent']"}),
            'vcard': ('django.db.models.fields.TextField', [], {})
        },
        u'irdb.hostedca': {
            'Meta': {'unique_together': "(('issuer', 'hosted'),)", 'object_name': 'HostedCA'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'hosted': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'hosted_by'", 'unique': 'True', 'to': u"orm['irdb.ResourceHolderCA']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['irdb.ServerCA']"})
        },
        u'irdb.parent': {
            'Meta': {'unique_together': "(('issuer', 'handle'),)", 'object_name': 'Parent', '_ormbases': [u'irdb.Turtle']},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'child_handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            'handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'parents'", 'to': u"orm['irdb.ResourceHolderCA']"}),
            'parent_handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            'referral_authorization': ('rpki.irdb.models.SignedReferralField', [], {'default': 'None', 'null': 'True', 'blank': 'True'}),
            'referrer': ('rpki.irdb.models.HandleField', [], {'max_length': '120', 'null': 'True', 'blank': 'True'}),
            'repository_type': ('rpki.fields.EnumField', [], {}),
            'ta': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            u'turtle_ptr': ('django.db.models.fields.related.OneToOneField', [], {'to': u"orm['irdb.Turtle']", 'unique': 'True', 'primary_key': 'True'})
        },
        u'irdb.referral': {
            'Meta': {'object_name': 'Referral'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'referral_certificate'", 'unique': 'True', 'to': u"orm['irdb.ResourceHolderCA']"}),
            'private_key': ('rpki.fields.KeyField', [], {'default': 'None', 'blank': 'True'})
        },
        u'irdb.repository': {
            'Meta': {'unique_together': "(('issuer', 'handle'),)", 'object_name': 'Repository'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'client_handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            'handle': ('rpki.irdb.models.HandleField', [], {'max_length': '120'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'repositories'", 'to': u"orm['irdb.ResourceHolderCA']"}),
            'service_uri': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'sia_base': ('django.db.models.fields.TextField', [], {}),
            'ta': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'turtle': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'repository'", 'unique': 'True', 'to': u"orm['irdb.Turtle']"})
        },
        u'irdb.resourceholderca': {
            'Meta': {'object_name': 'ResourceHolderCA'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'handle': ('rpki.irdb.models.HandleField', [], {'unique': 'True', 'max_length': '120'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'last_crl_update': ('rpki.fields.SundialField', [], {}),
            'latest_crl': ('rpki.fields.CRLField', [], {'default': 'None', 'blank': 'True'}),
            'next_crl_number': ('django.db.models.fields.BigIntegerField', [], {'default': '1'}),
            'next_crl_update': ('rpki.fields.SundialField', [], {}),
            'next_serial': ('django.db.models.fields.BigIntegerField', [], {'default': '1'}),
            'private_key': ('rpki.fields.KeyField', [], {'default': 'None', 'blank': 'True'})
        },
        u'irdb.resourceholderrevocation': {
            'Meta': {'unique_together': "(('issuer', 'serial'),)", 'object_name': 'ResourceHolderRevocation'},
            'expires': ('rpki.fields.SundialField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'revocations'", 'to': u"orm['irdb.ResourceHolderCA']"}),
            'revoked': ('rpki.fields.SundialField', [], {}),
            'serial': ('django.db.models.fields.BigIntegerField', [], {})
        },
        u'irdb.roarequest': {
            'Meta': {'object_name': 'ROARequest'},
            'asn': ('django.db.models.fields.BigIntegerField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'roa_requests'", 'to': u"orm['irdb.ResourceHolderCA']"})
        },
        u'irdb.roarequestprefix': {
            'Meta': {'unique_together': "(('roa_request', 'version', 'prefix', 'prefixlen', 'max_prefixlen'),)", 'object_name': 'ROARequestPrefix'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'max_prefixlen': ('django.db.models.fields.PositiveSmallIntegerField', [], {}),
            'prefix': ('django.db.models.fields.CharField', [], {'max_length': '40'}),
            'prefixlen': ('django.db.models.fields.PositiveSmallIntegerField', [], {}),
            'roa_request': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'prefixes'", 'to': u"orm['irdb.ROARequest']"}),
            'version': ('rpki.fields.EnumField', [], {})
        },
        u'irdb.rootd': {
            'Meta': {'object_name': 'Rootd', '_ormbases': [u'irdb.Turtle']},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            'issuer': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'rootd'", 'unique': 'True', 'to': u"orm['irdb.ResourceHolderCA']"}),
            'private_key': ('rpki.fields.KeyField', [], {'default': 'None', 'blank': 'True'}),
            u'turtle_ptr': ('django.db.models.fields.related.OneToOneField', [], {'to': u"orm['irdb.Turtle']", 'unique': 'True', 'primary_key': 'True'})
        },
        u'irdb.serverca': {
            'Meta': {'object_name': 'ServerCA'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'last_crl_update': ('rpki.fields.SundialField', [], {}),
            'latest_crl': ('rpki.fields.CRLField', [], {'default': 'None', 'blank': 'True'}),
            'next_crl_number': ('django.db.models.fields.BigIntegerField', [], {'default': '1'}),
            'next_crl_update': ('rpki.fields.SundialField', [], {}),
            'next_serial': ('django.db.models.fields.BigIntegerField', [], {'default': '1'}),
            'private_key': ('rpki.fields.KeyField', [], {'default': 'None', 'blank': 'True'})
        },
        u'irdb.serveree': {
            'Meta': {'unique_together': "(('issuer', 'purpose'),)", 'object_name': 'ServerEE'},
            'certificate': ('rpki.fields.CertificateField', [], {'default': 'None', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'ee_certificates'", 'to': u"orm['irdb.ServerCA']"}),
            'private_key': ('rpki.fields.KeyField', [], {'default': 'None', 'blank': 'True'}),
            'purpose': ('rpki.fields.EnumField', [], {})
        },
        u'irdb.serverrevocation': {
            'Meta': {'unique_together': "(('issuer', 'serial'),)", 'object_name': 'ServerRevocation'},
            'expires': ('rpki.fields.SundialField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issuer': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'revocations'", 'to': u"orm['irdb.ServerCA']"}),
            'revoked': ('rpki.fields.SundialField', [], {}),
            'serial': ('django.db.models.fields.BigIntegerField', [], {})
        },
        u'irdb.turtle': {
            'Meta': {'object_name': 'Turtle'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'service_uri': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        }
    }

    complete_apps = ['irdb']