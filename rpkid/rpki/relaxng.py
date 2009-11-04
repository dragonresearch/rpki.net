# Automatically generated, do not edit.

import lxml.etree

## @var left_right
## Parsed RelaxNG left_right schema
left_right = lxml.etree.RelaxNG(lxml.etree.fromstring('''<?xml version="1.0" encoding="UTF-8"?>
<!--
  $Id: left-right-schema.rnc 2839 2009-10-27 18:53:00Z sra $
  
  RelaxNG Schema for RPKI left-right protocol.
  
  libxml2 (including xmllint) only groks the XML syntax of RelaxNG, so
  run the compact syntax through trang to get XML syntax.
-->
<grammar ns="http://www.hactrn.net/uris/rpki/left-right-spec/" xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">
  <!-- Top level PDU -->
  <start>
    <element name="msg">
      <attribute name="version">
        <data type="positiveInteger">
          <param name="maxInclusive">1</param>
        </data>
      </attribute>
      <choice>
        <group>
          <attribute name="type">
            <value>query</value>
          </attribute>
          <zeroOrMore>
            <ref name="query_elt"/>
          </zeroOrMore>
        </group>
        <group>
          <attribute name="type">
            <value>reply</value>
          </attribute>
          <zeroOrMore>
            <ref name="reply_elt"/>
          </zeroOrMore>
        </group>
      </choice>
    </element>
  </start>
  <!-- PDUs allowed in a query -->
  <define name="query_elt" combine="choice">
    <ref name="self_query"/>
  </define>
  <define name="query_elt" combine="choice">
    <ref name="bsc_query"/>
  </define>
  <define name="query_elt" combine="choice">
    <ref name="parent_query"/>
  </define>
  <define name="query_elt" combine="choice">
    <ref name="child_query"/>
  </define>
  <define name="query_elt" combine="choice">
    <ref name="repository_query"/>
  </define>
  <define name="query_elt" combine="choice">
    <ref name="list_roa_requests_query"/>
  </define>
  <define name="query_elt" combine="choice">
    <ref name="list_resources_query"/>
  </define>
  <define name="query_elt" combine="choice">
    <ref name="list_published_objects_query"/>
  </define>
  <!-- PDUs allowed in a reply -->
  <define name="reply_elt" combine="choice">
    <ref name="self_reply"/>
  </define>
  <define name="reply_elt" combine="choice">
    <ref name="bsc_reply"/>
  </define>
  <define name="reply_elt" combine="choice">
    <ref name="parent_reply"/>
  </define>
  <define name="reply_elt" combine="choice">
    <ref name="child_reply"/>
  </define>
  <define name="reply_elt" combine="choice">
    <ref name="repository_reply"/>
  </define>
  <define name="reply_elt" combine="choice">
    <ref name="list_resources_reply"/>
  </define>
  <define name="reply_elt" combine="choice">
    <ref name="list_roa_requests_reply"/>
  </define>
  <define name="reply_elt" combine="choice">
    <ref name="list_published_objects_reply"/>
  </define>
  <define name="reply_elt" combine="choice">
    <ref name="report_error_reply"/>
  </define>
  <!-- Tag attributes for bulk operations -->
  <define name="tag">
    <optional>
      <attribute name="tag">
        <data type="token">
          <param name="maxLength">1024</param>
        </data>
      </attribute>
    </optional>
  </define>
  <!--
    Combinations of action and type attributes used in later definitions.
    The same patterns repeat in most of the elements in this protocol.
  -->
  <define name="ctl_create">
    <attribute name="action">
      <value>create</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_set">
    <attribute name="action">
      <value>set</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_get">
    <attribute name="action">
      <value>get</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_list">
    <attribute name="action">
      <value>list</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_destroy">
    <attribute name="action">
      <value>destroy</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <!-- Base64 encoded DER stuff -->
  <define name="base64">
    <data type="base64Binary">
      <param name="maxLength">512000</param>
    </data>
  </define>
  <!--
    Base definition for all fields that are really just SQL primary indices
    sql_id = xsd:nonNegativeInteger
  -->
  <!--
    ...except that fields containing SQL primary indicies don't belong
    in this protocol, so they're turninging into handles.
    Length restriction is a MySQL implementation issue.
    Handles are case-insensitive (because SQL is, among other reasons).
  -->
  <define name="object_handle">
    <data type="string">
      <param name="maxLength">255</param>
      <param name="pattern">[\-_A-Za-z0-9]*</param>
    </data>
  </define>
  <!-- URIs -->
  <define name="uri">
    <data type="anyURI">
      <param name="maxLength">4096</param>
    </data>
  </define>
  <!-- Name fields imported from up-down protocol -->
  <define name="up_down_name">
    <data type="token">
      <param name="maxLength">1024</param>
    </data>
  </define>
  <!-- Resource lists -->
  <define name="asn_list">
    <data type="string">
      <param name="maxLength">512000</param>
      <param name="pattern">[\-,0-9]*</param>
    </data>
  </define>
  <define name="ipv4_list">
    <data type="string">
      <param name="maxLength">512000</param>
      <param name="pattern">[\-,0-9/.]*</param>
    </data>
  </define>
  <define name="ipv6_list">
    <data type="string">
      <param name="maxLength">512000</param>
      <param name="pattern">[\-,0-9/:a-fA-F]*</param>
    </data>
  </define>
  <!-- <self/> element -->
  <define name="self_bool">
    <optional>
      <attribute name="rekey">
        <value>yes</value>
      </attribute>
    </optional>
    <optional>
      <attribute name="reissue">
        <value>yes</value>
      </attribute>
    </optional>
    <optional>
      <attribute name="revoke">
        <value>yes</value>
      </attribute>
    </optional>
    <optional>
      <attribute name="run_now">
        <value>yes</value>
      </attribute>
    </optional>
    <optional>
      <attribute name="publish_world_now">
        <value>yes</value>
      </attribute>
    </optional>
    <optional>
      <attribute name="revoke_forgotten">
        <value>yes</value>
      </attribute>
    </optional>
  </define>
  <define name="self_payload">
    <optional>
      <attribute name="use_hsm">
        <choice>
          <value>yes</value>
          <value>no</value>
        </choice>
      </attribute>
    </optional>
    <optional>
      <attribute name="crl_interval">
        <data type="positiveInteger"/>
      </attribute>
    </optional>
    <optional>
      <attribute name="regen_margin">
        <data type="positiveInteger"/>
      </attribute>
    </optional>
    <optional>
      <element name="bpki_cert">
        <ref name="base64"/>
      </element>
    </optional>
    <optional>
      <element name="bpki_glue">
        <ref name="base64"/>
      </element>
    </optional>
  </define>
  <define name="self_handle">
    <attribute name="self_handle">
      <ref name="object_handle"/>
    </attribute>
  </define>
  <define name="self_query" combine="choice">
    <element name="self">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="self_bool"/>
      <ref name="self_payload"/>
    </element>
  </define>
  <define name="self_reply" combine="choice">
    <element name="self">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="self_query" combine="choice">
    <element name="self">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="self_bool"/>
      <ref name="self_payload"/>
    </element>
  </define>
  <define name="self_reply" combine="choice">
    <element name="self">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="self_query" combine="choice">
    <element name="self">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="self_reply" combine="choice">
    <element name="self">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="self_payload"/>
    </element>
  </define>
  <define name="self_query" combine="choice">
    <element name="self">
      <ref name="ctl_list"/>
    </element>
  </define>
  <define name="self_reply" combine="choice">
    <element name="self">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
      <ref name="self_payload"/>
    </element>
  </define>
  <define name="self_query" combine="choice">
    <element name="self">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="self_reply" combine="choice">
    <element name="self">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <!-- <bsc/> element.  Key parameters hardwired for now. -->
  <define name="bsc_bool">
    <optional>
      <attribute name="generate_keypair">
        <value>yes</value>
      </attribute>
      <optional>
        <attribute name="key_type">
          <value>rsa</value>
        </attribute>
      </optional>
      <optional>
        <attribute name="hash_alg">
          <value>sha256</value>
        </attribute>
      </optional>
      <optional>
        <attribute name="key_length">
          <value>2048</value>
        </attribute>
      </optional>
    </optional>
  </define>
  <define name="bsc_handle">
    <attribute name="bsc_handle">
      <ref name="object_handle"/>
    </attribute>
  </define>
  <define name="bsc_payload">
    <optional>
      <element name="signing_cert">
        <ref name="base64"/>
      </element>
    </optional>
    <optional>
      <element name="signing_cert_crl">
        <ref name="base64"/>
      </element>
    </optional>
  </define>
  <define name="bsc_pkcs10">
    <optional>
      <element name="pkcs10_request">
        <ref name="base64"/>
      </element>
    </optional>
  </define>
  <define name="bsc_query" combine="choice">
    <element name="bsc">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
      <ref name="bsc_bool"/>
      <ref name="bsc_payload"/>
    </element>
  </define>
  <define name="bsc_reply" combine="choice">
    <element name="bsc">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
      <ref name="bsc_pkcs10"/>
    </element>
  </define>
  <define name="bsc_query" combine="choice">
    <element name="bsc">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
      <ref name="bsc_bool"/>
      <ref name="bsc_payload"/>
    </element>
  </define>
  <define name="bsc_reply" combine="choice">
    <element name="bsc">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
      <ref name="bsc_pkcs10"/>
    </element>
  </define>
  <define name="bsc_query" combine="choice">
    <element name="bsc">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
    </element>
  </define>
  <define name="bsc_reply" combine="choice">
    <element name="bsc">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
      <ref name="bsc_payload"/>
      <ref name="bsc_pkcs10"/>
    </element>
  </define>
  <define name="bsc_query" combine="choice">
    <element name="bsc">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="bsc_reply" combine="choice">
    <element name="bsc">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
      <ref name="bsc_payload"/>
      <ref name="bsc_pkcs10"/>
    </element>
  </define>
  <define name="bsc_query" combine="choice">
    <element name="bsc">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
    </element>
  </define>
  <define name="bsc_reply" combine="choice">
    <element name="bsc">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
      <ref name="bsc_handle"/>
    </element>
  </define>
  <!-- <parent/> element -->
  <define name="parent_handle">
    <attribute name="parent_handle">
      <ref name="object_handle"/>
    </attribute>
  </define>
  <define name="parent_bool">
    <optional>
      <attribute name="rekey">
        <value>yes</value>
      </attribute>
    </optional>
    <optional>
      <attribute name="reissue">
        <value>yes</value>
      </attribute>
    </optional>
    <optional>
      <attribute name="revoke">
        <value>yes</value>
      </attribute>
    </optional>
    <optional>
      <attribute name="revoke_forgotten">
        <value>yes</value>
      </attribute>
    </optional>
  </define>
  <define name="parent_payload">
    <optional>
      <attribute name="peer_contact_uri">
        <ref name="uri"/>
      </attribute>
    </optional>
    <optional>
      <attribute name="sia_base">
        <ref name="uri"/>
      </attribute>
    </optional>
    <optional>
      <ref name="bsc_handle"/>
    </optional>
    <optional>
      <ref name="repository_handle"/>
    </optional>
    <optional>
      <attribute name="sender_name">
        <ref name="up_down_name"/>
      </attribute>
    </optional>
    <optional>
      <attribute name="recipient_name">
        <ref name="up_down_name"/>
      </attribute>
    </optional>
    <optional>
      <element name="bpki_cms_cert">
        <ref name="base64"/>
      </element>
    </optional>
    <optional>
      <element name="bpki_cms_glue">
        <ref name="base64"/>
      </element>
    </optional>
    <optional>
      <element name="bpki_https_cert">
        <ref name="base64"/>
      </element>
    </optional>
    <optional>
      <element name="bpki_https_glue">
        <ref name="base64"/>
      </element>
    </optional>
  </define>
  <define name="parent_query" combine="choice">
    <element name="parent">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
      <ref name="parent_bool"/>
      <ref name="parent_payload"/>
    </element>
  </define>
  <define name="parent_reply" combine="choice">
    <element name="parent">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
    </element>
  </define>
  <define name="parent_query" combine="choice">
    <element name="parent">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
      <ref name="parent_bool"/>
      <ref name="parent_payload"/>
    </element>
  </define>
  <define name="parent_reply" combine="choice">
    <element name="parent">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
    </element>
  </define>
  <define name="parent_query" combine="choice">
    <element name="parent">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
    </element>
  </define>
  <define name="parent_reply" combine="choice">
    <element name="parent">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
      <ref name="parent_payload"/>
    </element>
  </define>
  <define name="parent_query" combine="choice">
    <element name="parent">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="parent_reply" combine="choice">
    <element name="parent">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
      <ref name="parent_payload"/>
    </element>
  </define>
  <define name="parent_query" combine="choice">
    <element name="parent">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
    </element>
  </define>
  <define name="parent_reply" combine="choice">
    <element name="parent">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
      <ref name="parent_handle"/>
    </element>
  </define>
  <!-- <child/> element -->
  <define name="child_handle">
    <attribute name="child_handle">
      <ref name="object_handle"/>
    </attribute>
  </define>
  <define name="child_bool">
    <optional>
      <attribute name="reissue">
        <value>yes</value>
      </attribute>
    </optional>
  </define>
  <define name="child_payload">
    <optional>
      <ref name="bsc_handle"/>
    </optional>
    <optional>
      <element name="bpki_cert">
        <ref name="base64"/>
      </element>
    </optional>
    <optional>
      <element name="bpki_glue">
        <ref name="base64"/>
      </element>
    </optional>
  </define>
  <define name="child_query" combine="choice">
    <element name="child">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
      <ref name="child_bool"/>
      <ref name="child_payload"/>
    </element>
  </define>
  <define name="child_reply" combine="choice">
    <element name="child">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
    </element>
  </define>
  <define name="child_query" combine="choice">
    <element name="child">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
      <ref name="child_bool"/>
      <ref name="child_payload"/>
    </element>
  </define>
  <define name="child_reply" combine="choice">
    <element name="child">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
    </element>
  </define>
  <define name="child_query" combine="choice">
    <element name="child">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
    </element>
  </define>
  <define name="child_reply" combine="choice">
    <element name="child">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
      <ref name="child_payload"/>
    </element>
  </define>
  <define name="child_query" combine="choice">
    <element name="child">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="child_reply" combine="choice">
    <element name="child">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
      <ref name="child_payload"/>
    </element>
  </define>
  <define name="child_query" combine="choice">
    <element name="child">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
    </element>
  </define>
  <define name="child_reply" combine="choice">
    <element name="child">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
    </element>
  </define>
  <!-- <repository/> element -->
  <define name="repository_handle">
    <attribute name="repository_handle">
      <ref name="object_handle"/>
    </attribute>
  </define>
  <define name="repository_payload">
    <optional>
      <attribute name="peer_contact_uri">
        <ref name="uri"/>
      </attribute>
    </optional>
    <optional>
      <ref name="bsc_handle"/>
    </optional>
    <optional>
      <element name="bpki_cert">
        <ref name="base64"/>
      </element>
    </optional>
    <optional>
      <element name="bpki_glue">
        <ref name="base64"/>
      </element>
    </optional>
  </define>
  <define name="repository_query" combine="choice">
    <element name="repository">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
      <ref name="repository_payload"/>
    </element>
  </define>
  <define name="repository_reply" combine="choice">
    <element name="repository">
      <ref name="ctl_create"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
    </element>
  </define>
  <define name="repository_query" combine="choice">
    <element name="repository">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
      <ref name="repository_payload"/>
    </element>
  </define>
  <define name="repository_reply" combine="choice">
    <element name="repository">
      <ref name="ctl_set"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
    </element>
  </define>
  <define name="repository_query" combine="choice">
    <element name="repository">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
    </element>
  </define>
  <define name="repository_reply" combine="choice">
    <element name="repository">
      <ref name="ctl_get"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
      <ref name="repository_payload"/>
    </element>
  </define>
  <define name="repository_query" combine="choice">
    <element name="repository">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="repository_reply" combine="choice">
    <element name="repository">
      <ref name="ctl_list"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
      <ref name="repository_payload"/>
    </element>
  </define>
  <define name="repository_query" combine="choice">
    <element name="repository">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
    </element>
  </define>
  <define name="repository_reply" combine="choice">
    <element name="repository">
      <ref name="ctl_destroy"/>
      <ref name="self_handle"/>
      <ref name="repository_handle"/>
    </element>
  </define>
  <!-- <list_resources/> element -->
  <define name="list_resources_query">
    <element name="list_resources">
      <ref name="tag"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
    </element>
  </define>
  <define name="list_resources_reply">
    <element name="list_resources">
      <ref name="tag"/>
      <ref name="self_handle"/>
      <ref name="child_handle"/>
      <attribute name="valid_until">
        <data type="dateTime">
          <param name="pattern">.*Z</param>
        </data>
      </attribute>
      <optional>
        <attribute name="asn">
          <ref name="asn_list"/>
        </attribute>
      </optional>
      <optional>
        <attribute name="ipv4">
          <ref name="ipv4_list"/>
        </attribute>
      </optional>
      <optional>
        <attribute name="ipv6">
          <ref name="ipv6_list"/>
        </attribute>
      </optional>
    </element>
  </define>
  <!-- <list_roa_requests/> element -->
  <define name="list_roa_requests_query">
    <element name="list_roa_requests">
      <ref name="tag"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="list_roa_requests_reply">
    <element name="list_roa_requests">
      <ref name="tag"/>
      <ref name="self_handle"/>
      <attribute name="asn">
        <data type="positiveInteger"/>
      </attribute>
      <optional>
        <attribute name="ipv4">
          <ref name="ipv4_list"/>
        </attribute>
      </optional>
      <optional>
        <attribute name="ipv6">
          <ref name="ipv6_list"/>
        </attribute>
      </optional>
    </element>
  </define>
  <!-- <list_published_objects/> element -->
  <define name="list_published_objects_query">
    <element name="list_published_objects">
      <ref name="tag"/>
      <ref name="self_handle"/>
    </element>
  </define>
  <define name="list_published_objects_reply">
    <element name="list_published_objects">
      <ref name="tag"/>
      <ref name="self_handle"/>
      <attribute name="uri">
        <ref name="uri"/>
      </attribute>
      <ref name="base64"/>
    </element>
  </define>
  <!-- <report_error/> element -->
  <define name="error">
    <data type="token">
      <param name="maxLength">1024</param>
    </data>
  </define>
  <define name="report_error_reply">
    <element name="report_error">
      <ref name="tag"/>
      <optional>
        <ref name="self_handle"/>
      </optional>
      <attribute name="error_code">
        <ref name="error"/>
      </attribute>
      <optional>
        <data type="string">
          <param name="maxLength">512000</param>
        </data>
      </optional>
    </element>
  </define>
</grammar>
<!--
  Local Variables:
  indent-tabs-mode: nil
  End:
-->
'''))

## @var up_down
## Parsed RelaxNG up_down schema
up_down = lxml.etree.RelaxNG(lxml.etree.fromstring('''<?xml version="1.0" encoding="UTF-8"?>
<!--
  $Id: up-down-schema.rnc 2839 2009-10-27 18:53:00Z sra $
  
  RelaxNG Scheme for up-down protocol, extracted from APNIC Wiki.
  
  libxml2 (including xmllint) only groks the XML syntax of RelaxNG, so
  run the compact syntax through trang to get XML syntax.
-->
<grammar ns="http://www.apnic.net/specs/rescerts/up-down/" xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">
  <start>
    <element name="message">
      <attribute name="version">
        <data type="positiveInteger">
          <param name="maxInclusive">1</param>
        </data>
      </attribute>
      <attribute name="sender">
        <data type="token">
          <param name="maxLength">1024</param>
        </data>
      </attribute>
      <attribute name="recipient">
        <data type="token">
          <param name="maxLength">1024</param>
        </data>
      </attribute>
      <ref name="payload"/>
    </element>
  </start>
  <define name="payload" combine="choice">
    <attribute name="type">
      <value>list</value>
    </attribute>
    <ref name="list_request"/>
  </define>
  <define name="payload" combine="choice">
    <attribute name="type">
      <value>list_response</value>
    </attribute>
    <ref name="list_response"/>
  </define>
  <define name="payload" combine="choice">
    <attribute name="type">
      <value>issue</value>
    </attribute>
    <ref name="issue_request"/>
  </define>
  <define name="payload" combine="choice">
    <attribute name="type">
      <value>issue_response</value>
    </attribute>
    <ref name="issue_response"/>
  </define>
  <define name="payload" combine="choice">
    <attribute name="type">
      <value>revoke</value>
    </attribute>
    <ref name="revoke_request"/>
  </define>
  <define name="payload" combine="choice">
    <attribute name="type">
      <value>revoke_response</value>
    </attribute>
    <ref name="revoke_response"/>
  </define>
  <define name="payload" combine="choice">
    <attribute name="type">
      <value>error_response</value>
    </attribute>
    <ref name="error_response"/>
  </define>
  <define name="list_request">
    <empty/>
  </define>
  <define name="list_response">
    <zeroOrMore>
      <ref name="class"/>
    </zeroOrMore>
  </define>
  <define name="class">
    <element name="class">
      <attribute name="class_name">
        <data type="token">
          <param name="maxLength">1024</param>
        </data>
      </attribute>
      <attribute name="cert_url">
        <data type="string">
          <param name="maxLength">4096</param>
        </data>
      </attribute>
      <attribute name="resource_set_as">
        <data type="string">
          <param name="maxLength">512000</param>
          <param name="pattern">[\-,0-9]*</param>
        </data>
      </attribute>
      <attribute name="resource_set_ipv4">
        <data type="string">
          <param name="maxLength">512000</param>
          <param name="pattern">[\-,/.0-9]*</param>
        </data>
      </attribute>
      <attribute name="resource_set_ipv6">
        <data type="string">
          <param name="maxLength">512000</param>
          <param name="pattern">[\-,/:0-9a-fA-F]*</param>
        </data>
      </attribute>
      <optional>
        <attribute name="resource_set_notafter">
          <data type="dateTime">
            <param name="pattern">.*Z</param>
          </data>
        </attribute>
      </optional>
      <optional>
        <attribute name="suggested_sia_head">
          <data type="anyURI">
            <param name="maxLength">1024</param>
            <param name="pattern">rsync://.+</param>
          </data>
        </attribute>
      </optional>
      <zeroOrMore>
        <element name="certificate">
          <attribute name="cert_url">
            <data type="string">
              <param name="maxLength">4096</param>
            </data>
          </attribute>
          <optional>
            <attribute name="req_resource_set_as">
              <data type="string">
                <param name="maxLength">512000</param>
                <param name="pattern">[\-,0-9]*</param>
              </data>
            </attribute>
          </optional>
          <optional>
            <attribute name="req_resource_set_ipv4">
              <data type="string">
                <param name="maxLength">512000</param>
                <param name="pattern">[\-,/.0-9]*</param>
              </data>
            </attribute>
          </optional>
          <optional>
            <attribute name="req_resource_set_ipv6">
              <data type="string">
                <param name="maxLength">512000</param>
                <param name="pattern">[\-,/:0-9a-fA-F]*</param>
              </data>
            </attribute>
          </optional>
          <data type="base64Binary">
            <param name="maxLength">512000</param>
          </data>
        </element>
      </zeroOrMore>
      <element name="issuer">
        <data type="base64Binary">
          <param name="maxLength">512000</param>
        </data>
      </element>
    </element>
  </define>
  <define name="issue_request">
    <element name="request">
      <attribute name="class_name">
        <data type="token">
          <param name="maxLength">1024</param>
        </data>
      </attribute>
      <optional>
        <attribute name="req_resource_set_as">
          <data type="string">
            <param name="maxLength">512000</param>
            <param name="pattern">[\-,0-9]*</param>
          </data>
        </attribute>
      </optional>
      <optional>
        <attribute name="req_resource_set_ipv4">
          <data type="string">
            <param name="maxLength">512000</param>
            <param name="pattern">[\-,/.0-9]*</param>
          </data>
        </attribute>
      </optional>
      <optional>
        <attribute name="req_resource_set_ipv6">
          <data type="string">
            <param name="maxLength">512000</param>
            <param name="pattern">[\-,/:0-9a-fA-F]*</param>
          </data>
        </attribute>
      </optional>
      <data type="base64Binary">
        <param name="maxLength">512000</param>
      </data>
    </element>
  </define>
  <define name="issue_response">
    <ref name="class"/>
  </define>
  <define name="revoke_request">
    <ref name="revocation"/>
  </define>
  <define name="revoke_response">
    <ref name="revocation"/>
  </define>
  <define name="revocation">
    <element name="key">
      <attribute name="class_name">
        <data type="token">
          <param name="maxLength">1024</param>
        </data>
      </attribute>
      <attribute name="ski">
        <data type="token">
          <param name="maxLength">1024</param>
        </data>
      </attribute>
    </element>
  </define>
  <define name="error_response">
    <element name="status">
      <data type="positiveInteger">
        <param name="maxInclusive">999999999999999</param>
      </data>
    </element>
    <optional>
      <element name="description">
        <attribute name="xml:lang">
          <data type="language"/>
        </attribute>
        <data type="string">
          <param name="maxLength">1024</param>
        </data>
      </element>
    </optional>
  </define>
</grammar>
<!--
  Local Variables:
  indent-tabs-mode: nil
  End:
-->
'''))

## @var publication
## Parsed RelaxNG publication schema
publication = lxml.etree.RelaxNG(lxml.etree.fromstring('''<?xml version="1.0" encoding="UTF-8"?>
<!--
  $Id: publication-schema.rnc 2839 2009-10-27 18:53:00Z sra $
  
  RelaxNG Schema for RPKI publication protocol.
  
  libxml2 (including xmllint) only groks the XML syntax of RelaxNG, so
  run the compact syntax through trang to get XML syntax.
-->
<grammar ns="http://www.hactrn.net/uris/rpki/publication-spec/" xmlns="http://relaxng.org/ns/structure/1.0" datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes">
  <!-- Top level PDU -->
  <start>
    <element name="msg">
      <attribute name="version">
        <data type="positiveInteger">
          <param name="maxInclusive">1</param>
        </data>
      </attribute>
      <choice>
        <group>
          <attribute name="type">
            <value>query</value>
          </attribute>
          <zeroOrMore>
            <ref name="query_elt"/>
          </zeroOrMore>
        </group>
        <group>
          <attribute name="type">
            <value>reply</value>
          </attribute>
          <zeroOrMore>
            <ref name="reply_elt"/>
          </zeroOrMore>
        </group>
      </choice>
    </element>
  </start>
  <!-- PDUs allowed in a query -->
  <define name="query_elt">
    <choice>
      <ref name="config_query"/>
      <ref name="client_query"/>
      <ref name="certificate_query"/>
      <ref name="crl_query"/>
      <ref name="manifest_query"/>
      <ref name="roa_query"/>
    </choice>
  </define>
  <!-- PDUs allowed in a reply -->
  <define name="reply_elt">
    <choice>
      <ref name="config_reply"/>
      <ref name="client_reply"/>
      <ref name="certificate_reply"/>
      <ref name="crl_reply"/>
      <ref name="manifest_reply"/>
      <ref name="roa_reply"/>
      <ref name="report_error_reply"/>
    </choice>
  </define>
  <!-- Tag attributes for bulk operations -->
  <define name="tag">
    <attribute name="tag">
      <data type="token">
        <param name="maxLength">1024</param>
      </data>
    </attribute>
  </define>
  <!-- Base64 encoded DER stuff -->
  <define name="base64">
    <data type="base64Binary">
      <param name="maxLength">512000</param>
    </data>
  </define>
  <!-- Publication URLs -->
  <define name="uri_t">
    <data type="anyURI">
      <param name="maxLength">4096</param>
    </data>
  </define>
  <define name="uri">
    <attribute name="uri">
      <ref name="uri_t"/>
    </attribute>
  </define>
  <!--
    Handles on remote objects (replaces passing raw SQL IDs).  NB:
    Unlike the up-down protocol, handles in this protocol allow "/" as a
    hierarchy delimiter.
  -->
  <define name="object_handle">
    <data type="string">
      <param name="maxLength">255</param>
      <param name="pattern">[\-_A-Za-z0-9/]*</param>
    </data>
  </define>
  <!--
    <config/> element (use restricted to repository operator)
    config_handle attribute, create, list, and destroy commands omitted deliberately, see code for details
  -->
  <define name="config_payload">
    <optional>
      <element name="bpki_crl">
        <ref name="base64"/>
      </element>
    </optional>
  </define>
  <define name="config_query" combine="choice">
    <element name="config">
      <attribute name="action">
        <value>set</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="config_payload"/>
    </element>
  </define>
  <define name="config_reply" combine="choice">
    <element name="config">
      <attribute name="action">
        <value>set</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
    </element>
  </define>
  <define name="config_query" combine="choice">
    <element name="config">
      <attribute name="action">
        <value>get</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
    </element>
  </define>
  <define name="config_reply" combine="choice">
    <element name="config">
      <attribute name="action">
        <value>get</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="config_payload"/>
    </element>
  </define>
  <!-- <client/> element (use restricted to repository operator) -->
  <define name="client_handle">
    <attribute name="client_handle">
      <ref name="object_handle"/>
    </attribute>
  </define>
  <define name="client_payload">
    <optional>
      <attribute name="base_uri">
        <ref name="uri_t"/>
      </attribute>
    </optional>
    <optional>
      <element name="bpki_cert">
        <ref name="base64"/>
      </element>
    </optional>
    <optional>
      <element name="bpki_glue">
        <ref name="base64"/>
      </element>
    </optional>
  </define>
  <define name="client_query" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>create</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
      <ref name="client_payload"/>
    </element>
  </define>
  <define name="client_reply" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>create</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
    </element>
  </define>
  <define name="client_query" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>set</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
      <ref name="client_payload"/>
    </element>
  </define>
  <define name="client_reply" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>set</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
    </element>
  </define>
  <define name="client_query" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>get</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
    </element>
  </define>
  <define name="client_reply" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>get</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
      <ref name="client_payload"/>
    </element>
  </define>
  <define name="client_query" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>list</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
    </element>
  </define>
  <define name="client_reply" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>list</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
      <ref name="client_payload"/>
    </element>
  </define>
  <define name="client_query" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>destroy</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
    </element>
  </define>
  <define name="client_reply" combine="choice">
    <element name="client">
      <attribute name="action">
        <value>destroy</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="client_handle"/>
    </element>
  </define>
  <!-- <certificate/> element -->
  <define name="certificate_query" combine="choice">
    <element name="certificate">
      <attribute name="action">
        <value>publish</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
      <ref name="base64"/>
    </element>
  </define>
  <define name="certificate_reply" combine="choice">
    <element name="certificate">
      <attribute name="action">
        <value>publish</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <define name="certificate_query" combine="choice">
    <element name="certificate">
      <attribute name="action">
        <value>withdraw</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <define name="certificate_reply" combine="choice">
    <element name="certificate">
      <attribute name="action">
        <value>withdraw</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <!-- <crl/> element -->
  <define name="crl_query" combine="choice">
    <element name="crl">
      <attribute name="action">
        <value>publish</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
      <ref name="base64"/>
    </element>
  </define>
  <define name="crl_reply" combine="choice">
    <element name="crl">
      <attribute name="action">
        <value>publish</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <define name="crl_query" combine="choice">
    <element name="crl">
      <attribute name="action">
        <value>withdraw</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <define name="crl_reply" combine="choice">
    <element name="crl">
      <attribute name="action">
        <value>withdraw</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <!-- <manifest/> element -->
  <define name="manifest_query" combine="choice">
    <element name="manifest">
      <attribute name="action">
        <value>publish</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
      <ref name="base64"/>
    </element>
  </define>
  <define name="manifest_reply" combine="choice">
    <element name="manifest">
      <attribute name="action">
        <value>publish</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <define name="manifest_query" combine="choice">
    <element name="manifest">
      <attribute name="action">
        <value>withdraw</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <define name="manifest_reply" combine="choice">
    <element name="manifest">
      <attribute name="action">
        <value>withdraw</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <!-- <roa/> element -->
  <define name="roa_query" combine="choice">
    <element name="roa">
      <attribute name="action">
        <value>publish</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
      <ref name="base64"/>
    </element>
  </define>
  <define name="roa_reply" combine="choice">
    <element name="roa">
      <attribute name="action">
        <value>publish</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <define name="roa_query" combine="choice">
    <element name="roa">
      <attribute name="action">
        <value>withdraw</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <define name="roa_reply" combine="choice">
    <element name="roa">
      <attribute name="action">
        <value>withdraw</value>
      </attribute>
      <optional>
        <ref name="tag"/>
      </optional>
      <ref name="uri"/>
    </element>
  </define>
  <!-- <report_error/> element -->
  <define name="error">
    <data type="token">
      <param name="maxLength">1024</param>
    </data>
  </define>
  <define name="report_error_reply">
    <element name="report_error">
      <optional>
        <ref name="tag"/>
      </optional>
      <attribute name="error_code">
        <ref name="error"/>
      </attribute>
      <optional>
        <data type="string">
          <param name="maxLength">512000</param>
        </data>
      </optional>
    </element>
  </define>
</grammar>
<!--
  Local Variables:
  indent-tabs-mode: nil
  End:
-->
'''))

