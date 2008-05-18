# Automatically generated, do not edit.

import lxml.etree

## @var left_right
## Parsed RelaxNG left_right schema
left_right = lxml.etree.RelaxNG(lxml.etree.fromstring('''<?xml version="1.0" encoding="UTF-8"?>
<!--
  $Id: left-right-schema.rnc 1800 2008-05-18 00:11:59Z sra $
  
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
      <zeroOrMore>
        <choice>
          <ref name="self_elt"/>
          <ref name="bsc_elt"/>
          <ref name="parent_elt"/>
          <ref name="child_elt"/>
          <ref name="repository_elt"/>
          <ref name="route_origin_elt"/>
          <ref name="list_resources_elt"/>
          <ref name="report_error_elt"/>
        </choice>
      </zeroOrMore>
    </element>
  </start>
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
  <define name="ctl_cq">
    <attribute name="action">
      <value>create</value>
    </attribute>
    <attribute name="type">
      <value>query</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_sq">
    <attribute name="action">
      <value>set</value>
    </attribute>
    <attribute name="type">
      <value>query</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_gq">
    <attribute name="action">
      <value>get</value>
    </attribute>
    <attribute name="type">
      <value>query</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_lq">
    <attribute name="action">
      <value>list</value>
    </attribute>
    <attribute name="type">
      <value>query</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_dq">
    <attribute name="action">
      <value>destroy</value>
    </attribute>
    <attribute name="type">
      <value>query</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_cr">
    <attribute name="action">
      <value>create</value>
    </attribute>
    <attribute name="type">
      <value>reply</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_sr">
    <attribute name="action">
      <value>set</value>
    </attribute>
    <attribute name="type">
      <value>reply</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_gr">
    <attribute name="action">
      <value>get</value>
    </attribute>
    <attribute name="type">
      <value>reply</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_lr">
    <attribute name="action">
      <value>list</value>
    </attribute>
    <attribute name="type">
      <value>reply</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <define name="ctl_dr">
    <attribute name="action">
      <value>destroy</value>
    </attribute>
    <attribute name="type">
      <value>reply</value>
    </attribute>
    <ref name="tag"/>
  </define>
  <!-- Base64 encoded DER stuff -->
  <define name="base64">
    <data type="base64Binary">
      <param name="maxLength">512000</param>
    </data>
  </define>
  <!-- Base definition for all fields that are really just SQL primary indices -->
  <define name="sql_id">
    <data type="nonNegativeInteger"/>
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
      <attribute name="clear_extension_preferences">
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
    <zeroOrMore>
      <element name="extension_preference">
        <attribute name="name">
          <data type="token">
            <param name="maxLength">1024</param>
          </data>
        </attribute>
        <data type="string">
          <param name="maxLength">512000</param>
        </data>
      </element>
    </zeroOrMore>
  </define>
  <define name="self_id">
    <attribute name="self_id">
      <ref name="sql_id"/>
    </attribute>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_cq"/>
      <ref name="self_bool"/>
      <ref name="self_payload"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_cr"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_sq"/>
      <ref name="self_id"/>
      <ref name="self_bool"/>
      <ref name="self_payload"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_sr"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_gq"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_gr"/>
      <ref name="self_id"/>
      <ref name="self_payload"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_lq"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_lr"/>
      <ref name="self_id"/>
      <ref name="self_payload"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_dq"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="self_elt" combine="choice">
    <element name="self">
      <ref name="ctl_dr"/>
      <ref name="self_id"/>
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
  <define name="bsc_id">
    <attribute name="bsc_id">
      <ref name="sql_id"/>
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
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_cq"/>
      <ref name="self_id"/>
      <ref name="bsc_bool"/>
      <ref name="bsc_payload"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_cr"/>
      <ref name="self_id"/>
      <ref name="bsc_id"/>
      <ref name="bsc_pkcs10"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_sq"/>
      <ref name="self_id"/>
      <ref name="bsc_id"/>
      <ref name="bsc_bool"/>
      <ref name="bsc_payload"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_sr"/>
      <ref name="self_id"/>
      <ref name="bsc_id"/>
      <ref name="bsc_pkcs10"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_gq"/>
      <ref name="self_id"/>
      <ref name="bsc_id"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_gr"/>
      <ref name="self_id"/>
      <ref name="bsc_id"/>
      <ref name="bsc_payload"/>
      <ref name="bsc_pkcs10"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_lq"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_lr"/>
      <ref name="self_id"/>
      <ref name="bsc_id"/>
      <ref name="bsc_payload"/>
      <ref name="bsc_pkcs10"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_dq"/>
      <ref name="self_id"/>
      <ref name="bsc_id"/>
    </element>
  </define>
  <define name="bsc_elt" combine="choice">
    <element name="bsc">
      <ref name="ctl_dr"/>
      <ref name="self_id"/>
      <ref name="bsc_id"/>
    </element>
  </define>
  <!-- <parent/> element -->
  <define name="parent_id">
    <attribute name="parent_id">
      <ref name="sql_id"/>
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
      <ref name="bsc_id"/>
    </optional>
    <optional>
      <ref name="repository_id"/>
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
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_cq"/>
      <ref name="self_id"/>
      <ref name="parent_bool"/>
      <ref name="parent_payload"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_cr"/>
      <ref name="self_id"/>
      <ref name="parent_id"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_sq"/>
      <ref name="self_id"/>
      <ref name="parent_id"/>
      <ref name="parent_bool"/>
      <ref name="parent_payload"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_sr"/>
      <ref name="self_id"/>
      <ref name="parent_id"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_gq"/>
      <ref name="self_id"/>
      <ref name="parent_id"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_gr"/>
      <ref name="self_id"/>
      <ref name="parent_id"/>
      <ref name="parent_payload"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_lq"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_lr"/>
      <ref name="self_id"/>
      <ref name="parent_id"/>
      <ref name="parent_payload"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_dq"/>
      <ref name="self_id"/>
      <ref name="parent_id"/>
    </element>
  </define>
  <define name="parent_elt" combine="choice">
    <element name="parent">
      <ref name="ctl_dr"/>
      <ref name="self_id"/>
      <ref name="parent_id"/>
    </element>
  </define>
  <!-- <child/> element -->
  <define name="child_id">
    <attribute name="child_id">
      <ref name="sql_id"/>
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
      <ref name="bsc_id"/>
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
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_cq"/>
      <ref name="self_id"/>
      <ref name="child_bool"/>
      <ref name="child_payload"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_cr"/>
      <ref name="self_id"/>
      <ref name="child_id"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_sq"/>
      <ref name="self_id"/>
      <ref name="child_id"/>
      <ref name="child_bool"/>
      <ref name="child_payload"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_sr"/>
      <ref name="self_id"/>
      <ref name="child_id"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_gq"/>
      <ref name="self_id"/>
      <ref name="child_id"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_gr"/>
      <ref name="self_id"/>
      <ref name="child_id"/>
      <ref name="child_payload"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_lq"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_lr"/>
      <ref name="self_id"/>
      <ref name="child_id"/>
      <ref name="child_payload"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_dq"/>
      <ref name="self_id"/>
      <ref name="child_id"/>
    </element>
  </define>
  <define name="child_elt" combine="choice">
    <element name="child">
      <ref name="ctl_dr"/>
      <ref name="self_id"/>
      <ref name="child_id"/>
    </element>
  </define>
  <!-- <repository/> element -->
  <define name="repository_id">
    <attribute name="repository_id">
      <ref name="sql_id"/>
    </attribute>
  </define>
  <define name="repository_payload">
    <optional>
      <attribute name="peer_contact_uri">
        <ref name="uri"/>
      </attribute>
    </optional>
    <optional>
      <ref name="bsc_id"/>
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
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_cq"/>
      <ref name="self_id"/>
      <ref name="repository_payload"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_cr"/>
      <ref name="self_id"/>
      <ref name="repository_id"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_sq"/>
      <ref name="self_id"/>
      <ref name="repository_id"/>
      <ref name="repository_payload"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_sr"/>
      <ref name="self_id"/>
      <ref name="repository_id"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_gq"/>
      <ref name="self_id"/>
      <ref name="repository_id"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_gr"/>
      <ref name="self_id"/>
      <ref name="repository_id"/>
      <ref name="repository_payload"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_lq"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_lr"/>
      <ref name="self_id"/>
      <ref name="repository_id"/>
      <ref name="repository_payload"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_dq"/>
      <ref name="self_id"/>
      <ref name="repository_id"/>
    </element>
  </define>
  <define name="repository_elt" combine="choice">
    <element name="repository">
      <ref name="ctl_dr"/>
      <ref name="self_id"/>
      <ref name="repository_id"/>
    </element>
  </define>
  <!-- <route_origin/> element -->
  <define name="route_origin_id">
    <attribute name="route_origin_id">
      <ref name="sql_id"/>
    </attribute>
  </define>
  <define name="route_origin_bool">
    <optional>
      <attribute name="suppress_publication">
        <value>yes</value>
      </attribute>
    </optional>
  </define>
  <define name="route_origin_payload">
    <optional>
      <attribute name="as_number">
        <data type="positiveInteger"/>
      </attribute>
    </optional>
    <optional>
      <attribute name="exact_match">
        <data type="boolean"/>
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
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_cq"/>
      <ref name="self_id"/>
      <ref name="route_origin_bool"/>
      <ref name="route_origin_payload"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_cr"/>
      <ref name="self_id"/>
      <ref name="route_origin_id"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_sq"/>
      <ref name="self_id"/>
      <ref name="route_origin_id"/>
      <ref name="route_origin_bool"/>
      <ref name="route_origin_payload"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_sr"/>
      <ref name="self_id"/>
      <ref name="route_origin_id"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_gq"/>
      <ref name="self_id"/>
      <ref name="route_origin_id"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_gr"/>
      <ref name="self_id"/>
      <ref name="route_origin_id"/>
      <ref name="route_origin_payload"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_lq"/>
      <ref name="self_id"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_lr"/>
      <ref name="self_id"/>
      <ref name="route_origin_id"/>
      <ref name="route_origin_payload"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_dq"/>
      <ref name="self_id"/>
      <ref name="route_origin_id"/>
    </element>
  </define>
  <define name="route_origin_elt" combine="choice">
    <element name="route_origin">
      <ref name="ctl_dr"/>
      <ref name="self_id"/>
      <ref name="route_origin_id"/>
    </element>
  </define>
  <!-- <list_resources/> element -->
  <define name="list_resources_elt">
    <element name="list_resources">
      <choice>
        <group>
          <attribute name="type">
            <value>query</value>
          </attribute>
          <ref name="tag"/>
          <ref name="self_id"/>
          <ref name="child_id"/>
        </group>
        <group>
          <attribute name="type">
            <value>reply</value>
          </attribute>
          <ref name="tag"/>
          <ref name="self_id"/>
          <ref name="child_id"/>
          <attribute name="valid_until">
            <data type="dateTime">
              <param name="pattern">.*Z</param>
            </data>
          </attribute>
          <optional>
            <attribute name="subject_name">
              <data type="token">
                <param name="maxLength">1024</param>
              </data>
            </attribute>
          </optional>
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
        </group>
      </choice>
    </element>
  </define>
  <!-- <report_error/> element -->
  <define name="report_error_elt">
    <element name="report_error">
      <ref name="tag"/>
      <ref name="self_id"/>
      <attribute name="error_code">
        <data type="token">
          <param name="maxLength">1024</param>
        </data>
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
  $Id: up-down-schema.rnc 1798 2008-05-17 08:21:50Z sra $
  
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
