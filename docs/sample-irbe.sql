drop table if exists net;
drop table if exists asn;
drop table if exists resource_class;
drop table if exists registrant;




CREATE TABLE asn (
       asn_id               SERIAL NOT NULL,
       start_as             BIGINT unsigned NOT NULL,
       end_as               BIGINT unsigned NOT NULL,
       resource_class_id    BIGINT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKasn ON asn
(
       asn_id
);


ALTER TABLE asn
       ADD PRIMARY KEY (asn_id);


CREATE TABLE net (
       net_id               SERIAL NOT NULL,
       start_ip             VARCHAR(40) NOT NULL,
       end_ip               VARCHAR(40) NOT NULL,
       version              TINYINT unsigned NOT NULL,
       resource_class_id    BIGINT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKnet ON net
(
       net_id
);


ALTER TABLE net
       ADD PRIMARY KEY (net_id);


CREATE TABLE registrant (
       registrant_id        SERIAL NOT NULL,
       IRBE_mapped_id       TEXT
);

CREATE UNIQUE INDEX XPKregistrant ON registrant
(
       registrant_id
);


ALTER TABLE registrant
       ADD PRIMARY KEY (registrant_id);


CREATE TABLE resource_class (
       resource_class_id    SERIAL NOT NULL,
       subject_name         TEXT,
       valid_until          DATETIME NOT NULL,
       registrant_id        BIGINT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKresource_class ON resource_class
(
       resource_class_id
);


ALTER TABLE resource_class
       ADD PRIMARY KEY (resource_class_id);


ALTER TABLE asn
       ADD FOREIGN KEY (resource_class_id)
                             REFERENCES resource_class
                             ON DELETE SET NULL
                             ON UPDATE SET NULL;


ALTER TABLE net
       ADD FOREIGN KEY (resource_class_id)
                             REFERENCES resource_class
                             ON DELETE SET NULL
                             ON UPDATE SET NULL;


ALTER TABLE resource_class
       ADD FOREIGN KEY (registrant_id)
                             REFERENCES registrant
                             ON DELETE SET NULL
                             ON UPDATE SET NULL;



insert into registrant (IRBE_mapped_id) values ('ARIN');
insert into registrant (IRBE_mapped_id) values ('TIER1_ISP1');
insert into registrant (IRBE_mapped_id) values ('TIER1_ISP2');
insert into registrant (IRBE_mapped_id) values ('JOES_PIZZA');
insert into resource_class (subject_name, valid_until, registrant_id)
select 'All ARIN resources', '2099-12-31', registrant_id from registrant
where IRBE_mapped_id = 'ARIN';
insert into resource_class (subject_name, valid_until, registrant_id)
select 'Tier 1 ISP foo subject name', '2008-12-31', registrant_id from registrant
where IRBE_mapped_id = 'TIER1_ISP1';
insert into resource_class (subject_name, valid_until, registrant_id)
select 'Tier 1 ISP foo subject name', '2009-06-30', registrant_id from registrant
where IRBE_mapped_id = 'TIER1_ISP1';
insert into resource_class (subject_name, valid_until, registrant_id)
select 'Tier 1 ISP bar subject name', '2007-07-31', registrant_id from registrant
where IRBE_mapped_id = 'TIER1_ISP2';
insert into resource_class (subject_name, valid_until, registrant_id)
select 'arbitrary characters', '2007-12-31', registrant_id from registrant
where IRBE_mapped_id = 'JOES_PIZZA';
insert into net (start_ip, end_ip, version, resource_class_id)
select 'DEAD:BEEF:0000:0000:0000:0000:0000:0000','DFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',6,resource_class_id from resource_class where subject_name = 'All ARIN resources';
insert into net (start_ip, end_ip, version, resource_class_id)
select 'DEAD:BEEF:FACE:0000:0000:0000:0000:0000','DEAD:BEEF:FACE:FFFF:FFFF:FFFF:FFFF:FFFF',6,resource_class_id from resource_class where subject_name = 'TIER 1 ISP foo subject name' and valid_until = '2009-06-30';
insert into net (start_ip, end_ip, version, resource_class_id)
select 'DEAD:BEEF:FACE:FADE:0000:0000:0000:0000','DEAD:BEEF:FACE:FADE:FFFF:FFFF:FFFF:FFFF',6,resource_class_id from resource_class where subject_name = 'arbitrary characters' and valid_until = '2007-12-31';
insert into net(start_ip, end_ip, version, resource_class_id)
select 
'010.000.000.000','010.255.255.255',4,resource_class_id from resource_class where subject_name = 'All ARIN resources';
insert into net(start_ip, end_ip, version, resource_class_id)
select 
'010.128.000.000','010.191.255.255',4,resource_class_id from resource_class where subject_name = 'Tier 1 ISP foo subject name' and valid_until = '2009-06-30';
insert into net(start_ip, end_ip, version, resource_class_id)
select 
'010.000.000.000','010.063.255.255',4,resource_class_id from resource_class where subject_name = 'Tier 1 ISP foo subject name' and valid_until = '2009-06-30';
insert into net(start_ip, end_ip, version, resource_class_id)
select 
'010.128.000.000','010.191.255.255',4,resource_class_id from resource_class where subject_name = 'arbitrary characters';
insert into asn(start_as, end_as, resource_class_id)
select 12345, 12345, resource_class_id from resource_class where subject_name = 'Tier 1 ISP foo subject name' and valid_until = '2009-06-30';
insert into asn(start_as, end_as, resource_class_id)
select 23456, 23457, resource_class_id from resource_class where subject_name = 'Tier 1 ISP foo subject name' and valid_until = '2009-06-30';
insert into asn(start_as, end_as, resource_class_id)
select 34567, 34567, resource_class_id from resource_class where subject_name = 'Tier 1 ISP foo subject name' and valid_until = '2008-12-31';

