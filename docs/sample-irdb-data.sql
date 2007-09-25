
INSERT INTO registrant (IRBE_mapped_id) VALUES ('ARIN');
INSERT INTO registrant (IRBE_mapped_id) VALUES ('TIER1_ISP1');
INSERT INTO registrant (IRBE_mapped_id) VALUES ('TIER1_ISP2');
INSERT INTO registrant (IRBE_mapped_id) VALUES ('JOES_PIZZA');

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'All ARIN resources', '2099-12-31', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'ARIN';

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'Tier 1 ISP foo subject name', '2008-12-31', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'TIER1_ISP1';

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'Tier 1 ISP foo subject name', '2009-06-30', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'TIER1_ISP1';

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'Tier 1 ISP bar subject name', '2007-07-31', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'TIER1_ISP2';

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'arbitrary characters', '2007-12-31', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'JOES_PIZZA';

INSERT INTO net (start_ip, end_ip, version, resource_class_id)
SELECT 'DEAD:BEEF:0000:0000:0000:0000:0000:0000', 'DFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 6, resource_class_id
FROM resource_class WHERE subject_name = 'All ARIN resources';

INSERT INTO net (start_ip, end_ip, version, resource_class_id)
SELECT 'DEAD:BEEF:FACE:0000:0000:0000:0000:0000', 'DEAD:BEEF:FACE:FFFF:FFFF:FFFF:FFFF:FFFF', 6, resource_class_id
FROM resource_class WHERE subject_name = 'TIER 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO net (start_ip, end_ip, version, resource_class_id)
SELECT 'DEAD:BEEF:FACE:FADE:0000:0000:0000:0000', 'DEAD:BEEF:FACE:FADE:FFFF:FFFF:FFFF:FFFF', 6, resource_class_id
FROM resource_class WHERE subject_name = 'arbitrary characters' AND valid_until = '2007-12-31';

INSERT INTO net(start_ip, end_ip, version, resource_class_id)
SELECT '010.000.000.000', '010.255.255.255', 4, resource_class_id
FROM resource_class WHERE subject_name = 'All ARIN resources';

INSERT INTO net(start_ip, end_ip, version, resource_class_id)
SELECT '010.128.000.000', '010.191.255.255', 4, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO net(start_ip, end_ip, version, resource_class_id)
SELECT '010.000.000.000', '010.063.255.255', 4, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO net(start_ip, end_ip, version, resource_class_id)
SELECT '010.128.000.000', '010.191.255.255', 4, resource_class_id
FROM resource_class WHERE subject_name = 'arbitrary characters';

INSERT INTO asn(start_as, end_as, resource_class_id)
SELECT 12345, 12345, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO asn(start_as, end_as, resource_class_id)
SELECT 23456, 23457, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO asn(start_as, end_as, resource_class_id)
SELECT 34567, 34567, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2008-12-31';
