XMLLINT		= xmllint --noout --relaxng
JING		= java -jar /usr/local/share/java/classes/jing.jar
SCHEMA		= ../up-down-medium-schema.rng

all: jing xmllint

jing:
	${JING}    ${SCHEMA} *.xml

xmllint:
	${XMLLINT} ${SCHEMA} *.xml
