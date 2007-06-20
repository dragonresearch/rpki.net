XMLLINT		= xmllint --noout --relaxng
JING		= java -jar /usr/local/share/java/classes/jing.jar

all:
	${JING}    ../up-down-schema.rng *.xml
	${XMLLINT} ../up-down-schema.rng *.xml
