# Automatically generated, do not edit.

all:: RIR.cer

RIR.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

RIR.req: RIR.key RIR.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config RIR.cnf -key RIR.key -out $@

RIR.cer: RIR.req RIR.cnf RIR.key Makefile
	@test -d RIR || mkdir RIR
	@test -f RIR/index || touch RIR/index
	@test -f RIR/serial || echo 01 >RIR/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in RIR.req -extfile RIR.cnf -config RIR.cnf -selfsign


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in RIR.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in RIR.cer

all:: LIR3.cer

LIR3.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

LIR3.req: LIR3.key LIR3.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config LIR3.cnf -key LIR3.key -out $@

LIR3.cer: LIR3.req LIR3.cnf RIR.key Makefile
	@test -d LIR3 || mkdir LIR3
	@test -f LIR3/index || touch LIR3/index
	@test -f LIR3/serial || echo 01 >LIR3/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in LIR3.req -extfile LIR3.cnf -config RIR.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in LIR3.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in LIR3.cer

all:: LIR2.cer

LIR2.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

LIR2.req: LIR2.key LIR2.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config LIR2.cnf -key LIR2.key -out $@

LIR2.cer: LIR2.req LIR2.cnf RIR.key Makefile
	@test -d LIR2 || mkdir LIR2
	@test -f LIR2/index || touch LIR2/index
	@test -f LIR2/serial || echo 01 >LIR2/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in LIR2.req -extfile LIR2.cnf -config RIR.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in LIR2.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in LIR2.cer

all:: LIR1.cer

LIR1.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

LIR1.req: LIR1.key LIR1.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config LIR1.cnf -key LIR1.key -out $@

LIR1.cer: LIR1.req LIR1.cnf RIR.key Makefile
	@test -d LIR1 || mkdir LIR1
	@test -f LIR1/index || touch LIR1/index
	@test -f LIR1/serial || echo 01 >LIR1/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in LIR1.req -extfile LIR1.cnf -config RIR.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in LIR1.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in LIR1.cer

all:: ISP5c.cer

ISP5c.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

ISP5c.req: ISP5c.key ISP5c.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config ISP5c.cnf -key ISP5c.key -out $@

ISP5c.cer: ISP5c.req ISP5c.cnf LIR3.key Makefile
	@test -d ISP5c || mkdir ISP5c
	@test -f ISP5c/index || touch ISP5c/index
	@test -f ISP5c/serial || echo 01 >ISP5c/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in ISP5c.req -extfile ISP5c.cnf -config LIR3.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in ISP5c.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in ISP5c.cer

all:: ISP5b.cer

ISP5b.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

ISP5b.req: ISP5b.key ISP5b.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config ISP5b.cnf -key ISP5b.key -out $@

ISP5b.cer: ISP5b.req ISP5b.cnf LIR3.key Makefile
	@test -d ISP5b || mkdir ISP5b
	@test -f ISP5b/index || touch ISP5b/index
	@test -f ISP5b/serial || echo 01 >ISP5b/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in ISP5b.req -extfile ISP5b.cnf -config LIR3.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in ISP5b.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in ISP5b.cer

all:: ISP5a.cer

ISP5a.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

ISP5a.req: ISP5a.key ISP5a.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config ISP5a.cnf -key ISP5a.key -out $@

ISP5a.cer: ISP5a.req ISP5a.cnf LIR3.key Makefile
	@test -d ISP5a || mkdir ISP5a
	@test -f ISP5a/index || touch ISP5a/index
	@test -f ISP5a/serial || echo 01 >ISP5a/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in ISP5a.req -extfile ISP5a.cnf -config LIR3.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in ISP5a.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in ISP5a.cer

all:: ISP4.cer

ISP4.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

ISP4.req: ISP4.key ISP4.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config ISP4.cnf -key ISP4.key -out $@

ISP4.cer: ISP4.req ISP4.cnf LIR2.key Makefile
	@test -d ISP4 || mkdir ISP4
	@test -f ISP4/index || touch ISP4/index
	@test -f ISP4/serial || echo 01 >ISP4/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in ISP4.req -extfile ISP4.cnf -config LIR2.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in ISP4.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in ISP4.cer

all:: ISP3.cer

ISP3.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

ISP3.req: ISP3.key ISP3.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config ISP3.cnf -key ISP3.key -out $@

ISP3.cer: ISP3.req ISP3.cnf LIR2.key Makefile
	@test -d ISP3 || mkdir ISP3
	@test -f ISP3/index || touch ISP3/index
	@test -f ISP3/serial || echo 01 >ISP3/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in ISP3.req -extfile ISP3.cnf -config LIR2.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in ISP3.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in ISP3.cer

all:: ISP2.cer

ISP2.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

ISP2.req: ISP2.key ISP2.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config ISP2.cnf -key ISP2.key -out $@

ISP2.cer: ISP2.req ISP2.cnf LIR1.key Makefile
	@test -d ISP2 || mkdir ISP2
	@test -f ISP2/index || touch ISP2/index
	@test -f ISP2/serial || echo 01 >ISP2/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in ISP2.req -extfile ISP2.cnf -config LIR1.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in ISP2.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in ISP2.cer

all:: ISP1.cer

ISP1.key:
	../../openssl/openssl-0.9.8f/apps/openssl genrsa -out $@ 2048

ISP1.req: ISP1.key ISP1.cnf Makefile
	../../openssl/openssl-0.9.8f/apps/openssl req -new -config ISP1.cnf -key ISP1.key -out $@

ISP1.cer: ISP1.req ISP1.cnf LIR1.key Makefile
	@test -d ISP1 || mkdir ISP1
	@test -f ISP1/index || touch ISP1/index
	@test -f ISP1/serial || echo 01 >ISP1/serial
	../../openssl/openssl-0.9.8f/apps/openssl ca -batch -out $@ -in ISP1.req -extfile ISP1.cnf -config LIR1.cnf


show_req::
	../../openssl/openssl-0.9.8f/apps/openssl req -noout -text -in ISP1.req -config /dev/null

show_cer::
	../../openssl/openssl-0.9.8f/apps/openssl x509 -noout -text -in ISP1.cer
