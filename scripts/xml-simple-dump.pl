# $Id$
#
# XML::Simple is relatively easy to use (have you looked at the
# alternatives?)  but sometimes even XML::Simple's internal
# representation is not immediately obvious.  On days when it'd be
# easier to write the XML by hand and let a machine tell you how
# XML::Simple would represent it, run this script.

eval 'exec perl -w -S $0 ${1+"$@"}'
    if 0;

use strict;
use XML::Simple;
use Data::Dumper;

my $xs = XML::Simple->new(KeepRoot => 1,
			  ForceArray => [qw(list_class)],
			  KeyAttr => [qw(header)],
 			  NormalizeSpace => 2);

my @xml = <>;
shift(@xml) while (@xml && $xml[0] =~ /^\s*$/);
$xml[0] =~ s/^\s+// if (@xml);

print(Dumper($xs->XMLin(join('', @xml))));
