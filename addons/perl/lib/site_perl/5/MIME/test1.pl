# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..10\n"; }
END {print "not ok 1\n" unless $loaded;}
use MIME::Base32;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

our $TestLevel = 1;
our $TestLevels = 10;
our $TestLabel = 'this case';
our $TestLabelPrefix = 'TEST:';
sub TestOK() { printf "ok %s\n", $TestLevel; return 1 }
sub TestKO() { printf "not ok %s\n", $TestLevel; return 0 } # KO -> k.o. -> knock out
sub TestSKIP() { printf "ok %s # SKIP\n", $TestLevel; return 1 }
sub TestIt($) { shift() ? TestOK : TestKO }
sub TestMSG($) { printf "\t%s%s: '%s'\n", $TestLabelPrefix, $TestLabel, shift() }
sub TestMSGf(@) { printf "\t%s%s: ".shift()."\n", $TestLabelPrefix, $TestLabel, @_ }

our $GlobalTestString = 'Hallo world, whats new?';
our $GlobalEncodedString;
our $GlobalDecodedString;

$TestLevel++;
$TestLabel = 'Encode';
TestIt(
	eval{
		$GlobalEncodedString = MIME::Base32::encode( $GlobalTestString );
		TestMSGf "'%s'->'%s'", $GlobalTestString, $GlobalEncodedString;
	} && !$@
);

$TestLevel++;
$TestLabel = 'Decode';
TestIt(
	eval{
		$GlobalDecodedString = MIME::Base32::decode( $GlobalEncodedString );
		TestMSGf "'%s'->'%s'", $GlobalEncodedString, $GlobalDecodedString;
	} && !$@
);

$TestLevel++;
$TestLabel = 'Reversibility match';
TestIt(
	eval{
		TestMSG ($GlobalTestString eq $GlobalDecodedString?'PASSED':'FAILED');
	} && !$@
);

# unUsed levels are OK
TestSKIP while $TestLevels > $TestLevel++;
