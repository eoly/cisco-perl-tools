#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;
use Net::Netmask;

#Trim whitespace from beginning and end of string.
sub trim {
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}

#Slurp lines from file containing show access-list output and close handle.
sub readFile {
    my $filePath = shift;
    open (my $handle,"<",$filePath) or die "Couldn't read file: $!";
    my @fileContents = <$handle>;
    close ($handle);
    return \@fileContents;
}

#Get unique list of access-list names.
sub getACLNames {
    my $fileContentsRef = shift; 
    my $aclNamesRef = [];
    foreach (@$fileContentsRef) {
        if (/^access-list+\s+(\w+);{1}/) {
            push (@{$aclNamesRef},$1);
        }
    }
    return $aclNamesRef;
}

#Get the expanded access list lines. These are lines that do not include the object or object-group references.
sub getExpandedACLS {
    my ($aclNamesRef, $fileContentsRef) = @_;
    my $expandedACLSRef = {};
    foreach (@$aclNamesRef) {
        my $aclName = $_;
        my $aclLinesRef = [];
        foreach (@$fileContentsRef) {
            my $fileLine = $_;
            if ($fileLine =~ /$aclName/) {
                if ($fileLine !~ /object|;/) {
                    push (@$aclLinesRef,trim($fileLine));
                }
            }
        }
        $expandedACLSRef->{$aclName} = $aclLinesRef;
    }
    return $expandedACLSRef;
}

#Get the rule portion of the access-list lines.
sub getACLRules {
    my $expandedACLSRef = shift(@_);
    my $aclRulesRef = {};
    foreach my $key (keys %{$expandedACLSRef}) {
        my $aclRuleLinesRef = [];
        foreach (@{$expandedACLSRef->{$key}}) {
            if (/^access-list\s+\w+\s+line\s+[0-9]+\s+extended\s+(.+)\s+\(hitcnt=[0-9]+\)\s+\w+$/) {
                push (@$aclRuleLinesRef,trim($1));
            }
        }
        $aclRulesRef->{$key} = $aclRuleLinesRef;
    }
    return $aclRulesRef;
}

sub extractACLParts {

    my $acl_action = qr/permit|deny/;
    my $acl_protocol = qr/ip|tcp|udp|icmp/;
    my $acl_ipaddr = qr/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    my $acl_host = qr/host\s{1}${acl_ipaddr}/;
    my $acl_net = qr/${acl_ipaddr}\s{1}${acl_ipaddr}/;
    my $acl_srcdst = qr/any|${acl_host}|${acl_net}/;
    my $acl_operator = qr/lt|gt|eq|neq|range/;
    my $acl_port = qr/\w+/;
    #my $acl_portrange = qr/[0-9]{1,5}\s{1}[0-9]{1,5}/;
    my $acl_portrange = qr/\w+\s{1}\w+/;

    my $aclRulesRef = shift;
    my $aclPartsRef = {};

    foreach my $aclName (keys %$aclRulesRef) {
        my $aclLinePartsRef = [];
        foreach (@{$aclRulesRef->{$aclName}}) {
            my $lineParts = {};
            my $dstpart = "";

            #Extract ACL Action
            if (/($acl_action){1}/) {
                $lineParts->{action} = $1;
            }

            #Extract ACL Protocol
            if (/$acl_action{1}\s{1}($acl_protocol){1}/) {
                $lineParts->{protocol} = $1;
            }

            #Extract ACL Source
            if (/$acl_action{1}\s{1}$acl_protocol{1}\s{1}($acl_srcdst){1}/) {
                my $src = $1;
                if ($src eq "any") {
                    $lineParts->{src} = "0.0.0.0/0";
                } elsif ($src =~ /host\s{1}($acl_ipaddr)/) {
                    $lineParts->{src} = $1."/32";
                } elsif ($src =~ /($acl_ipaddr)\s{1}($acl_ipaddr)/) {
                    my $srcblock = new Net::Netmask ($1,$2);
                    $lineParts->{src} = $srcblock->desc();
                }
            }

            #Extract source port or port ranges and operator if it exists and get the destination part of the ACL rule.
            if (/$acl_action{1}\s{1}$acl_protocol{1}\s{1}$acl_srcdst{1}\s{1}($acl_operator){1}/) {
                $lineParts->{srcportoperator} = $1;
                if ($1 ne "range") {
                    if (/$acl_action{1}\s{1}$acl_protocol{1}\s{1}$acl_srcdst{1}\s{1}$acl_operator{1}\s{1}($acl_port)\s{1}(.*)/) {
                        $lineParts->{srcport} = $1;
                        $dstpart = $2;
                    }
                } elsif ($1 eq "range") {
                    if (/$acl_action{1}\s{1}$acl_protocol{1}\s{1}$acl_srcdst{1}\s{1}$acl_operator{1}\s{1}($acl_portrange)\s{1}(.*)/) {
                        $lineParts->{srcport} = $1;
                        $dstpart = $2;
                    }
                }
            } elsif (/$acl_action{1}\s{1}$acl_protocol{1}\s{1}$acl_srcdst{1}\s{1}($acl_srcdst{1}.*)/) {
                $lineParts->{srcportoperator} = '';
                $lineParts->{srcport} = '';
                $dstpart = $1;
            }

            #Extract ACL Destination
            if ($dstpart =~ /($acl_srcdst){1}/) {
                my $dst = $1;
                if ($dst eq "any") {
                    $lineParts->{dst} = "0.0.0.0/0";
                } elsif ($dst =~ /host\s{1}($acl_ipaddr)/) {
                    $lineParts->{dst} = $1."/32";
                } elsif ($dst =~ /($acl_ipaddr)\s{1}($acl_ipaddr)/) {
                    my $dstblock = new Net::Netmask ($1,$2);
                    $lineParts->{dst} = $dstblock->desc();
                }
            }

            #Extract destination port or port ranges and operator if it exists.
            if ($dstpart =~ /$acl_srcdst{1}\s{1}($acl_operator){1}/) {
                $lineParts->{dstportoperator} = $1;
                if ($1 ne "range") {
                    if ($dstpart =~ /$acl_srcdst{1}\s{1}$acl_operator{1}\s{1}($acl_port)/) {
                        $lineParts->{dstport} = $1;
                    }
                } elsif ($1 eq "range") {
                    if ($dstpart =~ /$acl_srcdst{1}\s{1}$acl_operator{1}\s{1}($acl_portrange)/) {
                        $lineParts->{dstport} = $1;
                    }
                }
            } else {
                $lineParts->{dstportoperator} = '';
                $lineParts->{dstport} = '';
            }
            push (@$aclLinePartsRef,$lineParts);
        }
        $aclPartsRef->{$aclName} = $aclLinePartsRef;
    }
    return $aclPartsRef;
}

sub printHeader {
    print "action,protocol,src,srcportoperator,srcport,dst,dstportoperator,dstport\n";
}

sub searchACLS {
    my ($searchDirection, $searchString, $searchACL, $aclPartsRef) = @_;
    foreach my $aclName (keys %$aclPartsRef) {
        foreach ($aclPartsRef->{$aclName}) {
            if ($aclName eq $searchACL) {
                print $aclName . "\n";
                printHeader;
                foreach my $lineParts (@$_) {
                    my $searchBlock = new Net::Netmask ($lineParts->{$searchDirection});
                    if ($searchBlock->contains("$searchString")) {
                        print $lineParts->{'action'} . "," . $lineParts->{'protocol'} . ","; 
                        print $lineParts->{'src'} . "," . $lineParts->{'srcportoperator'} . "," . $lineParts->{'srcport'} . ",";
                        print $lineParts->{'dst'} . "," . $lineParts->{'dstportoperator'} . "," . $lineParts->{'dstport'} . "\n";
                    }
                }
            }
        }
    }
}

sub printUsage {
    print "\n";
    print "Cisco ASA ACL Analyzer Script\n\n";
    print "This script will search a file containing the output of the command show access-list.\n";
    print "Currently it only supports searching for a single IP address in either the src or dst portion of the ACL.\n";
    print "You must know the name of the ACL you want to search through.\n\n";
}

printUsage();

print "Enter path to firewall rules file: ";
my $fwRulesPath = <STDIN>;
chomp($fwRulesPath);

print "Enter the access list name: ";
my $fwAclName = <STDIN>;
chomp($fwAclName);

print "Enter host IP address to search for: ";
my $searchHostIP = <STDIN>;
chomp($searchHostIP);

print "Enter src or dst?: ";
my $fwAclDirection = <STDIN>;
chomp($fwAclDirection);

my $fileContentsRef = readFile($fwRulesPath);
my $aclNamesRef = getACLNames($fileContentsRef);
my $expandedACLSRef = getExpandedACLS($aclNamesRef, $fileContentsRef);
my $aclRulesRef = getACLRules($expandedACLSRef);
my $aclPartsRef = extractACLParts($aclRulesRef);

searchACLS($fwAclDirection,$searchHostIP,$fwAclName,$aclPartsRef);
