#!/usr/bin/env perl
# ---------------------------------------------------------------------------
# decrypt_aes_gcm.pl – Decrypt files produced by Java AESCryptUtil
# (AES‑128‑GCM + PBKDF2‑SHA256, 100 000 iterations)
# ---------------------------------------------------------------------------
use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use Digest::SHA qw(hmac_sha256);
use Crypt::Cipher::AES;
use Crypt::AuthEnc::GCM;
use File::Basename;

# ---- constants -------------------------------------------------------------
use constant {
    HEADER      => "Salted__",   # 8‑byte ASCII
    SALT_LEN    => 16,
    IV_LEN      => 12,
    TAG_LEN     => 16,
    KEY_LEN     => 16,           # 128‑bit key
    ITER        => 100_000,
};

# ---- PBKDF2‑SHA256 (minimal, no external deps) -----------------------------
sub pbkdf2_sha256 {
    my ($pwd,$salt,$iter,$dklen) = @_;
    my $hlen = 32;                      # SHA‑256 output length
    my $l    = int(($dklen + $hlen - 1) / $hlen);
    my $dk   = '';
    for my $i (1..$l) {
        my $u = hmac_sha256($salt . pack('N',$i), $pwd);
        my $t = $u;
        for (2..$iter) {
            $u = hmac_sha256($u, $pwd);
            $t = $t ^ $u;              # XOR each block
        }
        $dk .= $t;
    }
    return substr($dk, 0, $dklen);
}

# ---- CLI parsing -----------------------------------------------------------
my ($in,$out,$pass,$passenv,$verbose);
GetOptions(
    'in|i=s'         => \$in,
    'out|o=s'        => \$out,
    'passphrase|p=s' => \$pass,
    'passenv=s'      => \$passenv,
    'verbose'        => \$verbose,
) or die "Usage: $0 -i ENC -o DEC (-p PASS|--passenv ENV) [--verbose]\n";

$in  && $out or die "--in and --out are required\n";
$pass //= defined $passenv ? $ENV{$passenv} : undef;
$pass or die "Passphrase not provided\n";

# ---- read encrypted file ---------------------------------------------------
open my $fh, '<:raw', $in or die "Open $in: $!\n";
read($fh, my $hdr, length(HEADER)) == length(HEADER) or die "Short read\n";
$hdr eq HEADER or die "Invalid header\n";
read($fh, my $salt, SALT_LEN) == SALT_LEN or die "Salt read error\n";
read($fh, my $iv,   IV_LEN)   == IV_LEN   or die "IV read error\n";
my $blob; { local $/; $blob = <$fh>; }
close $fh;
length($blob) > TAG_LEN or die "Ciphertext too small\n";
my $tag = substr($blob, -TAG_LEN, TAG_LEN, '');
my $ct  = $blob;   # ciphertext without tag

if ($verbose) {
    printf STDERR "Salt: %s\nIV  : %s\n", unpack('H*',$salt), unpack('H*',$iv);
}

# ---- derive key ------------------------------------------------------------
my $key = pbkdf2_sha256($pass, $salt, ITER, KEY_LEN);
printf STDERR "Key : %s\n", unpack('H*',$key) if $verbose;

# ---- decrypt ---------------------------------------------------------------
my $gcm = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
my $plaintext = $gcm->decrypt_add($ct);
my $auth_ok   = $gcm->decrypt_done($tag);
$auth_ok or die "Authentication failed – wrong passphrase or corrupt file\n";

# ---- write output ----------------------------------------------------------
open my $outfh, '>:raw', $out or die "Write $out: $!\n";
print $outfh $plaintext;
close $outfh;

print "Decryption OK → ".basename($out)."\n";
