#!/bin/sh
# The cases run by cluster/test-backup-scripts.sh -- see that file for
# why any of this exists. Runs INSIDE the Percona image, against the
# real extracted scripts in /h and a stub pg_dump/psql on PATH.
#
# sh, not bash, deliberately: the scripts under test run under `sh -c`
# in their pods, so the test shell has to be the same one.
#
# SC2015 (A && B || C is not if-then-else): the whole file is written
# as `<assertion> && ok ... || bad ...`, and ok() cannot fail -- it is
# one echo -- so C never runs after a true A. Spelling ~50 assertions
# as if/else blocks would bury what each one checks.
# SC2012 (use find instead of ls): these globs are our own filenames,
# scm-postgres-<ISO timestamp>.sql.gz, with no spaces or newlines
# possible -- and `ls` is what the code under test uses.
# shellcheck disable=SC2015,SC2012
set -u
export POSTGRES_HOST=db POSTGRES_PORT=5432 POSTGRES_USER=u POSTGRES_DB=scm POSTGRES_PASSWORD=p
export PATH="/h/stubs:$PATH"
fails=0
ok()  { echo "  ok:   $1"; }
bad() { echo "  FAIL: $1"; fails=$((fails+1)); }

KD=/etc/scm-backup-decryption
reset() { rm -rf /backups/*; rm -rf /tmp/gnupg /tmp/survivors; }
# A restore always gets a NEW pod: empty keyring, no leftover key.
fresh() { rm -f "$KD"/* /tmp/psql.in; rm -rf /tmp/gnupg /tmp/decrypt.err; }
# A plausible existing backup: valid gzip containing a real dump header.
fake() { printf -- '--\n-- PostgreSQL database dump\n--\nSELECT 1;\n' | gzip > "/backups/scm-postgres-$1.sql.gz"; }
run() { ( cd / && sh /h/script-plain.sh ) >/tmp/out 2>&1; echo $?; }

echo "=== T1: plaintext path writes a dump + sidecar ==="
reset
rc=$(run)
[ "$rc" = 0 ] && ok "exit 0" || { bad "exit $rc"; tail -5 /tmp/out; }
n=$(ls /backups/scm-postgres-*.sql.gz 2>/dev/null | wc -l)
[ "$n" = 1 ] && ok "one .sql.gz written" || bad "expected 1 dump, got $n"
f=$(ls /backups/scm-postgres-*.sql.gz 2>/dev/null | head -1)
[ -f "${f}.sha256" ] && ok "sidecar written" || bad "no .sha256 sidecar"
( cd /backups && sha256sum -c --status "$(basename "$f").sha256" ) && ok "sidecar verifies" || bad "sidecar does not verify"
# The awk gate sits in the middle of the dump pipeline. If it alters
# so much as a byte, it is corrupting every backup this system takes.
sz=$(gzip -dc "$f" | wc -c)
raw=$(pg_dump | wc -c)
[ "$sz" = "$raw" ] && ok "byte-identical to pg_dump output ($sz bytes)" || bad "the awk gate altered the stream: $sz vs $raw"
gzip -dc "$f" | grep -q "INSERT INTO t VALUES (1999" && ok "last row present (not truncated)" || bad "stream truncated"

echo "=== T2: a dump that produces nothing must FAIL, not be kept ==="
# The three-day outage: pg_dump exits without writing, gzip happily
# compresses the empty stream, and the job reports success.
reset
cp /h/stubs/pg_dump /tmp/pg_dump.real; cp /h/stubs/pg_dump_empty /h/stubs/pg_dump
rc=$(run)
cp /tmp/pg_dump.real /h/stubs/pg_dump
[ "$rc" != 0 ] && ok "exit $rc (nonzero)" || bad "an empty dump reported success"
n=$(ls /backups/ 2>/dev/null | wc -l)
[ "$n" = 0 ] && ok "no corpse left in /backups" || { bad "left $n file(s)"; ls -la /backups; }

echo "=== T3: retention keeps the NEWEST and deletes the oldest ==="
reset
for d in 20260101 20260102 20260103 20260104 20260105 20260106 20260107 20260108 20260109 20260110; do
	fake "${d}T020000Z"
done
# Every fabricated file has the SAME mtime on purpose: an mtime sort
# has no signal here, so only name order can produce a right answer.
rc=$(run)
[ "$rc" = 0 ] && ok "exit 0" || { bad "exit $rc"; tail -20 /tmp/out; }
left=$(ls -1 /backups/scm-postgres-*.sql.gz 2>/dev/null | wc -l)
[ "$left" = 7 ] && ok "7 kept (KEEP_BACKUPS)" || bad "expected 7, got $left"
# 10 fabricated + 1 fresh = 11 -> the 7 kept are the fresh one and
# 0105..0110. Drop the `-r` from the prune's sort and this block is
# what fails.
for d in 20260105 20260106 20260107 20260108 20260109 20260110; do
	[ -f "/backups/scm-postgres-${d}T020000Z.sql.gz" ] && ok "kept ${d}" || bad "DELETED ${d} -- a recent backup"
done
for d in 20260101 20260102 20260103 20260104; do
	[ -f "/backups/scm-postgres-${d}T020000Z.sql.gz" ] && bad "kept ${d} -- should have been pruned" || ok "pruned ${d} (oldest)"
done

echo "=== T4: encrypted path round-trips ==="
reset
export GNUPGHOME=/tmp/keyring
rm -rf $GNUPGHOME && mkdir -p $GNUPGHOME && chmod 700 $GNUPGHOME
gpg --batch --quiet --passphrase '' --quick-generate-key 'scm-A' default default never 2>/dev/null
gpg --batch --quiet --passphrase '' --quick-generate-key 'scm-B' default default never 2>/dev/null
gpg --armor --export scm-A > /h/pubA.asc 2>/dev/null
gpg --armor --batch --pinentry-mode loopback --passphrase '' --export-secret-keys scm-A > /h/privA.asc 2>/dev/null
gpg --armor --batch --pinentry-mode loopback --passphrase '' --export-secret-keys scm-B > /h/privB.asc 2>/dev/null
unset GNUPGHOME
[ -s /h/pubA.asc ] && [ -s /h/privB.asc ] && ok "keypairs A and B generated" || bad "key generation failed"
GPG_RECIPIENT_FILE=/h/pubA.asc; export GPG_RECIPIENT_FILE
( cd / && sh /h/script-enc.sh ) >/tmp/out 2>&1; rc=$?
[ "$rc" = 0 ] && ok "exit 0" || { bad "exit $rc"; tail -20 /tmp/out; }
e=$(ls /backups/scm-postgres-*.sql.gz.gpg 2>/dev/null | head -1)
[ -n "$e" ] && ok "wrote $(basename "$e")" || bad "no .sql.gz.gpg written"
[ -f "${e}.sha256" ] && ok "sidecar written" || bad "no sidecar"
grep -q "PostgreSQL database dump" "$e" 2>/dev/null && bad "PLAINTEXT VISIBLE IN THE ENCRYPTED FILE" || ok "no plaintext dump header in the file"
export GNUPGHOME=/tmp/keyring
dec=$(gpg --batch --quiet --decrypt "$e" 2>/dev/null | gzip -dc | wc -c)
raw=$(pg_dump | wc -c)
[ "$dec" = "$raw" ] && ok "decrypt->gunzip round-trips exactly ($dec bytes)" || bad "round-trip mismatch: $dec vs $raw"
unset GNUPGHOME

echo "=== T5: an encrypted backup with no sidecar must be KEPT ==="
# "Cannot verify" must not mean "delete": the sweep cannot read an
# encrypted file, and the first run after enabling encryption would
# otherwise destroy every backup taken before it.
cp "$e" /backups/scm-postgres-20250101T020000Z.sql.gz.gpg
rm -f /backups/scm-postgres-20250101T020000Z.sql.gz.gpg.sha256
export KEEP_BACKUPS=50
( cd / && sh /h/script-enc.sh ) >/tmp/out2 2>&1; rc=$?
[ "$rc" = 0 ] && ok "exit 0" || { bad "exit $rc"; tail -10 /tmp/out2; }
[ -f /backups/scm-postgres-20250101T020000Z.sql.gz.gpg ] && ok "sidecar-less encrypted backup survived" || bad "DELETED an unverifiable-but-good encrypted backup"
grep -q "NOT assumed bad" /tmp/out2 && ok "said so in the log" || bad "no warning printed"

echo "=== T6: a backup that fails its own checksum IS discarded ==="
printf 'this is not a gpg file at all' > /backups/scm-postgres-20250202T020000Z.sql.gz.gpg
( cd /backups && sha256sum scm-postgres-20250202T020000Z.sql.gz.gpg > scm-postgres-20250202T020000Z.sql.gz.gpg.sha256 )
printf 'corrupted after the checksum was taken' > /backups/scm-postgres-20250202T020000Z.sql.gz.gpg
( cd / && sh /h/script-enc.sh ) >/tmp/out3 2>&1
[ -f /backups/scm-postgres-20250202T020000Z.sql.gz.gpg ] && bad "kept a file that fails its own checksum" || ok "discarded the checksum mismatch"

# ---- restore, fed by the backups the real backup job just wrote ----
export KEEP_BACKUPS=7
reset
GPG_RECIPIENT_FILE=/h/pubA.asc; export GPG_RECIPIENT_FILE
( cd / && sh /h/script-enc.sh ) >/tmp/b.out 2>&1 || { bad "backup job failed"; tail -5 /tmp/b.out; }
unset GPG_RECIPIENT_FILE
( cd / && sh /h/script-plain.sh ) >/tmp/b2.out 2>&1 || { bad "plaintext backup job failed"; tail -5 /tmp/b2.out; }
BKUP_ENC=$(cd /backups && ls -1 scm-postgres-*.sql.gz.gpg 2>/dev/null | head -1); export BKUP_ENC
BKUP_PLAIN=$(cd /backups && ls -1 scm-postgres-*.sql.gz 2>/dev/null | head -1); export BKUP_PLAIN
expected=$(pg_dump | wc -c)

echo "=== R1: encrypted + the RIGHT key restores the exact dump ==="
fresh; cp /h/privA.asc "$KD/privatekey.asc"
( cd / && sh /h/restore-enc.sh ) >/tmp/r1 2>&1; rc=$?
[ "$rc" = 0 ] && ok "exit 0" || { bad "exit $rc"; tail -12 /tmp/r1; }
got=$(wc -c < /tmp/psql.in 2>/dev/null || echo 0)
[ "$got" = "$expected" ] && ok "psql received the exact dump ($got bytes)" || bad "psql got $got bytes, expected $expected"
grep -q "INSERT INTO t VALUES (1999" /tmp/psql.in 2>/dev/null && ok "last row reached psql" || bad "stream truncated before psql"
grep -q "checksum sidecar verified" /tmp/r1 && ok "sidecar was verified" || bad "sidecar not verified"

echo "=== R2: encrypted + NO key refuses clearly and touches nothing ==="
fresh
( cd / && sh /h/restore-enc.sh ) >/tmp/r2 2>&1; rc=$?
[ "$rc" != 0 ] && ok "exit $rc (nonzero)" || bad "restored without a key"
grep -q "is encrypted, but no private key was supplied" /tmp/r2 && ok "says the key is missing" || { bad "unclear message"; cat /tmp/r2; }
grep -q "GPG_PRIVATE_KEY_FILE" /tmp/r2 && ok "tells the operator what to pass" || bad "no remedy in the message"
[ ! -f /tmp/psql.in ] && ok "psql was never invoked" || bad "psql ran anyway"

echo "=== R3: encrypted + the WRONG key is reported as a KEY problem ==="
# During an outage, "not a readable dump" would send someone hunting a
# corrupt backup that is perfectly fine.
fresh; cp /h/privB.asc "$KD/privatekey.asc"
( cd / && sh /h/restore-enc.sh ) >/tmp/r3 2>&1; rc=$?
[ "$rc" != 0 ] && ok "exit $rc (nonzero)" || bad "reported success with the wrong key"
grep -q "could not DECRYPT" /tmp/r3 && ok "diagnosed as a decryption failure" || { bad "not diagnosed as a key problem"; cat /tmp/r3; }
grep -q "this is a key problem, not a corrupt backup" /tmp/r3 && ok "explicitly rules out a corrupt backup" || bad "no such disambiguation"
grep -q "is not a readable PostgreSQL dump" /tmp/r3 && bad "ALSO blamed the backup -- misleading" || ok "does not blame the backup"
grep -q "ERROR:   " /tmp/r3 && ok "includes gpg's own words" || bad "gpg's reason not surfaced"
[ ! -f /tmp/psql.in ] && ok "psql was never invoked" || bad "psql ran anyway"

echo "=== R4: a plaintext backup still restores unchanged ==="
fresh
( cd / && sh /h/restore-plain.sh ) >/tmp/r4 2>&1; rc=$?
[ "$rc" = 0 ] && ok "exit 0" || { bad "exit $rc"; tail -12 /tmp/r4; }
got=$(wc -c < /tmp/psql.in 2>/dev/null || echo 0)
[ "$got" = "$expected" ] && ok "psql received the exact dump ($got bytes)" || bad "psql got $got bytes, expected $expected"

echo "=== R5: a backup that no longer matches its sidecar is refused ==="
fresh; cp /h/privA.asc "$KD/privatekey.asc"
sz=$(wc -c < "/backups/$BKUP_ENC")
dd if=/dev/zero of="/backups/$BKUP_ENC" bs=1 seek=$((sz / 2)) count=8 conv=notrunc 2>/dev/null
( cd / && sh /h/restore-enc.sh ) >/tmp/r5 2>&1; rc=$?
[ "$rc" != 0 ] && ok "exit $rc (nonzero)" || bad "restored a corrupted backup"
[ ! -f /tmp/psql.in ] && ok "psql was never invoked" || bad "fed a corrupt stream to psql"

echo
[ "$fails" = 0 ] && echo "ALL PASSED" || echo "$fails CHECK(S) FAILED"
exit "$fails"
