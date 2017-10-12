#!/usr/bin/env python3

from gnupg import GPG
from lxml import etree
from urllib.request import urlopen

import sys
import re
from tempfile import mkdtemp

NCSC_KEY_FINGERPRINT = 'BBE52FEFA5727121E1DD0441286E11B5C57E12F6'
NCSC_KEY_URL = 'https://www.ncsc.nl/binaries/content/assets/pgp-key/ncsc-nl-2017.asc'

def extract_advisory(url):
    advisory = ""
    try:
        parser = etree.HTMLParser()
        tree = etree.parse(url, parser)
    except IOError:
        tree = etree.parse(urlopen(url), parser)

    adv = tree.xpath('//pre')
    advisory = adv[0].text

    # https://xkcd.com/1181/
    if advisory[0:34] != "-----BEGIN PGP SIGNED MESSAGE-----":
        raise ValueError("extract_advisory: advisory does not have the expected format\n{}".format(advisory))
    return advisory

def verify_advisory(advisory):
    """
    Verifies the GPG signature

    This function returns True if the singed data was verified correctly.
    If the signature was in any way invalid (or absent), it will return False.
    """
    # Setup GPG environment and import NCSC key
    homedir = mkdtemp(prefix='adviesmolen-')
    gpg = GPG(homedir=homedir)
    r = urlopen(NCSC_KEY_URL)
    if r.status != 200:
        # Some status error occured
        raise ValueError('could not download NCSC pubkey')
    tmp = gpg.import_keys(r.read())
    if not any(x.get('status', None) == 'Entirely new key\n' and
               x.get('fingerprint', None) == NCSC_KEY_FINGERPRINT for x in tmp.results):
        # Did not import a good key
        raise ValueError('failed to import a correct key ({})'.format(tmp.results))

    verified = gpg.verify(advisory)
    if not verified.valid:
        return False
    if verified.fingerprint != NCSC_KEY_FINGERPRINT:
        return False
    return True

def parse_advisory(advisory):
    if advisory[0:34] != "-----BEGIN PGP SIGNED MESSAGE-----":
        raise ValueError("parse_advisory: advisory does not have the expected format")

    parsed_advisory = {}

    advisory = advisory.replace("\r", "")

    regexes = {
        "titel":       r"^Titel\s+:(?P<titel>.*)(?P<titelrest>(\n +.*)+)?",
        "advisoryid":  r"^Advisory ID\s+:(?P<advisoryid>.*)(?P<advisoryidrest>(\n +.*)+)?",
        "versie":      r"^Versie\s+:(?P<versie>.*)(?P<versierest>(\n +.*\n)+)?",
        "kans":        r"^Kans\s+:(?P<kans>.*)(?P<kansrest>(\n +.*\n)+)?",
        "cveids":      r"^CVE ID\s+:(?P<cveids>.*)(?P<cveidsrest>(\n +.*)+)?",
        "schade":      r"^Schade\s+:(?P<schade>.*)(?P<schaderest>(\n +.*)+)?",
        "datum":       r"^Uitgiftedatum\s+:(?P<datum>.*)(?P<datumrest>(\n +.*)+)?",
        "toepassing":  r"^Toepassing\s+:(?P<toepassing>.*)(?P<toepassingrest>(\n +.*)+)?",
        "tpversie":    r"^Versie\(s\)\s+:(?P<tpversie>.*)(?P<tpversierest>(\n +.*)+)?",
        "platform":    r"^Platform\(s\)\s+:(?P<platform>.*)(?P<platformrest>(\n +.*)*)?",
        "samenvatting":r"^Samenvatting\s*\n(?P<samenvatting>\s+.*)(?P<samenvattingrest>(\n +.*)*)?",
        "beschrijving":r"^Beschrijving\s*\n(?P<beschrijving>\s+.*)(?P<beschrijvingrest>(\n +.*)*)?",
        "solution":    r"^Mogelijke oplossingen\s*\n(?P<solution>\s+.*)(?P<solutionrest>(\n +.*)*)?",
        "disclaimer":  r"^Vrijwaringsverklaring\s*\n(?P<disclaimer>\s+.*)(?P<disclaimerrest>(\n +.*)*)?"

    }

    for index in list(regexes.keys()):
        match = re.search(regexes[index], advisory, re.MULTILINE)
        if match:
            rest = index + "rest"
            parsed_advisory[index] = match.group(index).strip()
            if match.group(rest):
                parsed_advisory[rest] = re.sub('\s{2,}', ' ', match.group(rest).strip())

    return parsed_advisory

def pretty_print(parsed_advisory):
    kans   = parsed_advisory['kans'][0:1].upper()
    schade = parsed_advisory['schade'][0:1].upper()
    print("{}/{}, {} ({}): {}".format(kans, schade, parsed_advisory['advisoryid'], parsed_advisory['versie'], parsed_advisory['titel']))

advisory = extract_advisory(sys.argv[1])
if verify_advisory(advisory):
    pretty_print(parse_advisory(advisory))
else:
    raise ValueError('could not verify the GPG signature of the advisory')

# vim: set et:ts=4:sw=4:
