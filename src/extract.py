#!/usr/bin/env python3

from lxml import etree

import sys
import re

def extract_advisory(url):
    advisory = ""
    try:
        parser = etree.HTMLParser()
        tree = etree.parse(url, parser)
        adv = tree.xpath('//pre')
        advisory = adv[0].text
    except:
        pass

    # https://xkcd.com/1181/
    if advisory[0:34] != "-----BEGIN PGP SIGNED MESSAGE-----":
        raise ValueError("extract_advisory: advisory does not have the expected format")
    return advisory

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
        "versie":      r"^Versie\(s\)\s+:(?P<versie>.*)(?P<versierest>(\n +.*)+)?",
        "platform":    r"^Platform\(s\)\s+:(?P<platform>.*)(?P<platformrest>(\n +.*)*)?"
    }

    for index in list(regexes.keys()):
        match = re.search(regexes[index], advisory, re.MULTILINE)
        if match:
            rest = index + "rest"
            parsed_advisory[index] = match.group(index).strip()
            if match.group(rest):
                parsed_advisory[rest] = re.sub('\s{2,}', ' ', match.group(rest).strip())

    return parsed_advisory

advisory_dict = parse_advisory(extract_advisory("./testpagina.html"))

for t in sorted(advisory_dict.keys()):
    print("{}: {}".format(t, advisory_dict[t]))

# vim: set et:ts=4:sw=4:
