#!/usr/bin/env python

import dns.resolver
import optfunc
from optfunc import arghelp
from dns.resolver import NXDOMAIN


# heuristics ftw!
THREE_LEVEL_SMELLS = 'ac co edu gov law mil nom org school'.split(' ')

# NO idea how to map from the integers to names using dnspython,
# so I'm hardcoding the constants here. yay!
A = 1
CNAME = 5

def is_root_domain(domain):
    # assume www. is already stripped from the front
    bits = domain.split('.')

    # something.com is probably a root
    if len(bits) == 2:
        return True

    # something.co.za is probably a root
    if len(bits) == 3:
        # two char TLD might mean a country
        # and a whitelisted second-level domain probably means that
        # country uses two-level deep TLDs.
        if len(bits[-1]) == 2 and bits[-2] in THREE_LEVEL_SMELLS:
            return True

    # assume everything else is a subdomain
    return False


def get_domain_details(domain, force_root=False):
    # @ means root domain, ok?
    tocheck = [('@', domain)]

    # if it looks like you're using a root domain, also check www.
    if force_root or is_root_domain(domain):
        tocheck.append(('www', 'www.'+domain))

    # will hold records['@'] = dict(type='A', address='107.20.228.0')
    records = {}

    # whatever we think is probably wrong. recommendations, you know.
    # (we'll probably be adding more elsewhere
    #  as we don't check everything here)
    warnings = []

    for n, d in tocheck:
        try:
            answers = dns.resolver.query(domain)
        except NXDOMAIN:
            if n == '@':
                # if the domain itself doesn't resolve it is a fatal error
                return False
            else:
                warnings.append('%s does not resolve.' % (n,))
        else:
            answer = answers.response.answer[0]
            item = answer.items[0]

            if item.rdtype == A:
                records[n] = dict(
                    type='A',
                    address=str(answers[0].address))

            if item.rdtype == CNAME:
                records[n] = dict(
                    type='CNAME',
                    address=str(answers[0].address),
                    target=str(item.target))

    return dict(warnings=warnings, records=records)

NXDOMAIN_ERROR = "%s does not resolve."
IP_ERROR = "%s points to %s"
CNAME_ERROR = "%s points to %s"
CNAME_WARNING = "%s is a CNAME to %s. Root domains should be A records, not CNAMEs."
WWW_IP_WARNING = "www.%s points to %s"
WWW_A_WARNING = "www.%s is an A record. Ideally it would be a CNAME to %s."
WWW_CNAME_WARNING = "www.%s points to %s"

def find_domain_problems(domain, ips, cnames):
    force_root = False
    # don't just check the www, check the root too
    if domain.startswith('www.'):
        # by specifying www. we can force both to be checked.
        force_root = True
        domain = domain[4:]

    report = get_domain_details(domain, force_root=force_root)

    warnings = []
    errors = []
    if report:
        warnings = report['warnings']

        root = report['records']['@']
        if root['address'] not in ips:
            errors.append(IP_ERROR % (domain, root['address']))
        else:
            # don't give multiple errors or warnings for the root domain
            # if it doesn't resolve at all
            if root['type'] == 'A':
                # we already checked if it resolved
                pass
            elif root['type'] == 'CNAME':
                if root['target'] not in cnames:
                    errors.append(CNAME_ERROR % (domain, root['target']))
                elif len(report['records'].keys()) > 1:
                    warnings.append(CNAME_WARNING % (domain, root['target']))

        if 'www' in report['records']:
            www = report['records']['www']
            if www['address'] not in ips:
                warnings.append(WWW_IP_WARNING % (domain, www['address']))
            else:
                # don't give multiple errors or warnings for the www domain
                # if it doesn't resolve at all
                if www['type'] == 'A':
                    # this one is a bit TOO pedantic
                    #warnings.append(WWW_A_WARNING % (domain, domain))
                    pass

                elif www['type'] == 'CNAME':
                    if www['target'] not in cnames:
                        warnings.append(WWW_CNAME_WARNING % (
                            domain, www['target']))

    else:
        errors.append(NXDOMAIN_ERROR % (domain,))

    report['warnings'] = warnings
    report['errors'] = errors

    return report

@arghelp('ips', 'comma-delimited list of allowed A records')
@arghelp('cnames', 'comma-delimited list of allowed CNAMEs')
def checkdomain(domain, ips='', cnames=''):
    "Usage: %prog -i ip1,ip1... -c cname1,cname2... <domain>"

    if not ips or not cnames:
        print checkdomain.__doc__
        return

    # ammo:
    # ips = ['107.20.228.0']
    # cnames = ['app.someammo.com.', 'get.someammo.com.']

    # tank:
    # ips = ['50.19.217.65']
    # cnames = ['withtank.com.']

    ips_list = [ip.strip() for ip in ips.split(',')]
    cnames_list = [cname.strip() for cname in cnames.split(',')]

    report = find_domain_problems(domain, ips_list, cnames_list)

    records = report.get('records', None)
    errors = report.get('errors', None)
    warnings = report.get('warnings', None)

    if records:
        print "RECORDS:"
        root = report['records']['@']
        if root['type'] == 'A':
            print "%s A %s" % (domain, root['address'])
        elif root['type'] == 'CNAME':
            print "%s CNAME %s" % (domain, root['target'])

        if 'www' in report['records']:
            www = report['records']['www']
            if www['type'] == 'A':
                print "www.%s A %s" % (domain, www['address'])
            elif www['type'] == 'CNAME':
                print "www.%s CNAME %s" % (domain, www['target'])

    if errors:
        print
        print "ERRORS:"
        print '\n'.join(errors)

    if warnings:
        print
        print "WARNINGS:"
        print '\n'.join(warnings)

    if not errors and not warnings:
        print "OK"


if __name__ == "__main__":
    optfunc.run(checkdomain)

