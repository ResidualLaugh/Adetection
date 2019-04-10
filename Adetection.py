#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2019-04-08 11:58:13
# @Author  : Residual Laugh (Residual.Laugh@gmail.com)
# @Link    : https://blog.0xccc.cc

import os
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import optparse
import censys
import censys.certificates
import censys.ipv4

UID = "your censys api UID"
SECRET = "your censys api SECRET"


def getv(d, key):
    if key in d:
        return d[key]
    else:
        return []

def censys_sub_domain(domain):
    print u"[-] Start find subdomains.."
    subdomains = []
    try:
        censys_certificates = censys.certificates.CensysCertificates(api_id=UID, api_secret=SECRET)
        certificate_query = 'parsed.names: %s' % domain
        certificates_search_results = censys_certificates.search(certificate_query, fields=['parsed.names'], max_records = 1000)
        for search_result in certificates_search_results:
            subdomains.extend(search_result['parsed.names'])
        print u"[-] Stop find subdomains.."
        return {'domain': domain,'subdomains':[ subdomain for subdomain in set(subdomains) if '*' not in subdomain and subdomain.endswith(domain) ]}
    except censys.base.CensysUnauthorizedException:
        print '[-] Your Censys credentials look invalid.\n'
    except censys.base.CensysRateLimitExceededException:
        print '[-] Looks like you exceeded your Censys account limits rate. Exiting\n'
    except censys.base.CensysException as e:
        # catch the Censys Base exception, example "only 1000 first results are available"
        print '[-] Something bad happened, ' + repr(e)
    finally:
        return {'domain': domain,'subdomains': [ subdomain for subdomain in set(subdomains) if '*' not in subdomain and subdomain.endswith(domain) ]}

def censys_ipv4(domain):
    print u"[-] Start find real ip.."
    results = []
    IPV4_FIELDS = ['ip',
             'ports',
             'location.country',
             'location.province',
             'updated_at',
             '80.http.get.title',
             '80.http.get.headers.server',
             '443.https.get.title',
             '443.https.get.headers.server',
             '443.https.tls.certificate.parsed.subject_dn',
             '443.https.tls.certificate.parsed.names',
             '443.https.tls.certificate.parsed.subject.common_name',
             '443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names',
             '25.smtp.starttls.tls.certificate.parsed.names',
             '25.smtp.starttls.tls.certificate.parsed.subject_dn',
             '110.pop3.starttls.tls.certificate.parsed.names',
             '110.pop3.starttls.tls.certificate.parsed.subject_dn']
    try:
        c = censys.ipv4.CensysIPv4(api_id=UID, api_secret=SECRET)
        data = list(c.search("(80.http.get.status_code: 200 or 443.https.get.status_code: 200) and 443.https.tls.certificate.parsed.names: %s or 25.smtp.starttls.tls.certificate.parsed.names: %s or 110.pop3.starttls.tls.certificate.parsed.names: %s" %(domain,domain,domain), IPV4_FIELDS, max_records = 1000))
        if len(data)>999:
            data = data[:999]
        for i in data:
            results.append({'ip': i['ip'],
                    'ports': i['ports'],
                    'location': getv(i,'location.country') or '' + ' ' + getv(i,'location.province') or '',
                    'updated_at': i['updated_at'],
                    'title': {'80': getv(i,'80.http.get.title'),'443': getv(i,'443.https.get.title')},
                    'server': {'80': getv(i,'80.http.get.headers.server'),'443': getv(i,'443.https.get.headers.server')},
                    'names': list(set(getv(i,'443.https.tls.certificate.parsed.names')+getv(i,'443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names')+getv(i,'25.smtp.starttls.tls.certificate.parsed.names')+getv(i,'110.pop3.starttls.tls.certificate.parsed.names')))
                    })
        print u"[-] Stop find real ip.."
        return results
    except censys.base.CensysUnauthorizedException:
        print '[-] Your Censys credentials look invalid.\n'
    except censys.base.CensysRateLimitExceededException:
        print '[-] Looks like you exceeded your Censys account limits rate. Exiting\n'
    except censys.base.CensysException as e:
        # catch the Censys Base exception, example "only 1000 first results are available"
        print '[-] Something bad happened, ' + repr(e)
    finally:
        return results

def output(domain,subdomains,results):
    y_domains = []
    with open(os.path.join(domain+'.txt'),'w') as f:
        for result in results:
            y_domains += result['names']
            print result['ip']+'\t'+','.join(result['names'])+'\t'+','.join('%s' %port for port in result['ports'])+'\t80:'+''.join(result['server']['80'])+'  '+''.join(result['title']['80'])+'\t443:'+''.join(result['server']['443'])+'  '+''.join(result['title']['443'])
            f.writelines(str(result['ip']+'\t'+','.join(result['names'])+'\t'+','.join('%s' %port for port in result['ports'])+'\t80:'+''.join(result['server']['80'])+'  '+''.join(result['title']['80'])+'\t443:'+''.join(result['server']['443'])+'  '+''.join(result['title']['443']))+'\n')
        print u"[-] No real IP was found in the following domain names"
        print ' '.join(set(subdomains) - set(y_domains))
        f.writelines('\n\nNo real IP was found in the following domain names\n')
        for sdomain in list(set(subdomains) - set(y_domains)):
            f.writelines(sdomain+'\n')
        print u"[-] The above information has been output to %s" %os.path.join(domain+'.txt')

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: %prog target.com', version="%prog 1.0.0")
    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit(0)
    domain = args[0]
    subdomains = censys_sub_domain(domain)
    subdomains = subdomains['subdomains']
    results = censys_ipv4(domain)
    output(domain,subdomains,results)

