import dns.query
import dns.message
import dns.name
import dns.flags
import dns.dnssec
import sys
import random

""" This is the DNSSEC resolver implementation """

roots = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10',
          '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17',
          '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

anchor_key1 = dns.rrset.from_text('.', 1, 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=')
anchor_key2 = dns.rrset.from_text('.', 1, 'IN', 'DNSKEY', '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=')

def get_dnskey(response):
    for rrset in response.answer:
        if rrset.rdtype == 48:
            return rrset

# Looks like DS record always shows up in authority section
def get_ds(response):
    for rrset in response.authority:
        if rrset.rdtype == 43:
            return rrset

def get_rrsig(response):
    for rrset in response.authority:
        if rrset.rdtype == 46:
            return rrset

def get_IP_from_answer(response):
    for rrset in response.answer:
        if rrset.rdtype == 1:
            return rrset

def get_NS_from_answer(response):
    for rrset in response.answer:
        if rrset.rdtype == 2:
            return rrset

def get_MX_from_answer(response):
    for rrset in response.answer:
        if rrset.rdtype == 15:
            return rrset

def get_publicKSK(dnskey):
    for key in dnskey:
        if key.flags == 257:
            return key

def dnssecResolve1(domainText, askWhoIPList, dnsType):
    domain = dns.name.from_text(domainText)
    labels = domain.labels
    # first thing is to verify the root zone:
    if askWhoIPList == roots: #Only when we are asking root servers we verify root zone
        request = dns.message.make_query('.', dns.rdatatype.DNSKEY, want_dnssec=True, payload=2048)
        while True:
            try:
                response = dns.query.udp(request, roots[random.randint(0, len(roots)-1)], timeout=3)
            except dns.exception.Timeout:
                continue
            except OSError:
                continue
            else:
                break
        dnskey = get_dnskey(response)
        if type(dnskey) == None:
            print("No DNSKEY received from root.\n")
            return
        for key in dnskey:
            if key.flags == 257:
                if key.to_text() == anchor_key1.items[0].to_text() or key.to_text() == anchor_key2.items[0].to_text():
                    print("This is real root.\n")
                else:
                    print("Root validation failed.\n")
                    return
    
    if dnsType == 'A':
        request = dns.message.make_query(domainText, dns.rdatatype.A, want_dnssec=True, payload=2048)
    elif dnsType == 'NS':
        request = dns.message.make_query(domainText, dns.rdatatype.NS, want_dnssec=True, payload=2048)
    elif dnsType == 'MX':
        request = dns.message.make_query(domainText, dns.rdatatype.MX, want_dnssec=True, payload=2048)
    else:
        print('Unknown DNS type.\n')
        return
    
    while True:
        try:
            response = dns.query.udp(request, askWhoIPList[random.randint(0, len(askWhoIPList)-1)], timeout=3)
        except dns.exception.Timeout:
            continue
        except OSError:
            continue
        else:
            break

    if len(response.answer) == 0 and len(response.additional) == 0:
        print('Not able to resolve.\n')
        return

    if dnsType == 'A':
        answer = get_IP_from_answer(response)
        #print(response.authority)
        if answer is not None:
            print('The answer is:', answer.items[0].to_text())
            return
    if dnsType == 'NS':
        answer = get_NS_from_answer(response)
        if answer is not None:
            print('The answer is:', answer.items[0].to_text())
            return
    if dnsType == 'MX':
        answer = get_MX_from_answer(response)
        if answer is not None:
            print('The answer is:', answer.items[0].to_text())
            return

    DS = get_ds(response)
    if DS is None:
        print('DNSSEC not supported\n')
        return
    currentSubDomain = DS.name.to_text()
    nameSubDomain = dns.name.from_text(currentSubDomain)

    # Now send request to get DNSKEY record
    current_NSs = []
    for ns in response.additional:
        if ns.rdtype == 1:
            current_NSs.append(ns.items[0].to_text())
    key_request = dns.message.make_query(currentSubDomain, dns.rdatatype.DNSKEY, want_dnssec=True, payload=2048)
    #print(response.answer)
    #print(response.additional)
    #print(response.authority)
    while True:
        try:
            key_response = dns.query.udp(key_request, current_NSs[random.randint(0, len(current_NSs)-1)], timeout=3)
        except dns.exception.Timeout:
            continue
        except OSError:
            continue
        else:
            break
    dnskey = get_dnskey(key_response)
    # Verify DNSKEY record
    try:
        dns.dnssec.validate(key_response.answer[0], key_response.answer[1], {nameSubDomain:dnskey})
    except dns.dnssec.ValidationFailure:
        print('DNSKEY validation failed.\n')
        return
    else:
        print('DNSKEY validation succeed.\n')
    # Verify DS record
    rrsig = get_rrsig(response)
    #print(rrsig)
    #print(dnskey)
    #print(response.authority)
    name = DS.name

    while True:
        try:
            response = dns.query.udp(request, current_NSs[random.randint(0, len(current_NSs)-1)], timeout=3)
        except dns.exception.Timeout:
            continue
        except OSError:
            continue
        else:
            break

    #print(response.authority)
    if len(response.authority) >= 3:
        try:
            dns.dnssec.validate(response.authority[1], response.authority[2], {name:dnskey})
        except dns.dnssec.ValidationFailure:
            print('DS validation failed.\n')
            return
        else:
            print('DS validation succeed.\n')

    # Verify zone
    publicKSK = get_publicKSK(dnskey)
    tempDS = dns.dnssec.make_ds(name, publicKSK, 'SHA256' if DS.items[0].digest_type==2 else 'SHA1')
    if tempDS == DS.items[0]:
        print('Zone validation succeed.\n')
    else:
        print('Zone validation failed.\n')
        return

    return dnssecResolve1(domainText, current_NSs, dnsType)

if __name__ == '__main__':
    dnssecResolve1(sys.argv[1], roots, sys.argv[2])