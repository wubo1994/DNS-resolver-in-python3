import dns.query
import dns.message
import dns.name
import dns.flags
import sys
import random
import time

""" 13 root servers' IP address """
roots = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10',
          '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17',
          '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']


def resolve(domainText, askWhoIPList, dnsType):
    domain = dns.name.from_text(domainText)
    if dnsType == 'A':
        request = dns.message.make_query(domainText, dns.rdatatype.A)
    elif dnsType == 'NS':
        request = dns.message.make_query(domainText, dns.rdatatype.NS)
    elif dnsType == 'MX':
        request = dns.message.make_query(domainText, dns.rdatatype.MX)
    else:
        print("Unknown DNS type.\n")
    
    while True:
        try:
            response = dns.query.udp(request, askWhoIPList[random.randint(0, len(askWhoIPList)-1)], timeout=3)
        except dns.exception.Timeout:
            continue
        except OSError:
            #print("OSError.\n")
            continue
        else:
            break

    if len(response.answer) != 0:
        rt = []
        # Here if rrset.rdtype == 5, it is CNAME
        for rrset in response.answer:
            if rrset.rdtype != 5:
                rt.append(rrset.items[0].to_text())
            elif rrset.rdtype == 5:
                return resolve(rrset.items[0].to_text(), roots, dnsType)
        return rt
    elif len(response.additional) != 0:
        IPs = []
        for rrset in response.additional:
            IPs.append(rrset.items[0].to_text())
        return resolve(domainText, IPs, dnsType)
    elif len(response.authority) != 0:
        authoDomain = []
        for rrset in response.authority:
            authoDomain.append(rrset.items[0])
        return resolve(domainText, resolve(authoDomain[0].to_text(), roots, 'A'), dnsType)
    else:
        print("Not able to find result.\n")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Please pass in correct arguments.\n")
    else:
        questionSec = sys.argv[1]+'    '+'IN'+'    '+sys.argv[2]+'\n'
        begin = time.time()
        answer = resolve(sys.argv[1], roots, sys.argv[2])
        timeElapsed = time.time() - begin
        answerSec = sys.argv[1]+'   '+'IN'+'    '+sys.argv[2]+'     '+answer[0]+'\n'
        print(answerSec)
        print(time.asctime(time.localtime(time.time())))
        print('QUESTION SECTION:')
        print(questionSec)
        print('ANSWER SECTION:')
        print(answerSec)
        print('Query time:',int(timeElapsed*1000), 'msec\n')
        print('WHEN:', time.asctime(time.localtime(time.time())))

    