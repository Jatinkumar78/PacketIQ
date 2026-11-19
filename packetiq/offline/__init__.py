"""
Offline recovery — the steps a responder does away from the wire.

Everything else in PacketIQ reads what the packets contain and refuses to invent
what they do not. This package is the deliberate, opt-in exception: given the
credential material the capture exposes, it performs the offline work an analyst
would otherwise do by hand — cracking an AS-REP roast against a wordlist, and,
with the recovered password, decrypting an NTLM-sealed WinRM session to read the
commands that ran. It is never part of the normal detection pipeline; it runs
only when the user asks for it (`packetiq crack`), because it crosses from
"reading the wire" into "attacking recovered material", and because it needs a
wordlist the user supplies.
"""
