#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pypopper: a file-based pop3 server
    Usage:
    python pypopper.py <host> <port>
"""

import logging
import os
import socket
import sys
import traceback

import crypt

logging.basicConfig(format="%(name)s %(levelname)s - %(message)s")
log = logging.getLogger("pypopper")
log.setLevel(logging.DEBUG)
messages=[]
class ChatterboxConnection(object):
    END = "\r\n"
    def __init__(self, conn):
        self.conn = conn
        self.user = ""
        self.aliasa = ""
    def __getattr__(self, name):
        return getattr(self.conn, name)
    def sendall(self, data, END=END):
        if len(data) < 50:
            log.debug("send: %r", data)
        else:
            log.debug("send: %r...", data[:50])
        data += END
        self.conn.sendall(data)

    def recvall(self, END=END):
        usera=""
        data = []
        while True:
            chunk = self.conn.recv(4096)
            if not chunk: break
            if END in chunk:
                data.append(chunk[:chunk.index(END)])
                break
            data.append(chunk)
            if len(data) > 1:
                pair = data[-2] + data[-1]
                if END in pair:
                    data[-2] = pair[:pair.index(END)]
                    data.pop()
                    break

        if data[0].split(" ")[0]=="USER":
            self.user = data[0].split(" ")[1]
            print "Le login donner "+self.user
            alias = open('/etc/mail/aliases','r')
            ase = alias.read()
            a = ase.split("\n")
            print "recherche du compte correspondant..."
            for elt in a:
                if len(elt)<1:
                    print "ligne vide"
                    print "fin."
                    break
                print "ligne non vide"
                try:
                    usera = elt.split(": ")[0]
                    self.aliasa = elt.split(": ")[1]
                    if usera==self.user:
                        ali=self.aliasa

                        print "Un compte a ete trouve ("+ali+")"
                        break
                except:
                    print "Ne trouve pas l'utilisateur correspondant"
            alias.close()

        if data[0].split(" ")[0]=="PASS":
            passwz = data[0].split(" ")[1]
            print "Le mot de passe donner est "+passwz
            path_sha = "/etc/shadow" #ouverture du ficier shadow
            pss = open(path_sha,'r')
            shline = pss.read() # rendre lisible le shadpw
            fsh = shline.split("\n") #convertir en liste de lignes
            print "recherche du compte correspondant..."
            for elt in fsh: #parcourir chaque ligne
                if len(elt)<1:
                    print "ligne vide"
                    print "fin"
                    break
                if elt.split(":")[0]==self.user:
                    shadow_hash = elt.split(":")[1]
                    print "Recherche dans le fichier shadow :\n"+shadow_hash
                    request_hash = crypt.crypt(passwz, "$6$"+elt.split("$6$")[1].split("$")[0]) # genere ligne shadow
                    print "hash du pass propose :\n"+request_hash
                    try:
                        if request_hash != shadow_hash:
                            return false
                        else:
                            print "le mot de passe est bon"
                            print "le compte est"+self.aliasa+" listing :"
                            listing(self.aliasa,messages)
                            break
                    except:
                        print "le mdp nest pas bon"
            pss.close()
        log.debug("recv: %r", "".join(data))
        return "".join(data)

class Message(object):
    def __init__(self, filename):
        msg = open(filename, "r")
        try:
            self.data = data = msg.read()
            self.size = len(data)
            self.top, bot = data.split("\n\n", 1)
            self.bot = bot.split("\n")
        finally:
            msg.close()

def handleUser(unused1, unused2):
    return "+OK user accepted"

def handlePass(unused1, unused2):
    return "+OK pass accepted"

def handleStat(unused1,messages):
    size = 0
    for msg in messages:
        size += msg.size
    return "+OK %i %i" % (len(messages), size)

def handleList(data, messages):
    if data:
        try:
            msgno = int(data)
            msg = messages[msgno-1]
            return "+OK %i %i" % (msgno, msg.size)
        except Exception:
            return "-ERR bad data %s" % data

    size = 0
    s = []
    msgno =1
    for msg in messages:
        s.append("%i %i\r\n" % (msgno, msg.size))
        size += msg.size
        msgno += 1

    s.insert(0,"+OK %i messages (%i octets)\r\n" % (len(messages), size))
    s.append('.')

    return ''.join(s)

def handleUidl(data, messages):
    if data:
        return "-ERR unhandled %s" %data

    s = []
    s.append("+OK unique-id listing follows\r\n")
    msgno =1
    for msg in messages:
        s.append("%i %i\r\n" % (msgno, msgno))
        msgno += 1

    s.append('.')

    return ''.join(s)

def handleTop(data, messages):
    num, lines = data.split()
    try:
        num = int(num)
        lines = int(lines)
        msg = messages[num-1]
        text = msg.top + "\r\n\r\n" + "\r\n".join(msg.bot[:lines])
        return "+OK top of message follows\r\n%s\r\n." % text
    except Exception:
        return "-ERR bad data %s" % data

def handleRetr(data, messages):
    try:
        msgno = int(data)
        msg = messages[msgno-1]
        return "+OK %i octets\r\n%s\r\n." % (msg.size, msg.data)
        log.info("message %i sent",msgno)
    except Exception:
        return "-ERR bad msgno %s" % data

def handleDele(unused1, unused2):
    return "+OK message 1 deleted "

def handleNoop(unused1, unused2):
    return "+OK"

def handleQuit(unused1, unused2):
    return "+OK pypopper POP3 server signing off"

dispatch = dict(
    USER=handleUser,
    PASS=handlePass,
    STAT=handleStat,
    LIST=handleList,
    UIDL=handleUidl,
    TOP=handleTop,
    RETR=handleRetr,
    DELE=handleDele,
    NOOP=handleNoop,
    QUIT=handleQuit,
)

follow=""
def serve(host, port,messages):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    try:
        if host:
            hostname = host
        else:
            hostname = "127.0.0.1"
        log.info("serving POP3 on %s:%s", hostname, port)

        while True:
            sock.listen(1)
            conn, addr = sock.accept()
            log.debug('Connected by %s', addr)
            try:
                conn = ChatterboxConnection(conn)
                conn.sendall("+OK pypopper file-based pop3 server ready")
                while True:
                    data = conn.recvall()
                    if not data: break
                    list = data. split(None, 1)
                    command = list[0]
                    if len(list) > 1:
                        param = list[1]
                    else:
                        param = None
                    try:
                        cmd = dispatch[command]
                    except KeyError:
                        conn.sendall("-ERR unknown command")
                    else:
                        result = cmd(param, messages)
                        try:
                            conn.sendall(result)
                        except Exception:
                            # socket might go away during sendall
                            break
                        if cmd is handleQuit:
                            messages=[]
                            follow=""
                            break
            finally:
                conn.close()
    except (SystemExit, KeyboardInterrupt):
        log.info("pypopper stopped")
    except Exception, ex:
        log.critical("fatal error", exc_info=ex)
    finally:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

def listing(follow,messages):
    papat="/home/"+follow+"/Maildir/new/"
    if not os.path.exists(papat):
        print "Path not found:"
    print "Serving :"
    for elt2 in os.listdir(papat):
        pathfile = papat+elt2
        print pathfile
        try:
            messages.append(Message(pathfile))
        except:
            print "message non ajoute"
            break
        os.remove(pathfile)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print __doc__
        sys.exit(0)

    host = ""
    port = sys.argv.pop(1)
    if ":" in port:
        host = port[:port.index(":")]
        port = port[port.index(":") + 1:]
    try:
        port = int(port)
    except Exception:
        print "Unknown port:", port
        sys.exit(1)
    sys.argv.pop(0)

    serve(host, port,messages)
