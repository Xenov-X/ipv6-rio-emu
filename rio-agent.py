#!/usr/bin/env python3
import os, sys, time, threading, subprocess, logging
from scapy.all import (AsyncSniffer, sendp, Ether, IPv6, ICMPv6ND_RS,
                       ICMPv6ND_RA, ICMPv6NDOptRouteInfo)

IFACE     = os.environ.get("IFACE", "eth0")
MAX_PLEN  = int(os.environ.get("MAX_PLEN", "64"))     # your accept_ra_rt_info_max_plen equivalent
MIN_PLEN  = int(os.environ.get("MIN_PLEN", "0"))
ALLOW_DEF = os.environ.get("ALLOW_DEFAULT", "0") == "1"  # honour ::/0 in a RIO
RS_EVERY  = int(os.environ.get("RS_INTERVAL", "300"))
REASSERT  = int(os.environ.get("REASSERT_INTERVAL", "30"))
# RFC 4191 prf: 1=high, 0=medium, 3=low(-1)
METRIC    = {1: 1024, 0: 2048, 3: 4096}

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(message)s")
log = logging.getLogger("rio")
routes, lock = {}, threading.Lock()   # (prefix, via) -> {"metric":int, "expires":float|None}

def ip(*args, check=False):
    r = subprocess.run(["ip", "-6", "route", *args],
                       capture_output=True, text=True)
    if r.returncode and check:
        log.warning("ip -6 route %s -> %s", " ".join(args), r.stderr.strip())
    return r.returncode == 0

def install(prefix, via, metric):
    ip("replace", prefix, "via", via, "dev", IFACE,
       "metric", str(metric), "proto", "static", check=True)

def remove(prefix, via, metric):
    ip("del", prefix, "via", via, "dev", IFACE, "metric", str(metric))

def handle(pkt):
    # A dissection failure on one packet must not take down the capture thread.
    try:
        handle_ra(pkt)
    except Exception as e:
        log.warning("error handling RA: %s", e)

def handle_ra(pkt):
    src = pkt[IPv6].src
    if not src.lower().startswith("fe80"):
        log.debug("ignoring RA from non-link-local %s", src)
        return
    opt = pkt[ICMPv6ND_RA].payload
    while opt:
        if isinstance(opt, ICMPv6NDOptRouteInfo):
            prefix = f"{opt.prefix}/{opt.plen}"
            if opt.plen > MAX_PLEN or opt.plen < MIN_PLEN:
                log.info("skip %s (plen policy)", prefix)
            elif opt.plen == 0 and not ALLOW_DEF:
                log.info("skip ::/0 RIO from %s (ALLOW_DEFAULT=0)", src)
            else:
                key    = (prefix, src)
                metric = METRIC.get(opt.prf, 2048)
                life   = opt.rtlifetime
                with lock:
                    if life == 0:
                        if key in routes:
                            remove(*key, routes.pop(key)["metric"])
                            log.info("withdraw %s via %s", prefix, src)
                    else:
                        old = routes.get(key)
                        if old and old["metric"] != metric:
                            remove(*key, old["metric"])
                        exp = None if life == 0xffffffff else time.time() + life
                        routes[key] = {"metric": metric, "expires": exp}
                        install(prefix, src, metric)
                        if not old:
                            log.info("install %s via %s metric %d life %s",
                                     prefix, src, metric, life)
        opt = opt.payload

def solicit():
    while True:
        try:
            sendp(Ether(dst="33:33:00:00:00:02") / IPv6(dst="ff02::2") /
                  ICMPv6ND_RS(), iface=IFACE, verbose=0)
        except Exception as e:
            log.warning("RS failed: %s", e)
        time.sleep(RS_EVERY)

def maintain():
    while True:
        time.sleep(REASSERT)
        now = time.time()
        with lock:
            for key, st in list(routes.items()):
                if st["expires"] and st["expires"] <= now:
                    remove(*key, st["metric"]); routes.pop(key)
                    log.info("expire %s via %s", *key)
                else:
                    install(*key, st["metric"])   # idempotent; survives DSM flushes

if __name__ == "__main__":
    if not os.path.exists(f"/sys/class/net/{IFACE}"):
        sys.exit(f"interface {IFACE} not present (host networking? ovs_eth0?)")
    sniffer = AsyncSniffer(iface=IFACE, filter="icmp6",
                           lfilter=lambda p: ICMPv6ND_RA in p, prn=handle,
                           store=False)
    sniffer.start()
    # AsyncSniffer.start() returns before the capture thread has set up its
    # socket, and .running stays True even once that thread is dead, so poll
    # the thread itself. Without this a missing libpcap (or any BPF compile
    # failure) is completely silent: no logs, no routes, process still alive.
    time.sleep(1)
    if not (sniffer.thread and sniffer.thread.is_alive()):
        sys.exit(f"capture thread died starting up on {IFACE} "
                 "(libpcap missing, or filter unsupported)")
    log.info("watching %s max_plen=%d min_plen=%d allow_default=%s "
             "rs_interval=%d reassert_interval=%d",
             IFACE, MAX_PLEN, MIN_PLEN, ALLOW_DEF, RS_EVERY, REASSERT)
    threading.Thread(target=solicit,  daemon=True).start()
    threading.Thread(target=maintain, daemon=True).start()
    while True:
        time.sleep(REASSERT)
        if not sniffer.thread.is_alive():
            sys.exit(f"capture thread on {IFACE} died; exiting for restart")
