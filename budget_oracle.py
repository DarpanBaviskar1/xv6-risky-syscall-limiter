#!/usr/bin/env python3
"""
budget_oracle.py - the expectations for the irreversibility budget, kept off
the machine being tested.

user/scenarios.c runs shaped workloads and emits a trace of every operation
with the kernel's policy and counter deltas around it. It asserts nothing. This
script re-implements the token-bucket rules from first principles, works out
what each operation should have done, and diffs that against what the kernel
says it did. Agreement is the result; a disagreement is a bug report with the
offending operation quoted.

Why the expectations live here: a test that derives its expectations from the
code under test cannot find a bug in that code. The kernel publishes its cost
table through budgetinfo() and the guest prices every operation from that table,
so both sides work from one source of truth - while the RULES (who pays, how
much, when a wait happens, what a refusal returns, what a policy change must not
do) are re-derived here and graded against the lab sheet.

    python3 budget_oracle.py <qemu-log> [--verbose] [--json out.json]

Exit status is 0 only if every derived expectation matched.
"""

import json
import re
import sys

# ---------------------------------------------------------------------------
# The lab sheet, Question 1. This is the authority the kernel is graded against,
# spelled out here rather than read from the kernel, so a kernel that quietly
# changed its prices fails instead of teaching its own test to agree.
# ---------------------------------------------------------------------------
LAB_COSTS = {
    "unlink": 10,          # deleting a file: irreversible
    "console": 1,          # every write to the console
    "ownwrite": 0,         # write to a file the group itself owns
    "foreignwrite": 3,     # write to a file another group owns
    "foreignexec": 5,      # exec of a binary another group wrote
    "ownexec": 0,
}
LAB_GROUPS = 20          # the size of the group table
LAB_DENIED = -42         # a refusal must be distinguishable from a failed syscall
# The cost table above is the lab sheet. The group count is NOT: 16 was this
# project's own choice, and Step 4 raised it to 20 to reserve ids for the
# confinement cell, its decoy and the upstream suite without any two of them
# sharing a bucket. It is pinned here anyway, because a group table that quietly
# shrinks would hide a group from every check in this file.
TAGS = ("PARAMS", "SCN", "OP", "DATA", "RES", "FAN", "EDGE", "WARN", "ABORT", "DONE")

# Classes that never reach the bucket at all, so no counter may ever move on
# their account - not even when the group's budget is zero and its mode is FAIL.
FREE_KINDS = ("ownwrite", "ownexec", "pipe", "report", "idle")

# How a trace class name maps onto a field of the published table. Anything the
# table does not price is free by definition, so it is absent here.
PRICE_FIELDS = {
    "unlink": "unlink",
    "console": "console",
    "ownwrite": "ownwrite",
    "foreignwrite": "foreignwrite",
    "foreignexec": "foreignexec",
    "ownexec": "ownexec",
    "pipe": "pipe",
}


def kv(fields):
    out = {}
    for part in fields:
        if "=" in part:
            key, _, value = part.partition("=")
            out[key] = value
    return out


def records(path):
    """Yield (tag, payload) for every trace record, ignoring console noise.

    A granted console write can land in front of a trace line - that is the
    logger scenario working as designed - so a record is found by its bracket
    rather than by the start of the line.
    """
    with open(path, "r", errors="replace") as handle:
        for raw in handle:
            start = raw.find("[")
            if start < 0:
                continue
            match = re.match(r"\[([A-Z]+)\],?(.*)", raw[start:].strip())
            if match and match.group(1) in TAGS:
                yield match.group(1), match.group(2)


class Trace:
    """Everything one run reported, grouped by scenario."""

    def __init__(self, path):
        self.path = path
        self.params = {}
        self.scenarios = {}
        self.order = []
        self.edges = []
        self.warns = []
        self.aborts = []
        self.done = False
        self.raw = list(records(path))
        self._group()

    def _group(self):
        for tag, payload in self.raw:
            parts = payload.split(",")
            if tag == "PARAMS":
                self.params = {k: int(v) for k, v in kv(parts).items()}
            elif tag == "SCN":
                sc = kv(parts[2:])
                sc["id"], sc["name"] = parts[0], parts[1]
                for key in ("gid", "max", "refill", "mode", "budget", "ops", "atomic"):
                    sc[key] = int(sc[key])
                sc.update({"log": [], "kids": [], "data": [], "res": None})
                self.scenarios[sc["id"]] = sc
                self.order.append(sc["id"])
            elif tag == "OP":
                op = {"id": parts[0], "i": int(parts[1]), "kind": parts[2]}
                op.update({k: int(v) for k, v in kv(parts[3:]).items()})
                sc = self.scenarios.get(op["id"])
                if sc is not None:
                    sc["log"].append(op)
            elif tag == "DATA":
                sc = self.scenarios.get(parts[0])
                if sc is not None:
                    sc["data"].append((int(parts[1]), int(parts[2])))
            elif tag == "RES":
                sc = self.scenarios.get(parts[0])
                if sc is not None:
                    sc["res"] = {k: int(v) for k, v in kv(parts[1:]).items()}
            elif tag == "FAN":
                kid = {"id": parts[0], "kid": int(parts[1])}
                kid.update({k: int(v) for k, v in kv(parts[2:]).items()})
                sc = self.scenarios.get(parts[0])
                if sc is not None:
                    sc["kids"].append(kid)
            elif tag == "EDGE":
                row = {"name": parts[0]}
                row.update(kv(parts[1:]))
                self.edges.append(row)
            elif tag == "WARN":
                self.warns.append(payload)
            elif tag == "ABORT":
                self.aborts.append(payload)
            elif tag == "DONE":
                self.done = True


class Oracle:
    """Derive expectations from the published table, then diff them."""

    def __init__(self, trace, verbose=False, muted=False):
        self.t = trace
        self.verbose = verbose
        # A plot script runs the oracle to collect rows; it should not have to
        # reprint the whole terminal report first. Failures always print.
        self.muted = muted
        self.checks = 0
        self.fails = 0
        self.failures = []
        self.rows = []
        self.p = trace.params

    # ---- reporting -------------------------------------------------------
    def say(self, text):
        if not self.muted:
            print(text)

    def check(self, ok, label, detail=""):
        self.checks += 1
        if ok:
            if self.verbose:
                print("  [PASS] %s%s" % (label, (" (" + detail + ")") if detail else ""))
        else:
            self.fails += 1
            self.failures.append(label)
            print("  [FAIL] %s%s" % (label, (" -> " + detail) if detail else ""))
        return ok

    def cost(self, kind):
        """Price a class from the table the kernel published in this very run."""
        field = PRICE_FIELDS.get(kind)
        return self.p[field] if field else 0

    def mode_name(self, mode):
        return "BLOCK" if mode == self.p["block"] else "FAIL"

    # ---- layer 1: is the published table the table the lab asked for? ----
    def check_params(self):
        self.say("\n== published cost table ==")
        for kind in sorted(LAB_COSTS):
            self.check(self.cost(kind) == LAB_COSTS[kind],
                       "%s costs %d as the lab specifies" % (kind, LAB_COSTS[kind]),
                       "kernel publishes %d" % self.cost(kind))
        self.check(self.p.get("ngroup") == LAB_GROUPS, "ngroup is %d" % LAB_GROUPS,
                   "kernel publishes %d" % self.p.get("ngroup", -1))
        self.check(self.p.get("denied") == LAB_DENIED,
                   "a refusal returns %d" % LAB_DENIED,
                   "kernel publishes %d" % self.p.get("denied", 0))
        # Being negative and being DISTINCT are the two properties the harness
        # relies on: a program that cannot tell "cannot afford it" from "not
        # allowed to ask" cannot report which one it hit.
        self.check(self.p.get("noauth", 0) < 0 and
                   self.p.get("noauth") != self.p.get("denied"),
                   "a policy call without authority has its own negative sentinel",
                   "denied=%s noauth=%s" % (self.p.get("denied"), self.p.get("noauth")))
        self.check(self.p.get("block") == 0 and self.p.get("fail") == 1,
                   "mode constants are BLOCK=0, FAIL=1")
        self.check(self.p.get("period", 0) > 0, "the refill period is positive",
                   "period=%d ticks" % self.p.get("period", 0))

    # ---- layer 2: the bucket rules, operation by operation ---------------
    def decide(self, sc, op):
        """What the engine must have done, from the state it itself reported.

        The lab's rule written out as code: pay the price or do not run. BLOCK
        is a wait only where waiting can help - if the ceiling is below the
        price, or nothing ever refills, sleeping is a hang rather than a delay,
        so the engine has to deny. A price of zero never reaches the bucket.
        """
        cost = self.cost(op["kind"])
        affordable = op["bb"] >= cost
        hopeless = sc["max"] < cost or sc["refill"] <= 0
        can_wait = sc["mode"] == self.p["block"] and not hopeless
        if cost <= 0:
            return dict(cost=0, ran=True, denied=False, waited=False, free=True)
        if affordable or can_wait:
            return dict(cost=cost, ran=True, denied=False,
                        waited=not affordable, free=False)
        return dict(cost=cost, ran=False, denied=True, waited=False, free=False)

    def check_scenario(self, sc):
        """Run the model over one atomic scenario and diff every field it predicts."""
        sid, period = sc["id"], self.p["period"]
        strict = sc["refill"] == 0  # with no accrual the whole run is closed-form

        self.say("\n== %s (%s): gid %d, max %d, refill %d, mode %s ==" % (
            sid, sc["name"], sc["gid"], sc["max"], sc["refill"], self.mode_name(sc["mode"])))

        # The trace must be complete. A lost line used to be able to swallow a
        # whole verdict, so the operation count is itself under test.
        self.check(len(sc["log"]) == sc["ops"], "%d operations traced" % sc["ops"],
                   "saw %d" % len(sc["log"]))

        grants = refusals = waits = free_ops = spend = 0
        prev_bb = prev_deduct = prev_t = None
        for op in sc["log"]:
            want = self.decide(sc, op)
            grants += 1 if want["ran"] else 0
            refusals += 1 if want["denied"] else 0
            waits += 1 if want["waited"] else 0
            free_ops += 1 if want["free"] else 0
            paid = want["cost"] if (want["ran"] and not want["free"]) else 0
            spend += paid

            # 1. the decision the kernel reports is the decision the rule gives
            if want["denied"]:
                self.check(op["res"] == 1, "op %d %s with bb=%d must be denied" % (op["i"], op["kind"], op["bb"]),
                           "kernel returned res=%d; res=2 would mean the syscall failed on its own, not on policy" % op["res"])
            elif want["free"]:
                self.check(op["res"] in (0, 3), "op %d %s ran free" % (op["i"], op["kind"]),
                           "res=%d" % op["res"])
            else:
                self.check(op["res"] == 0, "op %d %s with bb=%d must be granted" % (op["i"], op["kind"], op["bb"]),
                           "res=%d" % op["res"])

            # 2. the price charged is the published price of that class
            self.check(op["exp"] == want["cost"], "op %d %s priced at %d" % (op["i"], op["kind"], want["cost"]),
                       "trace says exp=%d" % op["exp"])

            # 3. the counters move exactly as the decision implies
            got = (op["da"], op["db"], op["dr"], op["du"])
            want_moved = (1 if paid else 0, 1 if want["waited"] else 0,
                          1 if want["denied"] else 0, paid)
            self.check(got == want_moved,
                       "op %d counters allowed/blocked/refused/used = %s" % (op["i"], want_moved),
                       "kernel says %s" % (got,))

            # 4. the bucket: predicted exactly where nothing accrues, bounded
            #    by the refill rate where it does
            self.check(0 <= op["bb"] <= sc["max"], "op %d bucket is legal" % op["i"],
                       "bb=%d of max=%d" % (op["bb"], sc["max"]))
            if strict and prev_bb is not None:
                self.check(op["bb"] == prev_bb - prev_deduct,
                           "op %d bucket at %d" % (op["i"], prev_bb - prev_deduct),
                           "kernel says bb=%d" % op["bb"])
            elif prev_bb is not None:
                low = prev_bb - prev_deduct
                bound = ((op["t"] - prev_t) // period + 1) * sc["refill"]
                self.check(low <= op["bb"] <= min(sc["max"], low + bound),
                           "op %d bucket within the accrual it could have earned" % op["i"],
                           "bb=%d, expected %d..%d" % (op["bb"], low, min(sc["max"], low + bound)))
            prev_bb, prev_deduct, prev_t = op["bb"], paid, op["t"]

        # 5. totals: the scenario summary is the sum of its operations
        res = sc["res"]
        if res is None:
            self.check(False, "%s reported a summary" % sid, "no [RES] line")
            return
        want = dict(allowed=grants - free_ops, blocked=waits, refused=refusals,
                    used=spend, granted=grants)
        for field in ("allowed", "blocked", "refused", "used", "granted"):
            self.check(res[field] == want[field], "%s %s = %d" % (sid, field, want[field]),
                       "kernel says %d" % res[field])
        self.check(0 <= res["budget"] <= sc["max"], "%s ends with a legal bucket" % sid,
                   "budget=%d" % res["budget"])
        self.rows.append(dict(id=sid, name=sc["name"], kind=sc["log"][0]["kind"] if sc["log"] else "",
                              gid=sc["gid"], max=sc["max"], refill=sc["refill"],
                              mode=self.mode_name(sc["mode"]), ops=sc["ops"],
                              predict=want, actual={k: res[k] for k in
                                                    ("allowed", "blocked", "refused", "used", "granted")},
                              bucket=sc["budget"], end_bucket=res["budget"]))

    # ---- layer 3: concurrency, where only the aggregate is determined ----
    def check_fanout(self, sc):
        sid, cost = sc["id"], self.cost("unlink")
        self.say("\n== %s (%s): %d children, one bucket ==" % (sid, sc["name"], sc["ops"]))
        self.check(sc["atomic"] == 0, "%s is marked concurrent" % sid)
        self.check(len({k["kid"] for k in sc["kids"]}) == sc["ops"],
                   "every one of %d children reported" % sc["ops"],
                   "saw %d records" % len(sc["kids"]))
        self.check(all(k["rc"] != 2 for k in sc["kids"]),
                   "no child failed for a non-budget reason",
                   "rc=2 would mean its victim was missing, not its budget")
        # Closed-form however the children interleave: with no accrual every
        # grant takes exactly one price out of one shared bucket, so the count
        # of grants is pinned by the starting bucket.
        grants = sum(1 for k in sc["kids"] if k["rc"] == 0)
        want = sc["budget"] // cost
        self.check(grants == want, "grants = floor(%d / %d) = %d" % (sc["budget"], cost, want),
                   "children that ran: %d" % grants)
        self.check(all(k["bb"] >= cost for k in sc["kids"] if k["rc"] == 0),
                   "every child that ran had the price in hand")
        self.check(all(k["bb"] < cost for k in sc["kids"] if k["rc"] == 1),
                   "every child that was denied had less than the price")
        reachable = {sc["budget"] - n * cost for n in range(want + 1)}
        self.check({k["bb"] for k in sc["kids"]} <= reachable,
                   "buckets the children saw are the reachable ones",
                   "saw %s" % sorted({k["bb"] for k in sc["kids"]}))
        res = sc["res"]
        if res:
            self.check(res["allowed"] == want, "%s kernel allowed %d" % (sid, want),
                       "says %d" % res["allowed"])
            self.check(res["refused"] == sc["ops"] - want,
                       "%s kernel refused %d" % (sid, sc["ops"] - want),
                       "says %d" % res["refused"])
            self.check(res["used"] == want * cost, "%s used = %d" % (sid, want * cost),
                       "says %d" % res["used"])
            self.check(res["budget"] == sc["budget"] - want * cost,
                       "%s bucket drained to %d" % (sid, sc["budget"] - want * cost),
                       "says %d" % res["budget"])
            self.check(res["rc_deny"] == sc["ops"] - want and res["rc_err"] == 0,
                       "%s child exit statuses agree with the kernel" % sid,
                       "rc_deny=%s rc_err=%s" % (res.get("rc_deny"), res.get("rc_err")))
        self.rows.append(dict(id=sid, name=sc["name"], kind="unlink", gid=sc["gid"],
                              max=sc["max"], refill=sc["refill"],
                              mode=self.mode_name(sc["mode"]), ops=sc["ops"],
                              predict=dict(allowed=want, blocked=0,
                                           refused=sc["ops"] - want, used=want * cost,
                                           granted=want),
                              actual={k: (res[k] if res else 0) for k in
                                      ("allowed", "blocked", "refused", "used", "granted")},
                              bucket=sc["budget"], end_bucket=(res or {}).get("budget", 0)))

    # ---- layer 4: inputs the engine must refuse --------------------------
    def check_edges(self):
        if not self.t.edges:
            return
        self.say("\n== invalid inputs ==")
        rows = {e["name"]: e for e in self.t.edges}
        for name in ("setbudget_gid_negative", "setbudget_gid_out_of_range",
                     "setbudget_max_negative", "setbudget_refill_negative",
                     "setbudget_mode_unknown", "setgroup_negative",
                     "setgroup_out_of_range", "budgetinfo_bad_address",
                     "getbudgetstat_bad_address"):
            row = rows.get(name)
            if row is None:
                self.check(False, "%s was traced" % name, "record missing")
                continue
            self.check(row.get("rc") == "-1", "%s rejected with -1" % name, "rc=%s" % row.get("rc"))
        rej = rows.get("after_rejects")
        if rej:
            self.check(rej.get("moved") == "0",
                       "five rejected setbudget calls left the policy alone",
                       "max=%s refill=%s mode=%s budget=%s" % (rej.get("max"), rej.get("refill"),
                                                               rej.get("mode"), rej.get("budget")))
        acc = rows.get("accept_good")
        if acc:
            self.check(acc.get("rc") == "0" and acc.get("max") == "11" and
                       acc.get("refill") == "2" and acc.get("mode") == str(self.p["fail"]),
                       "a valid call still lands, so the validator is not refusing everything",
                       "rc=%s max=%s refill=%s mode=%s" % (acc.get("rc"), acc.get("max"),
                                                           acc.get("refill"), acc.get("mode")))
        shell = rows.get("shell_group_untouched")
        if shell:
            self.check(int(shell["max"]) == self.p["dmax"] and
                       int(shell["refill"]) == self.p["drefill"] and
                       int(shell["mode"]) == self.p["block"],
                       "the shell's own group is still at the defaults",
                       "max=%s refill=%s mode=%s" % (shell["max"], shell["refill"], shell["mode"]))

    # ---- layer 5: authority - who is allowed to write policy at all -------
    #
    # An escape attempt is not a charged syscall, so layer 2's bucket model has
    # nothing to say about it: the property under test is that the attempt
    # changes NOTHING. The confined group's actual WORK, on the other hand, is an
    # ordinary traced scenario, so layer 2 grades it with the same model it uses
    # for a controller's - which is the half that proves a confined group is
    # still being accounted for rather than quietly exempted.
    ESCAPES = ("confine_raise_own_ceiling", "confine_rewrite_decoy",
               "confine_migrate_to_rich_group", "confine_bad_gid_still_noauth",
               "confine_policy_after_second_drop", "confine_grandchild_policy",
               "confine_grandchild_migrate")

    def check_confinement(self):
        rows = {e["name"]: e for e in self.t.edges}
        if "confinement_setup" not in rows:
            return  # a kernel from before the authority rule: nothing to grade
        self.say("\n== policy authority ==")
        setup = rows["confinement_setup"]
        gid, decoy, noauth = int(setup["gid"]), int(setup["decoy"]), self.p["noauth"]
        rich = int(setup["decoy_max"])

        self.check(gid != decoy, "the cell and the decoy are different groups",
                   "gid=%d decoy=%d" % (gid, decoy))
        self.check(rich > int(setup["max"]),
                   "the decoy really is richer than the group being confined",
                   "decoy max=%d, confined max=%s" % (rich, setup["max"]))
        self.check(int(setup["budget"]) == int(setup["max"]),
                   "the confined group starts at its ceiling",
                   "budget=%s max=%s" % (setup["budget"], setup["max"]))

        for name in self.ESCAPES:
            row = rows.get(name)
            if row is None:
                self.check(False, "%s was traced" % name, "record missing")
                continue
            self.check(row.get("rc") == str(noauth),
                       "%s refused for lack of authority" % name,
                       "rc=%s, expected the noauth sentinel %d" % (row.get("rc"), noauth))

        self.check(rows.get("confine_drop_first", {}).get("had") == "1",
                   "the first drop really took authority away",
                   "had=%s" % rows.get("confine_drop_first", {}).get("had"))
        self.check(rows.get("confine_drop_second", {}).get("rc") == "0",
                   "dropping a second time neither fails nor grants anything back",
                   "rc=%s" % rows.get("confine_drop_second", {}).get("rc"))
        self.check(rows.get("confine_child_status", {}).get("status") == "0",
                   "the confined child and its grandchild both ended as the model expects",
                   "status=%s" % rows.get("confine_child_status", {}).get("status"))

        read = rows.get("confine_can_read_table", {})
        self.check(read.get("rc") == "0" and read.get("ngroup") == str(self.p.get("ngroup")),
                   "a confined process can still read the published table",
                   "rc=%s ngroup=%s" % (read.get("rc"), read.get("ngroup")))
        vis = rows.get("confine_bucket_visible", {})
        self.check(vis.get("rc") == "0" and vis.get("max") == setup["max"],
                   "and still see the bucket it is being charged against",
                   "rc=%s max=%s" % (vis.get("rc"), vis.get("max")))

        after = rows.get("confine_after_escape", {})
        self.check(after.get("moved") == "0",
                   "seven escape attempts moved no policy at all",
                   "max=%s refill=%s mode=%s" % (after.get("max"), after.get("refill"),
                                                 after.get("mode")))
        d = rows.get("confine_decoy_untouched", {})
        self.check(d.get("moved") == "0",
                   "and none of them reached a different group's ceiling",
                   "decoy max=%s, started at %s" % (d.get("max"), rich))

        sc = self.t.scenarios.get("C_confine")
        if sc is None:
            self.check(False, "the confined workload was traced", "no C_confine scenario")
            return
        self.check(sc["gid"] == gid and sc["refill"] == 0 and
                   sc["mode"] == self.p["fail"] and sc["fill"] == "inherited",
                   "the confined workload ran under the policy it inherited",
                   "gid=%d max=%d refill=%d mode=%d fill=%s" % (sc["gid"], sc["max"],
                                                                sc["refill"], sc["mode"],
                                                                sc["fill"]))
        res = sc["res"] or {}
        self.check(res.get("used", 0) > 0 and res.get("allowed", 0) > 0,
                   "confinement charged the group instead of exempting it",
                   "allowed=%s used=%s refused=%s" % (res.get("allowed"), res.get("used"),
                                                      res.get("refused")))

    # ---- layer 6: properties that hold across the whole run --------------
    def check_global(self):
        self.say("\n== run-wide invariants ==")
        ops = [op for sc in self.t.scenarios.values() for op in sc["log"]]
        self.check(self.t.done, "the trace ended with [DONE]")
        self.check(not self.t.aborts, "no scenario aborted", "; ".join(self.t.aborts))
        self.check(not self.t.warns, "every bucket that asked to be full reached its ceiling",
                   "; ".join(self.t.warns))

        free = [op for op in ops if op["kind"] in FREE_KINDS]
        bad = [op for op in free if any((op["da"], op["db"], op["dr"], op["du"]))]
        self.check(not bad, "%d free operations moved no counter, at any budget" % len(free),
                   "offenders: %s" % ["%s#%d" % (o["id"], o["i"]) for o in bad][:4])

        denied = [op for op in ops if op["res"] == 1]
        self.check(all(op["du"] == 0 and op["da"] == 0 for op in denied),
                   "%d denials charged nothing and allowed nothing" % len(denied))

        # Conservation: every charged operation is either allowed or refused,
        # never neither and never both.
        mixed = []
        for sc in self.t.scenarios.values():
            for op in sc["log"]:
                if self.cost(op["kind"]) > 0 and op["da"] + op["dr"] != 1:
                    mixed.append("%s#%d" % (sc["id"], op["i"]))
        self.check(not mixed, "every charged operation is accounted exactly once",
                   "offenders: %s" % mixed[:4])

        over = [sc["id"] for sc in self.t.scenarios.values()
                if sc["res"] and sc["res"]["blocked"] > sc["res"]["allowed"]]
        self.check(not over, "no blocked episode ends without a grant",
                   "suspects: %s" % over)

        # A policy rewrite must bank what the old policy earned: the grid reuses
        # its group, and every cell that asked for a full bucket got one.
        waited = [sc["id"] for sc in self.t.scenarios.values()
                  if sc.get("fill") == "wait" and sc["res"] is not None]
        short = [sid for sid in waited
                 if self.t.scenarios[sid]["res"]["budget"] >= 0
                 and self.t.scenarios[sid]["budget"] != self.t.scenarios[sid]["max"]]
        self.check(not short, "fill=wait scenarios start exactly at their ceiling",
                   "short: %s" % short)

    # ---- terminal report -------------------------------------------------
    def table(self):
        if self.muted:
            return
        head = "%-26s %-12s %5s %5s %6s %3s %3s %6s %5s %5s" % (
            "scenario", "class", "max", "refill", "mode", "ops", "gr",
            "refused", "used", "wait")
        print("\n" + "=" * len(head))
        print("PREDICTED AND MEASURED (identical columns mean the engine agreed)")
        print("=" * len(head))
        print(head)
        print("-" * len(head))
        for row in self.rows:
            # The trace only prints what the kernel did, so agreement with the
            # model is the pass/fail above; here both are shown side by side.
            print("%-26s %-12s %5d %5d %6s %3d %3d %6d %5d %5d" % (
                row["id"], row["kind"], row["max"], row["refill"], row["mode"],
                row["ops"], row["predict"]["allowed"], row["predict"]["refused"],
                row["predict"]["used"], row["predict"]["blocked"]))
            if row["predict"] != row["actual"]:
                print("%-26s %-12s measured: %s" % ("", "", row["actual"]))
        print("=" * len(head))

    def run(self):
        self.check_params()
        for sid in self.t.order:
            sc = self.t.scenarios[sid]
            if sc["atomic"] == 0:
                self.check_fanout(sc)
            else:
                self.check_scenario(sc)
        self.check_edges()
        self.check_confinement()
        self.check_global()
        self.table()
        # The verdict has to travel back out of run(): a caller that graded the
        # run by exit status would otherwise always see "failure".
        return self.summary()

    def summary(self):
        print("\n[ORACLE] scenarios=%d operations=%d checks=%d pass=%d fail=%d" % (
            len(self.t.scenarios),
            sum(len(sc["log"]) for sc in self.t.scenarios.values()),
            self.checks, self.checks - self.fails, self.fails))
        return self.fails == 0


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 2
    trace = Trace(argv[1])
    if not trace.params:
        print("no [PARAMS] record in %s: this is not a scenarios trace" % argv[1])
        return 2
    oracle = Oracle(trace, verbose="--verbose" in argv)
    ok = oracle.run()
    if "--json" in argv:
        out = argv[argv.index("--json") + 1]
        with open(out, "w") as handle:
            json.dump(dict(params=trace.params, edges=trace.edges, rows=oracle.rows,
                           scenarios={sid: {k: v for k, v in sc.items() if k != "data"}
                                      for sid, sc in trace.scenarios.items()}),
                      handle, indent=1)
        print("parsed trace and model rows written to %s" % out)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
