#!/usr/bin/env python3
"""
analyze_results.py - turn a /scenarios QEMU trace into the graphs the lab asks
for, with every number on them derived from the trace itself.

The previous version of this file drew a picture of a test that no longer
exists: it hard-wired "Test 4: Exactly 3 deletions succeeded, 7 failed", an
axis limit, and a "2 unlinks = 20 tokens" threshold line into the plot. Those
were assertions in disguise. If the engine had been wrong the graph would still
have looked exactly the same, because the interesting numbers were typed in by
hand.

Now the shapes come from the kernel's own reported state: the refill period and
the price of each class are read from the [PARAMS] record that budgetinfo()
published in this very run, ceilings are computed as max // price, refill marks
are placed where the bucket actually rose, and the pass/fail verdict is
budget_oracle's, not a list of expected test names. A wrong engine now draws a
wrong picture, which is the point.

    python3 analyze_results.py <qemu-log> [--out results] [--quiet]

Exit status is the oracle's: 0 only when every derived expectation matched.
"""

import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from budget_oracle import Oracle, PRICE_FIELDS, Trace

GRANT = "#1F77B4"    # ran, paid for it
DENY = "#D62728"     # refused by policy
WAIT = "#2CA02C"     # ran after sleeping for the tokens
BUCKET = "#7F7F7F"   # the bucket itself
NOISE = "#BDBDBD"    # a class that never reaches the bucket


def outcome(op):
    if op["res"] == 1:
        return "deny"
    if op["db"]:
        return "wait"
    if op["res"] in (0, 3):
        return "grant"
    return "error"


def charged(trace, sc):
    """Scenarios whose class actually pays, so their bucket does something."""
    return any(trace_price(trace.params, op["kind"]) > 0 for op in sc["log"])


def trace_price(p, kind):
    """Price a class from the [PARAMS] record, the same table the kernel charged."""
    field = PRICE_FIELDS.get(kind)
    return p[field] if field and field in p else 0


def mode_of(p, mode):
    return "BLOCK" if mode == p["block"] else "FAIL"


# ---------------------------------------------------------------------------
# figure 1: the BLOCK staircase against the FAIL flat line, same workload
# ---------------------------------------------------------------------------
def workload_key(sc):
    kinds = {op["kind"] for op in sc["log"]}
    if len(kinds) != 1 or not sc["data"]:
        return None
    return (next(iter(kinds)), sc["ops"], sc["max"])


def wait_ticks(sc, i):
    """Ticks this attempt consumed beyond the previous one - the cost of waiting."""
    ops = sc["log"]
    return 0 if i == 0 else ops[i]["t"] - ops[i - 1]["t"]


def elapsed_span(sc):
    return sc["log"][-1]["t"] - sc["log"][0]["t"] if sc["log"] else 0


def plot_staircase(trace, out):
    """Find the workload that appears once in each mode and show the two shapes.

    The pairing is discovered, not named: any two scenarios with the same class,
    the same number of operations and the same ceiling that differ only in mode
    are a legitimate staircase-vs-flat comparison, whichever ids the trace
    happens to use.
    """
    pairs = {}
    for sid in trace.order:
        sc = trace.scenarios[sid]
        key = workload_key(sc)
        if key is None:
            continue
        pairs.setdefault(key, {})[mode_of(trace.params, sc["mode"])] = sc
    usable = [(k, v) for k, v in pairs.items()
              if set(v) == {"BLOCK", "FAIL"} and v["BLOCK"]["refill"] > 0]
    if not usable:
        print("no BLOCK/FAIL pair with the same workload in this trace; skipping the staircase plot")
        return
    usable.sort(key=lambda kv: (-kv[1]["BLOCK"]["ops"], kv[0][0]))
    (kind, ops, ceiling), pair = usable[0]
    price = trace_price(trace.params, kind)
    period = trace.params["period"]

    fig, axes = plt.subplots(2, 1, figsize=(10, 8), sharex=True)
    for ax, mode in zip(axes, ("BLOCK", "FAIL")):
        sc = pair[mode]
        n = len(sc["log"])
        idx = list(range(n))
        # One [DATA] row is emitted per traced operation, so the two line up by
        # position; a lost row would already have failed the oracle's count.
        done = [g for _, g in sc["data"]][:n]
        t0 = sc["log"][0]["t"]
        elapsed = [op["t"] - t0 for op in sc["log"]]
        color = GRANT if mode == "BLOCK" else DENY

        # Attempt number, not tick, is the shared axis: FAIL refuses instantly,
        # so all of its operations happen inside a single tick and a time axis
        # would draw the flat ceiling as one vertical line. Time is still here -
        # it is the second series, and it is what BLOCK spends waiting.
        ax.step(idx, done, where="post", color=color, linewidth=2,
                label="operations completed")
        ax.fill_between(idx, done, step="post", alpha=0.18, color=color)

        # The ceiling the lab's own arithmetic gives: a bucket that starts full
        # and never refills can pay for floor(max / price) operations.
        limit = ceiling // price
        ax.axhline(y=limit, color=BUCKET, linestyle="--", linewidth=1.2,
                   label="ceiling = %d // %d = %d ops" % (ceiling, price, limit))

        refused = [(i, done[i]) for i, op in enumerate(sc["log"]) if op["res"] == 1]
        if refused:
            ax.scatter([i for i, _ in refused], [g for _, g in refused], marker="x",
                       s=70, color=DENY, linewidths=2, label="refused by policy")
        for i, op in enumerate(sc["log"]):
            if op["db"]:
                ax.annotate("waited\n%d ticks" % wait_ticks(sc, i), xy=(i, done[i]),
                            xytext=(i, max(0.4, limit - 0.9)), ha="center", fontsize=8,
                            color=WAIT, arrowprops=dict(arrowstyle="->", color=WAIT))

        ax2 = ax.twinx()
        if max(elapsed) > 0:
            ax2.step(idx, elapsed, where="post", color=WAIT, linestyle=":", linewidth=1.5,
                     label="ticks elapsed since the first attempt")
            ax2.set_ylabel("ticks elapsed", color=WAIT, fontsize=9)
            ax2.tick_params(labelsize=8, colors=WAIT)
            handles, labels = ax.get_legend_handles_labels()
            handles2, labels2 = ax2.get_legend_handles_labels()
            ax.legend(handles + handles2, labels + labels2, loc="lower right",
                      fontsize=8, framealpha=0.9)
        else:
            # A FAIL-mode run can finish inside one tick. Drawing an axis for a
            # quantity that never moved would only invent tick marks.
            ax2.axis("off")
            ax.text(0.02, 0.92, "every attempt returned in the same tick: 0 ticks elapsed",
                    fontsize=8, color=WAIT, va="top", transform=ax.transAxes)
            ax.legend(loc="lower right", fontsize=8, framealpha=0.9)

        ax.set_ylabel("operations completed")
        ax.set_ylim(bottom=0, top=max(limit, max(done)) + 1.2)
        ax.set_xticks(idx)
        ax.grid(True, alpha=0.25)
        ax.set_title("%s / %s: %s x%d, ceiling %d, refill %d every %d ticks, mode %s" % (
            sc["id"], sc["name"], kind, ops, ceiling, sc["refill"], period, mode),
            fontsize=11)

    axes[-1].set_xlabel("attempt (operation index)")
    fig.suptitle("%s x%d under BLOCK and FAIL: waiting climbs a staircase, refusing holds flat\n"
                 "BLOCK finished all %d and spent %d ticks doing it; FAIL finished %d in %d ticks" % (
                     kind, ops,
                     pair["BLOCK"]["res"]["granted"] if pair["BLOCK"]["res"] else 0,
                     elapsed_span(pair["BLOCK"]),
                     pair["FAIL"]["res"]["allowed"] if pair["FAIL"]["res"] else 0,
                     elapsed_span(pair["FAIL"])), fontsize=12)
    path = os.path.join(out, "staircase_block_vs_fail.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


# ---------------------------------------------------------------------------
# figure 2: the bucket under every scenario, op by op
# ---------------------------------------------------------------------------
def plot_depletion(trace, out):
    scs = [trace.scenarios[sid] for sid in trace.order
           if sc_ok(trace, sid) and charged(trace, trace.scenarios[sid])]
    if not scs:
        return
    cols = 3
    rows = (len(scs) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(12, 2.5 * rows), squeeze=False)

    for n, sc in enumerate(scs):
        ax = axes[n // cols][n % cols]
        ops = sc["log"]
        xs = [op["i"] for op in ops]
        ax.step(xs, [op["bb"] for op in ops], where="post", color=BUCKET,
                linewidth=1.4, label="bucket before the op")
        ax.fill_between(xs, [op["bb"] for op in ops], step="post", alpha=0.15, color=BUCKET)
        for op in ops:
            style = {"grant": ("o", GRANT), "wait": ("s", WAIT),
                     "deny": ("x", DENY), "error": ("_", NOISE)}[outcome(op)]
            ax.plot([op["i"]], [op["bb"]], marker=style[0], color=style[1],
                    linestyle="none", markersize=6)
        price = trace_price(trace.params, ops[0]["kind"]) if ops else 0
        if price:
            ax.axhline(y=price, color=DENY, linestyle=":", linewidth=1.0)
        ax.axhline(y=sc["max"], color="#000000", linestyle="--", linewidth=0.8, alpha=0.5)
        ax.set_ylim(bottom=0)
        ax.set_xlim(-0.5, max(xs) + 0.5 if xs else 1)
        ax.set_title("%s  %s / %s\nmax %d, refill %d, %s" % (
            sc["id"], sc["name"], mode_of(trace.params, sc["mode"]),
            sc["max"], sc["refill"], "%d ops" % len(ops)), fontsize=8)
        ax.tick_params(labelsize=7)
        ax.set_xlabel("operation", fontsize=7)
        ax.set_ylabel("tokens", fontsize=7)
    for n in range(len(scs), rows * cols):
        axes[n // cols][n % cols].axis("off")

    fig.legend(handles=[
        plt.Line2D([], [], marker="o", color=GRANT, linestyle="none", label="ran, paid for it"),
        plt.Line2D([], [], marker="s", color=WAIT, linestyle="none", label="ran after waiting for tokens"),
        plt.Line2D([], [], marker="x", color=DENY, linestyle="none", label="refused by policy"),
        plt.Line2D([], [], color=BUCKET, linestyle="-", label="bucket before the operation"),
        plt.Line2D([], [], color=DENY, linestyle=":", label="price of this class"),
        plt.Line2D([], [], color="#000000", linestyle="--", label="the group's ceiling"),
    ], loc="lower center", ncol=6, fontsize=8, frameon=False)

    fig.suptitle("Token accounting: the bucket each operation saw, coloured by what the engine did",
                 fontsize=11)
    fig.tight_layout(rect=(0, 0.02, 1, 0.97))
    path = os.path.join(out, "bucket_accounting.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def sc_ok(trace, sid):
    sc = trace.scenarios[sid]
    return sc["atomic"] == 1 and bool(sc["log"])


# ---------------------------------------------------------------------------
# figure 3: the price of each class, and whether the engine charged it
# ---------------------------------------------------------------------------
def plot_cost_matrix(trace, out):
    classes = [op["kind"] for sid in trace.order for op in trace.scenarios[sid]["log"]]
    classes = sorted(set(classes), key=lambda k: (-trace_price(trace.params, k), k))
    modes = ["BLOCK", "FAIL"]

    fig, (ax_price, ax_matrix) = plt.subplots(1, 2, figsize=(13, 0.7 + 0.5 * len(classes)),
                                              gridspec_kw={"width_ratios": [1, 1.4]})

    prices = [trace_price(trace.params, k) for k in classes]
    ax_price.barh(classes, [p if p else 0.12 for p in prices],
                  color=[NOISE if p == 0 else GRANT for p in prices])
    for y, p in enumerate(prices):
        ax_price.text(p + 0.2, y, "%d%s" % (p, "  free, never reaches the bucket" if p == 0 else ""),
                      va="center", fontsize=8)
    ax_price.set_title("published price of each class\n(from [PARAMS], budgetinfo in this run)")
    ax_price.set_xlabel("tokens per operation")
    ax_price.set_xlim(0, max(prices) * 2.6)
    ax_price.tick_params(labelsize=8)
    ax_price.invert_yaxis()

    # Aggregate every traced operation by (class, mode). Reading the per-scenario
    # rows instead would keep only the last scenario that touched a class, and
    # would miss the classes that appear solely inside a mixed workload.
    ran = {(k, m): 0 for k in classes for m in modes}
    refused = {(k, m): 0 for k in classes for m in modes}
    spent = {(k, m): 0 for k in classes for m in modes}
    for sid in trace.order:
        sc = trace.scenarios[sid]
        mode = mode_of(trace.params, sc["mode"])
        for op in sc["log"]:
            key = (op["kind"], mode)
            if op["res"] == 1:
                refused[key] += 1
            elif op["res"] in (0, 3):
                ran[key] += 1
            spent[key] += op["du"]

    grid = np.ma.masked_all((len(classes), len(modes)))
    for y, kind in enumerate(classes):
        price = trace_price(trace.params, kind)
        for x, mode in enumerate(modes):
            key = (kind, mode)
            if ran[key] + refused[key] == 0:
                ax_matrix.text(x, y, "not exercised", ha="center", va="center",
                               fontsize=7, color="#777777", style="italic")
                continue
            paid_by = ran[key] if price else 0
            want = price * paid_by
            grid[y, x] = 1 if spent[key] == want else 0
            ax_matrix.text(x, y, "%d ran, %d refused\n%d spent, %d expected" % (
                ran[key], refused[key], spent[key], want),
                ha="center", va="center", fontsize=7)

    cmap = matplotlib.colors.ListedColormap(["#F5B7B1", "#D5F5E3"])
    cmap.set_bad("#EFEFEF")
    ax_matrix.imshow(grid, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax_matrix.set_xticks(range(len(modes)))
    ax_matrix.set_xticklabels(modes)
    ax_matrix.set_yticks(range(len(classes)))
    ax_matrix.set_yticklabels(classes, fontsize=8)
    ax_matrix.set_title("measured, over every operation in the trace\n"
                        "green = spent equals price x grants, red = it does not")

    fig.tight_layout()
    path = os.path.join(out, "cost_matrix.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


# ---------------------------------------------------------------------------
# figure 4: many children, one bucket
# ---------------------------------------------------------------------------
def plot_fanout(trace, out):
    fan = [trace.scenarios[sid] for sid in trace.order if trace.scenarios[sid]["atomic"] == 0]
    if not fan:
        return
    fig, axes = plt.subplots(1, len(fan), figsize=(5 * len(fan), 4), squeeze=False)
    price = trace_price(trace.params, "unlink")
    for ax, sc in zip(axes[0], fan):
        kids = sorted(sc["kids"], key=lambda k: k["kid"])
        colors = [GRANT if k["rc"] == 0 else (DENY if k["rc"] == 1 else "#8E44AD") for k in kids]
        ax.bar([k["kid"] for k in kids], [k["bb"] for k in kids], color=colors)
        # A refused child found the bucket empty, and a zero-height bar is
        # invisible: mark those children so the refusals are not edited out of
        # the picture by the geometry.
        empty = [k["kid"] for k in kids if k["bb"] == 0]
        if empty:
            ax.scatter(empty, [0] * len(empty), marker="_", s=320, color=DENY,
                       linewidths=3, label="refused: bucket already empty")
            ax.set_ylim(bottom=-max(sc["budget"], price) * 0.07)
        ax.axhline(y=price, color="#000000", linestyle="--", linewidth=1.0,
                   label="price of one unlink")
        ax.legend(fontsize=8, loc="upper right")
        ax.set_xlabel("child")
        ax.set_ylabel("tokens in the shared bucket when it tried")
        ran = sum(1 for k in kids if k["rc"] == 0)
        ax.set_title("%s: floor(%d / %d) = %d children could pay, and %d did\n"
                     "%d refused, %d ended below the price" % (
                         sc["id"], sc["budget"], price, sc["budget"] // price, ran,
                         sum(1 for k in kids if k["rc"] == 1),
                         sum(1 for k in kids if k["bb"] < price)), fontsize=10)
        ax.tick_params(labelsize=8)
    fig.tight_layout()
    path = os.path.join(out, "fanout_shared_bucket.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


# ---------------------------------------------------------------------------
# figure 5: the differential view - model against kernel
# ---------------------------------------------------------------------------
def plot_differential(oracle, out):
    fields = ("allowed", "blocked", "refused", "used")
    fig, ax = plt.subplots(figsize=(7, 7))
    mismatch = 0
    for field in fields:
        xs, ys, bad = [], [], []
        for row in oracle.rows:
            want, got = row["predict"][field], row["actual"][field]
            (xs if want == got else bad).append((want, got))
            if want != got:
                mismatch += 1
        ax.scatter([x for x, _ in xs], [y for _, y in xs], s=26, alpha=0.7, label=field)
        ax.scatter([x for x, _ in bad], [y for _, y in bad], marker="x", s=90,
                   color=DENY, linewidths=2)
    limit = max([1] + [max(r["predict"][f], r["actual"][f]) for r in oracle.rows for f in fields])
    ax.plot([0, limit], [0, limit], color=BUCKET, linestyle="--", linewidth=1.0)
    ax.set_xlabel("predicted by budget_oracle.py (the lab rules, re-implemented)")
    ax.set_ylabel("measured in the kernel's own counters")
    ax.set_title("Independent model vs kernel: %d scenarios, %d aggregate counters\n"
                 "%d points off the agreement line" % (
                     len(oracle.rows), len(fields) * len(oracle.rows), mismatch))
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.25)
    path = os.path.join(out, "predicted_vs_measured.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def plot_confinement(trace, out):
    """What a process that cannot write policy asked for, and what it got back.

    The left panel is read out of the trace, not typed in here: every [EDGE]
    record whose name starts with confine_ is plotted at the return code the
    kernel gave, and the colour says what that code means according to the table
    budgetinfo() published in this same run. So the two codes that legitimately
    come back as 0 - the free reads, and the second drop - are visible as
    allowed, and the figure has to be read as a capability map rather than as
    "everything red". The right panel is the part a boundary claim really needs:
    the confined group's work, drawn with the same bucket model as every other
    scenario, because a group that stopped being charged would look just as safe
    and be just as broken.
    """
    rows = {e["name"]: e for e in trace.edges}
    if "confinement_setup" not in rows:
        print("no confinement records in this trace; skipping the boundary plot")
        return None

    p = trace.params
    meanings = {p.get("noauth"): (DENY, "refused: this process may not write policy"),
                p.get("denied"): (WAIT, "refused: the group could not pay"),
                0: (GRANT, "allowed"),
                -1: (NOISE, "rejected as a malformed argument")}

    attempts = []
    for edge in trace.edges:
        name = edge["name"]
        if name.startswith("confine_") and "rc" in edge:
            attempts.append((name[len("confine_"):].replace("_", " "),
                             int(edge["rc"])))

    fig, (ladder, bucket) = plt.subplots(1, 2, figsize=(13.5, 5.6))
    drawn = set()
    for i, (label, rc) in enumerate(attempts):
        colour, meaning = meanings.get(rc, (BUCKET, "a return code the table does not explain"))
        ladder.plot([i, i], [0, rc], color=colour, linewidth=2.2)
        ladder.scatter([i], [rc], color=colour, s=60,
                       label=None if meaning in drawn else meaning, zorder=3)
        drawn.add(meaning)

    for code, (colour, _) in meanings.items():
        if code in (p.get("noauth"), p.get("denied"), 0):
            ladder.axhline(code, color=colour, linestyle=":", linewidth=1.0, alpha=0.7)
            ladder.text(-0.45, code, "%d" % code, fontsize=8, color=colour,
                        va="center", ha="right")

    ladder.set_xticks(range(len(attempts)))
    ladder.set_xticklabels([label for label, _ in attempts], rotation=38,
                           ha="right", fontsize=8)
    ladder.set_xlim(-1.2, len(attempts) - 0.2)
    # Room below the two sentinels, so the legend sits in empty space instead of
    # on top of the stems it is explaining.
    ladder.set_ylim(min(p.get("noauth", -43), p.get("denied", -42)) - 20, 3)
    ladder.set_ylabel("return code")
    ladder.set_title("%d things a confined process can still try\n"
                     "%d refused for lack of authority, %d allowed" % (
                         len(attempts),
                         sum(1 for _, rc in attempts if rc == p.get("noauth")),
                         sum(1 for _, rc in attempts if rc == 0)), fontsize=11)
    ladder.legend(fontsize=8, loc="lower left", framealpha=0.95)
    ladder.grid(True, alpha=0.25, axis="y")

    setup = rows["confinement_setup"]
    after = rows.get("confine_after_escape", {})
    sc = trace.scenarios.get("C_confine")
    if sc and sc["log"]:
        ops = sc["log"]
        cost = trace_price(p, ops[0]["kind"])
        bucket.plot(range(len(ops)), [op["bb"] for op in ops], color=BUCKET,
                    linewidth=1.4, marker="", label="bucket before the operation")
        for i, op in enumerate(ops):
            state = outcome(op)
            colour = {"grant": GRANT, "deny": DENY, "wait": WAIT}.get(state, NOISE)
            bucket.scatter([i], [op["bb"]], color=colour, s=62, zorder=3,
                           marker="o" if state != "deny" else "x")
        bucket.axhline(cost, color=DENY, linestyle=":", linewidth=1.0)
        bucket.axhline(sc["max"], color=BUCKET, linestyle="--", linewidth=1.0)
        bucket.text(len(ops) - 0.5, cost, " price %d" % cost, fontsize=8,
                    color=DENY, va="bottom", ha="right")
        bucket.text(len(ops) - 0.5, sc["max"], " ceiling %d" % sc["max"], fontsize=8,
                    color=BUCKET, va="bottom", ha="right")
        bucket.set_xlabel("%s operations in group %d" % (ops[0]["kind"], sc["gid"]))
        bucket.set_title("the confined group is still charged: %d of %d %ss paid\n"
                         "policy after the attempts: max=%s refill=%s mode=%s (moved=%s)" % (
                             sum(1 for op in ops if outcome(op) == "grant"), len(ops),
                             ops[0]["kind"], after.get("max", setup["max"]),
                             after.get("refill", setup["refill"]),
                             mode_of(p, sc["mode"]), after.get("moved", "?")),
                         fontsize=11)
        bucket.set_xticks(range(len(ops)))
        bucket.grid(True, alpha=0.25, axis="y")
    else:
        bucket.set_axis_off()
        bucket.text(0.5, 0.5, "no confined workload in this trace",
                    ha="center", va="center", fontsize=11)

    path = os.path.join(out, "confinement_boundary.png")
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 2
    log_file = argv[1]
    out = argv[argv.index("--out") + 1] if "--out" in argv else "results"
    quiet = "--quiet" in argv
    os.makedirs(out, exist_ok=True)

    trace = Trace(log_file)
    if not trace.params:
        print("%s has no [PARAMS] record: run /scenarios in QEMU and pass that log" % log_file)
        return 2

    oracle = Oracle(trace, muted=True)
    ok = oracle.run()

    print("trace %s: %d scenarios, %d operations, %d records" % (
        log_file, len(trace.scenarios),
        sum(len(sc["log"]) for sc in trace.scenarios.values()), len(trace.raw)))

    plots = [plot_staircase(trace, out), plot_depletion(trace, out),
             plot_cost_matrix(trace, out), plot_fanout(trace, out),
             plot_confinement(trace, out), plot_differential(oracle, out)]
    for path in plots:
        if path:
            print("wrote %s" % path)

    if not ok:
        print("\nTHE ENGINE DISAGREED WITH THE LAB RULES - see the [FAIL] lines above")
    elif not quiet:
        print("\nall derived expectations matched; the graphs above are drawn from them")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
