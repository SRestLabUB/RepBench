#!/usr/bin/env python3
"""
Plots for paper submission
"""

import matplotlib.pyplot as plt
from matplotlib import rcParams
from matplotlib.ticker import PercentFormatter
from collections import defaultdict
import json
import sys
import argparse
from adjustText import adjust_text

def data_grouped_by(results, group_by):
    ret = []

    if group_by not in results:
        print("Data group by not found.", file=sys.stderr)
        sys.exit(1)

    grouped_data = results[group_by]

    return grouped_data

def determine_prompt_family(variant):
    if variant == "raw":
        return "Source-only"
    if variant in ["ast", "ast_cfg", "ast_pdg", "cfg", "cfg_pdg", "pdg"]:
        return "Graph-only"
    if variant in ["ast_plus_source", "full", "pdg_plus_source"]:
        return "Source-plus-Graph"
    return variant

def raw_curated_vs_metric(results, metric, sig_figs):
    ret = {}
    for res in results:
        variant = res['variant']
        prompt_fam = determine_prompt_family(variant)
        metric_val = round(res[metric], sig_figs)
        cur_acc = round(res['curated_accuracy'] * 100, 1)
        if prompt_fam in ret:
            ret[prompt_fam]["names"].append(variant)
            ret[prompt_fam][metric].append(metric_val)
            ret[prompt_fam]["accuracy"].append(cur_acc)
        else:
            ret[prompt_fam] = {
                "names": [variant],
                metric: [metric_val],
                "accuracy": [cur_acc]
            }

    return ret

def aggregate_curated_by_category(results, cat):
    categories = []
    vals = []
    for res in results:
        categories.append(res[cat])
        vals.append(round(res['curated_accuracy'] * 100, 2))

    return categories, vals


def aggregate_curated_by_multi_category(results, cat, field):
    vals = defaultdict(lambda: defaultdict(dict))

    for res in results:
        category_key = res[cat]
        field_key = res[field]
        vals[category_key][field_key] = round(res['curated_accuracy'] * 100, 1)

    return vals


def curated_vs_avgpromptchars(results):

    data = raw_curated_vs_metric(results, 'avg_prompt_chars', 0)

    STYLE = {
        "Source-only":       {"color": "#0072B2", "marker": "o"},  # blue
        "Graph-only":        {"color": "#E69F00", "marker": "s"},  # orange
        "Source-plus-Graph": {"color": "#009E73", "marker": "^"},  # green
    }

    #   ~3.5 = single column, ~7.0 = double column
    FIG_WIDTH  = 7.0
    FIG_HEIGHT = 4.3

    fig, ax = plt.subplots(figsize=(FIG_WIDTH, FIG_HEIGHT))

    texts = []

    for label, vals in data.items():
        s = STYLE[label]
        ax.scatter(
            vals["avg_prompt_chars"],
            vals["accuracy"],
            label=label,
            color=s["color"],
            marker=s["marker"],
            s=70,
            edgecolors="black",
            linewidths=0.6,
            alpha=0.9,
            zorder=3,
        )

        # Label each point; text is tinted with the category color so the
        # grouping reads even with the labels present.
        for name, x, y in zip(vals["names"], vals["avg_prompt_chars"], vals["accuracy"]):
            texts.append(ax.text(x, y, name))

    adjust_text(
        texts,
        expand=(1.5,1.3)
    )

    ax.set_xlabel("Average Number of Characters in Prompt")
    ax.set_ylabel("Curated Accuracy")
    ax.set_title("Curated Accuracy vs Average Prompt Chars")

    # Light dashed grid + clean spines
    ax.yaxis.set_major_formatter(PercentFormatter(100.0))
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.4, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax.legend(
        title="Prompt Family",
        frameon=True,
        framealpha=0.9,
        edgecolor="0.8",
        loc="best",
    )

    fig.tight_layout()

    fig.savefig(f"{outdir}/variant_curated_accuracy_vs_prompt_chars.pdf", bbox_inches="tight")
    print("Wrote: ", f"{outdir}/variant_curated_accuracy_vs_prompt_chars.pdf")


def curated_vs_cwe(results):
    categories, accuracy = aggregate_curated_by_category(results, 'cwe')

    BAR_COLOR = "#0072B2"

    # Figure size (inches): ~3.5 = single column, ~7.0 = double column.
    FIG_WIDTH  = 7.0
    FIG_HEIGHT = 4.3

    cats, accs = list(categories), list(accuracy)
    # ascending: for horizontal, largest ends up on top; for vertical, on the right.
    order = sorted(range(len(accs)), key=lambda i: accs[i])
    cats = [cats[i] for i in order]
    accs = [accs[i] for i in order]

    headroom = min(100.0, max(accs) * 1.15)

    fig, ax = plt.subplots(figsize=(FIG_WIDTH, FIG_HEIGHT))

    bars = ax.barh(
        cats, accs,
        color=BAR_COLOR, edgecolor="black", linewidth=0.6, height=0.65, zorder=3,
    )
    ax.set_xlabel("Curated Accuracy")
    ax.set_ylabel("CWE Category")
    ax.set_xlim(0, headroom)
    ax.xaxis.set_major_formatter(PercentFormatter(100.0))
    ax.grid(True, axis="x", linestyle="--", linewidth=0.5, alpha=0.4, zorder=0)

    fig.savefig(f"{outdir}/aggregate_curated_accuracy_vs_cwe.pdf")
    print("Wrote: ", f"{outdir}/aggregate_curated_accuracy_vs_cwe.pdf")


def curated_vs_multi_cat(results, cat, field, special_field = False):
    mult_cat_res = aggregate_curated_by_multi_category(results, cat, field)

    categories = mult_cat_res.keys()
    values = {}

    for outer, res in mult_cat_res.items():
        for key, val in res.items():
            if key not in values:
                values[key] = [val]
            else:
                values[key].append(val)

    # Hard coded 'special' field to add data outside of chosen 'field'
    # but still can be compared. Used to highlight 'AST + PDG' results
    if special_field:
        special_res = aggregate_curated_by_multi_category(data_grouped_by(breakdowns, 'cwe__variant'), 'cwe', 'variant')
        special_vals = []
        for cwe, cwe_val in special_res.items():
            for variant, val in cwe_val.items():
                if variant == 'ast_pdg':
                    special_vals.append(val)

        values['ast_pdg'] = special_vals

    COLORS = [
        "#0072B2",  # blue
        "#E69F00",  # orange
        "#009E73",  # bluish green
        "#D55E00",  # vermillion
        "#CC79A7",  # reddish purple
        "#56B4E9",  # sky blue
        "#F0E442",  # yellow
        "#000000",  # black
    ]

    MARKERS = ["o", "s", "^", "D", "v", "P", "X", "*", "<", ">"]
    STYLE = {}
    groups = list(values.keys())

    for key, val in enumerate(groups):
        STYLE[val] = {"color": COLORS[key % len(COLORS)], "marker": MARKERS[key % len(MARKERS)]}

    # Set up plot bands to space out categories
    groups = list(values.keys())
    band_width = 0.45
    G = len(groups)
    step = band_width / (G - 1) if G > 1 else 0
    offsets = [-band_width / 2 + i * step for i in range(G)]

    # Figure size (inches): ~3.5 = single column, ~7.0 = double column.
    FIG_WIDTH  = 7.0
    FIG_HEIGHT = 4.3

    fig, ax = plt.subplots(figsize=(FIG_WIDTH, FIG_HEIGHT))

    # shaded category lanes (subtle for print) + boundary lines
    for c in range(len(categories)):
        if c % 2 == 0:
            ax.axvspan(c - 0.5, c + 0.5, color="0.95", zorder=0)
        if c > 0:
            ax.axvline(c - 0.5, color="0.85", lw=0.6, zorder=0)

    # one scatter call per group -> automatic legend
    for gi, group in enumerate(groups):
        s = STYLE[group]
        xs = [c + offsets[gi] for c in range(len(categories))]
        ys = values[group]
        ax.scatter(
            xs, ys,
            label=group,
            color=s["color"],
            marker=s["marker"],
            s=55,
            edgecolors="black",
            linewidths=0.5,
            alpha=0.9,
            zorder=3,
        )

    cat_label = 'CWE' if cat == 'cwe' else cat.title()
    group_by_label = " ".join(field.split("_")).title()

    ax.set_xticks(range(len(categories)))
    ax.set_xticklabels(categories)
    ax.set_xlim(-0.5, len(categories) - 0.5)
    ax.set_ylabel("Curated Accuracy")
    ax.set_title(f"Curated Accuracy vs {cat_label}: by {group_by_label}")

    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.4, zorder=0)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax.legend(
        title=group_by_label,
        frameon=True,
        framealpha=0.9,
        edgecolor="0.8",
        bbox_to_anchor=(1.01, 1),
        loc="upper left",
    )

    fig.tight_layout()

    fig.savefig(f"{outdir}/curated_accuracy_vs_{cat_label}_by_{group_by_label}.pdf", bbox_inches="tight")
    print("Wrote: ", f"{outdir}/curated_accuracy_vs_{cat_label}_by_{group_by_label}.pdf")

def main():
    parser = argparse.ArgumentParser(description='Generate plots for paper.')

    parser.add_argument('-r', '--results', help='Test results JSON file.')
    parser.add_argument('-o', '--output', help='Output dir for visualizations.')
    args = parser.parse_args()

    global outdir
    outdir = '.'

    if outdir:
        outdir = args.output

    rcParams.update({
        "font.family":     "serif",
        "font.size":       11,
        "axes.labelsize":  12,
        "axes.titlesize":  13,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "axes.linewidth":  0.8,
        "savefig.dpi":     300,
        "figure.dpi":      150,
        "mathtext.fontset": "cm",
    })


    with open(args.results, 'r') as f:
        data = json.load(f)

    global breakdowns
    breakdowns = data['groupings']

    curated_vs_avgpromptchars(data_grouped_by(breakdowns, 'variant'))
    curated_vs_cwe(data_grouped_by(breakdowns, 'cwe'))
    curated_vs_multi_cat(data_grouped_by(breakdowns, 'cwe__variant'), 'cwe', 'variant')
    curated_vs_multi_cat(data_grouped_by(breakdowns, 'cwe__prompt_family'), 'cwe', 'prompt_family', True)

if __name__ == "__main__":
    main()
