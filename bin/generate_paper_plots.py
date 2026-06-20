#!/usr/bin/env python3
"""
Plots for paper submission
"""

import matplotlib.pyplot as plt
from matplotlib import rcParams
from matplotlib.ticker import PercentFormatter
import json
import sys
import argparse
from adjustText import adjust_text

def data_grouped_by(data, group_by):
    ret = []
    grouped_data = data[group_by]

    if not grouped_data:
        print("Data group by not found.", file=sys.stderr)
        sys.exit(1)

    for key, val in grouped_data.items():
        ret.append({key : val})

    return ret

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
        for key, val in res.items():
            prompt_fam = determine_prompt_family(key)
            prompt_avg_chars = round(val[metric], sig_figs)
            prompt_cur_acc = round(val['curated_accuracy'] * 100, 1)
            if prompt_fam in ret:
                ret[prompt_fam]["names"].append(key)
                ret[prompt_fam][metric].append(prompt_avg_chars)
                ret[prompt_fam]["accuracy"].append(prompt_cur_acc)
            else:
                ret[prompt_fam] = {
                    "names": [key],
                    metric: [prompt_avg_chars],
                    "accuracy": [prompt_cur_acc]
                }

    return ret

def aggregate_curated_by_category(results):
    categories = []
    vals = []
    for res in results:
        for key, val in res.items():
            categories.append(key)
            vals.append(round(val['curated_accuracy'] * 100, 2))

    return categories, vals



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

    rcParams.update({
        "font.family":     "serif",
        "font.size":       11,
        "axes.labelsize":  12,
        "axes.titlesize":  13,
        "legend.fontsize": 10,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "axes.linewidth":  0.8,
        "savefig.dpi":     300,
        "figure.dpi":      150,
        "mathtext.fontset": "cm",
    })

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

    ax.set_xlabel("Average Prompt Characters")
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

    fig.savefig("variant_curated_accuracy_vs_prompt_chars.pdf", bbox_inches="tight")


def curated_vs_cwe(results):
    categories, accuracy = aggregate_curated_by_category(results)

    BAR_COLOR = "#0072B2"

    # Figure size (inches): ~3.5 = single column, ~7.0 = double column.
    FIG_WIDTH  = 7.0
    FIG_HEIGHT = 4.3

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

    cats, accs = list(categories), list(accuracy)
    # ascending: for horizontal, largest ends up on top; for vertical, on the right.
    order = sorted(range(len(accs)), key=lambda i: accs[i])
    cats = [cats[i] for i in order]
    accs = [accs[i] for i in order]

    print(cats)
    print(accs)
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

    fig.savefig("aggregate_curated_accuracy_vs_cwe.pdf", bbox_inches="tight")


def main():
    parser = argparse.ArgumentParser(description='Generate plots for paper.')

    parser.add_argument('-r', '--results', help='Test results JSON file.')
    args = parser.parse_args()

    with open(args.results, 'r') as f:
        data = json.load(f)

    data_by_variant = data_grouped_by(data, 'by_variant')
    data_by_cwe = data_grouped_by(data, 'by_cwe_rows')
    curated_vs_avgpromptchars(data_by_variant)
    curated_vs_cwe(data_by_cwe)

if __name__ == "__main__":
    main()
