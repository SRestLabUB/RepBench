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


def _cwe_support(results):
    """Return testcase support per CWE from grouped variant/family rows."""
    # Source-only contains exactly one variant (raw), so its row count is the
    # testcase count rather than a pooled prompt-row count.
    source_only = {
        row["cwe"]: row["count"]
        for row in results
        if row.get("prompt_family") == "source_only"
    }
    if source_only:
        return source_only

    support = {}
    for row in results:
        support[row["cwe"]] = max(support.get(row["cwe"], 0), row["count"])
    return support


def _cwe_tick_label(cwe, support):
    marker = r"$^\dagger$" if support[cwe] < 5 else ""
    return f"{cwe}{marker}\n(n={support[cwe]})"


def curated_vs_cwe_by_variant(results):
    """Render the dense CWE-by-variant breakdown as an annotated heatmap."""
    cwes = sorted({row["cwe"] for row in results})
    support = _cwe_support(results)
    variant_order = [
        "raw",
        "ast", "cfg", "pdg", "ast_cfg", "ast_pdg", "cfg_pdg",
        "ast_plus_source", "pdg_plus_source", "full",
    ]
    labels = {
        "raw": "Raw source",
        "ast": "AST",
        "cfg": "CFG",
        "pdg": "PDG",
        "ast_cfg": "AST+CFG",
        "ast_pdg": "AST+PDG",
        "cfg_pdg": "CFG+PDG",
        "ast_plus_source": "AST+Source",
        "pdg_plus_source": "PDG+Source",
        "full": "Source+AST+CFG+PDG",
    }
    lookup = {
        (row["variant"], row["cwe"]): row["curated_accuracy"] * 100
        for row in results
    }
    matrix = [
        [lookup.get((variant, cwe), float("nan")) for cwe in cwes]
        for variant in variant_order
    ]

    fig, ax = plt.subplots(figsize=(7.0, 5.8))
    image = ax.imshow(matrix, cmap="YlGnBu", vmin=0, vmax=100, aspect="auto")

    for row_index, row in enumerate(matrix):
        for col_index, value in enumerate(row):
            if value != value:
                text, color = "--", "black"
            else:
                text = f"{value:.1f}"
                color = "white" if value >= 68 else "black"
            ax.text(col_index, row_index, text, ha="center", va="center",
                    fontsize=8.5, color=color)

    ax.set_xticks(range(len(cwes)))
    ax.set_xticklabels([_cwe_tick_label(cwe, support) for cwe in cwes])
    ax.set_yticks(range(len(variant_order)))
    ax.set_yticklabels([labels[variant] for variant in variant_order])
    ax.set_xlabel("CWE Category")
    ax.set_ylabel("Representation Variant")
    ax.set_title("Curated Accuracy by CWE and Representation Variant")

    # Separate source-only, graph-only, and source-plus-graph rows.
    ax.axhline(0.5, color="white", linewidth=2.0)
    ax.axhline(6.5, color="white", linewidth=2.0)
    colorbar = fig.colorbar(image, ax=ax, pad=0.02)
    colorbar.set_label("Curated Accuracy (%)")
    fig.text(0.5, 0.015, r"$^\dagger$ Low support ($n<5$); interpret descriptively.",
             ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.04, 1, 1))

    output = f"{outdir}/curated_accuracy_vs_CWE_by_Variant.pdf"
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)
    print("Wrote: ", output)


def curated_vs_cwe_by_prompt_family(results):
    """Render the three prompt families as an easy-to-compare grouped bar chart."""
    cwes = sorted({row["cwe"] for row in results})
    support = _cwe_support(results)
    families = ["source_only", "graph_only", "source_plus_graph"]
    labels = {
        "source_only": "Source-only",
        "graph_only": "Graph-only",
        "source_plus_graph": "Source+Graph",
    }
    colors = {
        "source_only": "#0072B2",
        "graph_only": "#E69F00",
        "source_plus_graph": "#009E73",
    }
    lookup = {
        (row["prompt_family"], row["cwe"]): row["curated_accuracy"] * 100
        for row in results
    }

    fig, ax = plt.subplots(figsize=(7.0, 4.8))
    width = 0.24
    centers = list(range(len(cwes)))
    for family_index, family in enumerate(families):
        offset = (family_index - 1) * width
        values = [lookup.get((family, cwe), 0.0) for cwe in cwes]
        bars = ax.bar(
            [center + offset for center in centers],
            values,
            width,
            label=labels[family],
            color=colors[family],
            edgecolor="black",
            linewidth=0.5,
        )
        ax.bar_label(bars, fmt="%.1f", fontsize=8, padding=2)

    ax.set_xticks(centers)
    ax.set_xticklabels([_cwe_tick_label(cwe, support) for cwe in cwes])
    ax.set_ylim(0, 110)
    ax.set_xlabel("CWE Category")
    ax.set_ylabel("Curated Accuracy")
    ax.yaxis.set_major_formatter(PercentFormatter(100.0))
    fig.suptitle("Curated Accuracy by CWE and Prompt Family", y=0.98)
    ax.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.4)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    handles, legend_labels = ax.get_legend_handles_labels()
    fig.legend(handles, legend_labels, title="Prompt Family", ncol=3,
               loc="upper center", bbox_to_anchor=(0.5, 0.91))
    fig.text(0.5, 0.015, r"$^\dagger$ Low support ($n<5$); interpret descriptively.",
             ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.04, 1, 0.80))

    output = f"{outdir}/curated_accuracy_vs_CWE_by_Prompt Family.pdf"
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)
    print("Wrote: ", output)

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
    curated_vs_cwe_by_variant(data_grouped_by(breakdowns, 'cwe__variant'))
    curated_vs_cwe_by_prompt_family(data_grouped_by(breakdowns, 'cwe__prompt_family'))

if __name__ == "__main__":
    main()
