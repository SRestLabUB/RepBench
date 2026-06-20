#!/usr/bin/env python3
"""
Plots for paper submission
"""

import matplotlib.pyplot as plt
from matplotlib import rcParams

def curated_vs_avgpromptchars():

    data = {
        "Source-only": {
            "names":        ["raw"],
            "prompt_chars": [34666],
            "accuracy":     [53.5],
        },
        "Graph-only": {
            "names":        ["ast", "ast_cfg", "ast_pdg", "cfg", "cfg_pdg", "pdg"],
            "prompt_chars": [17705, 21761, 22280, 10664, 17403, 11336],
            "accuracy":     [72.1, 80.4, 83.2, 68.0, 73.8, 69.0],
        },
        "Source-plus-Graph": {
            "names":        ["ast_plus_source", "full", "pdg_plus_source"],
            "prompt_chars": [40579, 42900, 38951],
            "accuracy":     [69.3, 73.5, 65.7],
        },
    }

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

    for label, vals in data.items():
        s = STYLE[label]
        ax.scatter(
            vals["prompt_chars"],
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

    ax.set_xlabel("Average Prompt Characters")
    ax.set_ylabel("Curated Accuracy")
    ax.set_title("Curated Accuracy vs Average Prompt Chars")

    # Light dashed grid + clean spines
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.4, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax.legend(
        title="Method",
        frameon=True,
        framealpha=0.9,
        edgecolor="0.8",
        loc="best",
    )

    fig.tight_layout()

    fig.savefig("variant_curated_accuracy_vs_prompt_chars.pdf", bbox_inches="tight")


def main():
    curated_vs_avgpromptchars()

if __name__ == "__main__":
    main()
