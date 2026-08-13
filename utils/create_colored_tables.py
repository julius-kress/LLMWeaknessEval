from pathlib import Path
from html import escape
import pandas as pd
import os



CELL_WIDTH = 300
CELL_HEIGHT = 80
HEADER_HEIGHT = 60
ID_WIDTH = 240
TARGET_WIDTH = 150

EMPTY_COLOR = "#80EE80"
FILLED_COLOR = "#FF5B5B"
HEADER_COLOR = "#DDDDDD"
BORDER_COLOR = "#555555"
TEXT_COLOR = "#000000"

FONT_FAMILY = "Arial, sans-serif"
FONT_SIZE = 16
HEADER_FONT_SIZE = 16

def generate_table(csv_path, output_path, flag_sorted:bool = False):
    df = pd.read_csv(csv_path)

    # Clean model names
    df["model"] = (df["model"]
                   .replace("deepseek/deepseek-v3.2", "DeepSeek")
                   .replace("openai/gpt-4o-mini", "GPT-4o mini")
                   .replace("qwen/qwen3-coder-30b-a3b-instruct", "Qwen3-Coder"))
    models = df["model"].drop_duplicates().tolist()

    ids = df["id"].drop_duplicates().tolist()
    if flag_sorted:
        ids = sorted(ids)

    evaluation_lookup = (
        df.set_index(["id", "model"])["conjunction_bandit_codeql"]
        .to_dict()
    )


    target_cwe_lookup = (
        df.drop_duplicates("id")
        .set_index("id")["target_cwe"]
        .to_dict()
    )

    width = ID_WIDTH + TARGET_WIDTH + len(models) * CELL_WIDTH
    height = HEADER_HEIGHT + len(ids) * CELL_HEIGHT

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
    ]

    # ---------------------------------------------------------------------
    # ID header
    # ---------------------------------------------------------------------

    svg.append(
        f'<rect x="0" y="0" '
        f'width="{ID_WIDTH}" height="{HEADER_HEIGHT}" '
        f'fill="{HEADER_COLOR}" '
        f'stroke="{BORDER_COLOR}"/>'
    )

    svg.append(
        f'<text x="{ID_WIDTH / 2}" '
        f'y="{HEADER_HEIGHT / 2}" '
        f'font-family="{FONT_FAMILY}" '
        f'font-size="{HEADER_FONT_SIZE}px" '
        f'font-weight="bold" '
        f'text-anchor="middle" '
        f'dominant-baseline="middle">'
        f'id'
        f'</text>'
    )

    # ---------------------------------------------------------------------
    # target_cwe header
    # ---------------------------------------------------------------------

    svg.append(
        f'<rect x="{ID_WIDTH}" y="0" '
        f'width="{TARGET_WIDTH}" height="{HEADER_HEIGHT}" '
        f'fill="{HEADER_COLOR}" '
        f'stroke="{BORDER_COLOR}"/>'
    )

    svg.append(
        f'<text x="{ID_WIDTH + TARGET_WIDTH / 2}" '
        f'y="{HEADER_HEIGHT / 2}" '
        f'font-family="{FONT_FAMILY}" '
        f'font-size="{HEADER_FONT_SIZE}px" '
        f'font-weight="bold" '
        f'text-anchor="middle" '
        f'dominant-baseline="middle">'
        f'target_cwe'
        f'</text>'
    )

    # ---------------------------------------------------------------------
    # Model headers
    # ---------------------------------------------------------------------

    for col_index, model in enumerate(models):
        x = ID_WIDTH + TARGET_WIDTH + col_index * CELL_WIDTH

        svg.append(
            f'<rect x="{x}" y="0" '
            f'width="{CELL_WIDTH}" height="{HEADER_HEIGHT}" '
            f'fill="{HEADER_COLOR}" '
            f'stroke="{BORDER_COLOR}"/>'
        )

        svg.append(
            f'<text x="{x + CELL_WIDTH / 2}" '
            f'y="{HEADER_HEIGHT / 2}" '
            f'font-family="{FONT_FAMILY}" '
            f'font-size="{HEADER_FONT_SIZE}px" '
            f'font-weight="bold" '
            f'text-anchor="middle" '
            f'dominant-baseline="middle">'
            f'{escape(str(model))}'
            f'</text>'
        )

    # ---------------------------------------------------------------------
    # Rows
    # ---------------------------------------------------------------------

    for row_index, id_value in enumerate(ids):

        y = HEADER_HEIGHT + row_index * CELL_HEIGHT

        # -----------------------------------------------------------------
        # ID cell
        # -----------------------------------------------------------------

        svg.append(
            f'<rect x="0" y="{y}" '
            f'width="{ID_WIDTH}" height="{CELL_HEIGHT}" '
            f'fill="{HEADER_COLOR}" '
            f'stroke="{BORDER_COLOR}"/>'
        )

        svg.append(
            f'<text x="{ID_WIDTH / 2}" '
            f'y="{y + CELL_HEIGHT / 2}" '
            f'font-family="{FONT_FAMILY}" '
            f'font-size="{FONT_SIZE}px" '
            f'text-anchor="middle" '
            f'dominant-baseline="middle">'
            f'{escape(str(id_value))}'
            f'</text>'
        )

        # -----------------------------------------------------------------
        # target_cwe cell
        # -----------------------------------------------------------------

        cwe_x = ID_WIDTH

        target_cwe = target_cwe_lookup.get(id_value, "")
        if pd.isna(target_cwe):
            target_cwe = ""

        svg.append(
            f'<rect x="{cwe_x}" y="{y}" '
            f'width="{TARGET_WIDTH}" height="{CELL_HEIGHT}" '
            f'fill="{HEADER_COLOR}" '
            f'stroke="{BORDER_COLOR}"/>'
        )

        svg.append(
            f'<text x="{cwe_x + TARGET_WIDTH / 2}" '
            f'y="{y + CELL_HEIGHT / 2}" '
            f'font-family="{FONT_FAMILY}" '
            f'font-size="{FONT_SIZE}px" '
            f'text-anchor="middle" '
            f'dominant-baseline="middle">'
            f'{escape(str(target_cwe))}'
            f'</text>'
        )

        # -----------------------------------------------------------------
        # Model + evaluation cells
        # -----------------------------------------------------------------

        for col_index, model in enumerate(models):

            # Shift model columns past both ID and target_cwe columns.
            x = ID_WIDTH + TARGET_WIDTH + col_index * CELL_WIDTH

            value = evaluation_lookup.get((id_value, model), "")

            if pd.isna(value) or not str(value).strip():
                value = ""
                background = EMPTY_COLOR
            else:
                value = ", ".join(
                    line.strip()
                    for line in str(value).splitlines()
                    if line.strip()
                )
                background = FILLED_COLOR
            # Cell background
            svg.append(
                f'<rect x="{x}" y="{y}" '
                f'width="{CELL_WIDTH}" height="{CELL_HEIGHT}" '
                f'fill="{background}" '
                f'stroke="{BORDER_COLOR}"/>'
            )

            # Evaluation text
            if value:
                svg.append(
                    f'<text x="{x + CELL_WIDTH / 2}" '
                    f'y="{y + CELL_HEIGHT / 2}" '
                    f'font-family="{FONT_FAMILY}" '
                    f'font-size="{FONT_SIZE}px" '
                    f'text-anchor="middle" '
                    f'dominant-baseline="middle">'
                    f'{escape(value)}'
                    f'</text>'
                )

    svg.append("</svg>")

    Path(output_path).write_text(
        "\n".join(svg),
        encoding="utf-8"
    )


def main():
    folder_path = "../evaluation_results/raw_results"
    output_folder = "../evaluation_results/visualizations/"

    if not os.path.isdir(folder_path):
        raise SystemExit(f"Not a directory: {folder_path}")

    files = sorted([
        os.path.join(folder_path, f)
        for f in os.listdir(folder_path)
        if f.endswith("_result.csv")
    ])

    if not files:
        print(f"No *_result.csv files found in {folder_path}")
        return

    for path in files:
        print(output_folder + Path(path).stem + ".svg")
        generate_table(path, output_folder + Path(path).stem.replace("result", "sorted_alphabetical") + ".svg", True)
        generate_table(path, output_folder + Path(path).stem.replace("result", "sorted_failure") + ".svg", False)


if __name__ == "__main__":
    main()